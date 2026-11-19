"""
Test: Executor replay lease — DynamoDB-serializable values and finalize
gating.

Serialization: the lease claim passed Python floats
into ExpressionAttributeValues on the boto3 DynamoDB RESOURCE API, which
raises TypeError("Float types are not supported...") — not a ClientError —
so every live invocation crashed before routing, including CIRCUIT_BREAKER
containment. The claim must use int epoch seconds, and any non-ClientError
must become an audited PROVENANCE_CHECK_FAILED that still never routes.

Finalize gating: finalize_compliance_id_processed ran
even when a SAR filing / escalation returned FILING_FAILED /
ESCALATION_FAILED, permanently blocking retry of an unfiled report. Finalize
must only run when every action record is a true success.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest
from boto3.dynamodb.types import TypeSerializer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _executor_fixtures  # noqa: E402
import lambdas.executor_agent.handler as executor_handler
from lambdas.executor_agent.handler import handler


CLUSTER_SAR = {
    "cluster_id": "cluster-a",
    "decision": "FILE_SAR",
    "sar_narrative": "Stored SAR narrative A",
    "challenger_rationale": "Stored rationale A",
    "challenger_opinion": "AGREE",
    "challenger_failed": False,
    "guardrail_triggered": False,
    "model_metadata": {"model": "claude", "version": "1"},
}
CLUSTER_REVIEW = dict(CLUSTER_SAR, cluster_id="cluster-r", decision="NEEDS_REVIEW",
                      challenger_opinion="DISPUTE")
CLUSTER_BREAKER = dict(CLUSTER_SAR, cluster_id="cluster-b", decision="CIRCUIT_BREAKER",
                       sar_narrative="", challenger_opinion="DISPUTE")


def _serializing_table(record):
    """Fake Table whose update_item serializes ExpressionAttributeValues the
    same way the real boto3 resource API does — so a float raises the exact
    TypeError seen in a live deployment."""
    table = MagicMock()
    table.get_item.return_value = {"Item": record}
    serializer = TypeSerializer()

    def update_item(**kwargs):
        for value in kwargs.get("ExpressionAttributeValues", {}).values():
            serializer.serialize(value)
        return {}

    table.update_item.side_effect = update_item
    return table


def _patch_live(monkeypatch, table, file_status="filed", escalate_status="escalated"):
    resource = MagicMock()
    resource.Table.return_value = table
    monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: resource)
    audits = []
    monkeypatch.setattr(executor_handler, "write_audit_record", audits.append)
    monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))
    calls = {"sar": 0, "escalate": 0, "breaker": 0}

    def fake_sar(cluster, mode):
        calls["sar"] += 1
        return {"status": file_status}

    def fake_escalate(cluster, mode):
        calls["escalate"] += 1
        return {"status": escalate_status}

    def fake_breaker(mode):
        calls["breaker"] += 1
        return {"status": "circuit_breaker_invoked"}

    monkeypatch.setattr(executor_handler, "execute_file_sar", fake_sar)
    monkeypatch.setattr(executor_handler, "execute_escalate", fake_escalate)
    monkeypatch.setattr(executor_handler, "execute_circuit_breaker", fake_breaker)
    return audits, calls


def _event(clusters):
    return _executor_fixtures.event(clusters)


def _record(clusters):
    return _executor_fixtures.stored_record(clusters)


class TestLeaseValuesAreDynamoSerializable:
    def test_claim_values_contain_no_floats(self, monkeypatch):
        table = _serializing_table(_record([CLUSTER_SAR]))
        _patch_live(monkeypatch, table)
        assert executor_handler.claim_compliance_id_for_processing("comp-1") is None
        values = table.update_item.call_args_list[0].kwargs["ExpressionAttributeValues"]
        for key in (":now", ":lease_expires_at"):
            assert isinstance(values[key], int) and not isinstance(values[key], bool)
        assert values[":lease_expires_at"] - values[":now"] == executor_handler.EXECUTOR_LEASE_SECONDS

    def test_circuit_breaker_routing_reaches_breaker_with_real_serializer(self, monkeypatch):
        """The float-serialization reproduction: with resource-API serialization in
        place, CIRCUIT_BREAKER containment routing must actually execute."""
        table = _serializing_table(_record([CLUSTER_BREAKER]))
        _, calls = _patch_live(monkeypatch, table)
        result = handler(_event([CLUSTER_BREAKER]))
        assert "error" not in result
        assert calls["breaker"] == 1
        assert result["total_circuit_breaker"] == 1


class TestNonClientErrorFailsClosedAndAudited:
    def test_type_error_in_claim_is_audited_and_routes_nothing(self, monkeypatch):
        table = _serializing_table(_record([CLUSTER_SAR, CLUSTER_BREAKER]))
        table.update_item.side_effect = TypeError(
            "Float types are not supported. Use Decimal types instead."
        )
        audits, calls = _patch_live(monkeypatch, table)

        result = handler(_event([CLUSTER_SAR, CLUSTER_BREAKER]))

        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert calls == {"sar": 0, "escalate": 0, "breaker": 0}
        assert any(
            a.get("action_taken") == "PROVENANCE_CHECK_FAILED"
            and a.get("violation_type") == "REPLAY_REJECTED"
            for a in audits
        )
        # Raw exception text must not leak into the caller response.
        assert "Float types" not in result["message"]

    def test_direct_claim_returns_error_string_on_non_client_error(self, monkeypatch):
        table = _serializing_table(_record([CLUSTER_SAR]))
        table.update_item.side_effect = ValueError("boom")
        _patch_live(monkeypatch, table)
        error = executor_handler.claim_compliance_id_for_processing("comp-1")
        assert error is not None
        assert "lookup error" in error


class TestFinalizeOnlyOnTrueSuccess:
    def _update_expressions(self, table):
        return [c.kwargs.get("UpdateExpression", "") for c in table.update_item.call_args_list]

    def test_filing_failed_skips_finalize(self, monkeypatch):
        table = _serializing_table(_record([CLUSTER_SAR]))
        _patch_live(monkeypatch, table, file_status="FILING_FAILED")
        result = handler(_event([CLUSTER_SAR]))
        assert result["actions"][0]["action_taken"] == "FILING_FAILED"
        exprs = self._update_expressions(table)
        assert len(exprs) == 1  # claim only
        assert not any(":done" in e for e in exprs)

    def test_escalation_failed_skips_finalize(self, monkeypatch):
        table = _serializing_table(_record([CLUSTER_SAR, CLUSTER_REVIEW]))
        _patch_live(monkeypatch, table, escalate_status="ESCALATION_FAILED")
        result = handler(_event([CLUSTER_SAR, CLUSTER_REVIEW]))
        taken = {a["cluster_id"]: a["action_taken"] for a in result["actions"]}
        assert taken == {"cluster-a": "FILED", "cluster-r": "ESCALATION_FAILED"}
        assert not any(":done" in e for e in self._update_expressions(table))

    def test_unknown_decision_skips_finalize(self, monkeypatch):
        """An unknown decision is a SOX value violation: no
        side effect, no lease claim, and never finalized."""
        odd = dict(CLUSTER_SAR, cluster_id="cluster-x", decision="SOMETHING_ELSE")
        table = _serializing_table(_record([odd]))
        _, calls = _patch_live(monkeypatch, table)
        result = handler(_event([odd]))
        assert result["error"] == "SOX_VIOLATION"
        assert "decision" in result["message"]
        assert calls == {"sar": 0, "escalate": 0, "breaker": 0}
        assert table.update_item.call_args_list == []  # no lease claim
        assert not any(":done" in e for e in self._update_expressions(table))

    @pytest.mark.parametrize("clusters", [
        [CLUSTER_SAR],
        [CLUSTER_SAR, CLUSTER_REVIEW, CLUSTER_BREAKER],
    ])
    def test_all_success_finalizes(self, monkeypatch, clusters):
        table = _serializing_table(_record(clusters))
        _patch_live(monkeypatch, table)
        handler(_event(clusters))
        exprs = self._update_expressions(table)
        # claim, one completion ADD per non-CB cluster, finalize
        non_cb = [c for c in clusters if c["decision"] != "CIRCUIT_BREAKER"]
        assert len(exprs) == 2 + len(non_cb)
        assert "IN_PROGRESS" in str(table.update_item.call_args_list[0])
        assert exprs[1:-1] == ["ADD completed_clusters :cid"] * len(non_cb)
        assert "executor_processed = :done" in exprs[-1]
