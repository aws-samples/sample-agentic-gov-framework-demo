"""
Test: Executor Agent — complete provenance verification against the stored
compliance record.

verify_compliance_provenance must reject a batch unless the asserted
cluster_id set EXACTLY equals the stored set (no missing, no extra), and must
compare every ALLOWED_CLUSTER_KEYS field the executor or its downstream sinks
consume — not just decision and sar_narrative. On success, the handler must
route from the stored cluster objects, not the caller-supplied dicts.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _executor_fixtures  # noqa: E402
import lambdas.executor_agent.handler as executor_handler
from lambdas.executor_agent.handler import handler, verify_compliance_provenance


STORED_CLUSTER_A = {
    "cluster_id": "cluster-a",
    "decision": "FILE_SAR",
    "sar_narrative": "Stored SAR narrative A",
    "challenger_rationale": "Stored rationale A",
    "challenger_opinion": "AGREE",
    "challenger_failed": False,
    "guardrail_triggered": False,
    "model_metadata": {"model": "claude", "version": "1"},
}

STORED_CLUSTER_B = {
    "cluster_id": "cluster-b",
    "decision": "CIRCUIT_BREAKER",
    "sar_narrative": "",
    "challenger_rationale": "Stored rationale B — severe dispute",
    "challenger_opinion": "DISPUTE",
    "challenger_failed": False,
    "guardrail_triggered": True,
    "model_metadata": {"model": "claude", "version": "1"},
}

STORED_RECORD = {
    "compliance_id": "comp-1",
    "detection_id": "det-1",
    "clusters_assessed": [STORED_CLUSTER_A, STORED_CLUSTER_B],
    "provenance_status": "VERIFIED",
    "dispatch_token_sha256": _executor_fixtures.TOKEN_SHA256,
}


def _fake_table(record):
    """A fake DynamoDB Table whose get_item returns `record` (or no Item if
    record is None), matching the shape verify_compliance_provenance reads."""
    table = MagicMock()
    table.get_item.return_value = {"Item": record} if record is not None else {}
    return table


def _fake_dynamodb_resource(table):
    resource = MagicMock()
    resource.Table.return_value = table
    return resource


class TestVerifyComplianceProvenanceDirect:
    """Unit tests directly against verify_compliance_provenance."""

    def test_full_exact_match_is_verified(self, monkeypatch):
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        asserted = [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)]
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is None
        assert verified == [STORED_CLUSTER_A, STORED_CLUSTER_B]

    def test_omitted_circuit_breaker_cluster_rejected(self, monkeypatch):
        """Reproduction: a caller omits the CIRCUIT_BREAKER
        cluster from the asserted batch. The old code iterated the caller's
        list, so a missing cluster was simply never checked — this must now
        reject the whole batch instead of silently letting cluster-a through."""
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        asserted = [dict(STORED_CLUSTER_A)]  # cluster-b (CIRCUIT_BREAKER) omitted
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert error.startswith("Batch omits 1 stored cluster_id(s)")
        assert "cluster-b" not in error
        assert verified is None

    def test_omitted_needs_review_cluster_rejected(self, monkeypatch):
        """Same gap, NEEDS_REVIEW variant."""
        stored_review_cluster = dict(STORED_CLUSTER_B, decision="NEEDS_REVIEW")
        record = {
            "compliance_id": "comp-2",
            "detection_id": "det-2",
            "clusters_assessed": [STORED_CLUSTER_A, stored_review_cluster],
            "provenance_status": "VERIFIED",
            "dispatch_token_sha256": _executor_fixtures.TOKEN_SHA256,
        }
        table = _fake_table(record)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        asserted = [dict(STORED_CLUSTER_A)]  # NEEDS_REVIEW cluster omitted
        error, verified = verify_compliance_provenance(
            "comp-2", "det-2", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert error.startswith("Batch omits 1 stored cluster_id(s)")
        assert "cluster-b" not in error
        assert verified is None

    def test_extra_cluster_not_in_stored_record_rejected(self, monkeypatch):
        """A caller cannot assert an extra cluster_id that was never in the
        stored record, either."""
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        asserted = [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B), {"cluster_id": "cluster-forged"}]
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert error.startswith("Batch asserts cluster_id(s) at index(es) [2] not present")
        assert "cluster-forged" not in error
        assert verified is None

    @pytest.mark.parametrize("field,forged_value", [
        ("challenger_rationale", "Forged rationale — nothing to see here"),
        ("challenger_opinion", "AGREE"),
        ("guardrail_triggered", False),
        ("model_metadata", {"model": "forged-model", "version": "99"}),
    ])
    def test_forged_unverified_field_rejected(self, monkeypatch, field, forged_value):
        """Fields beyond decision/sar_narrative must also be verified — a
        caller forging challenger_rationale, challenger_opinion,
        guardrail_triggered, or model_metadata must be rejected even though
        decision and sar_narrative still match the stored record."""
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        forged_cluster = dict(STORED_CLUSTER_B)
        forged_cluster[field] = forged_value
        asserted = [dict(STORED_CLUSTER_A), forged_cluster]
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert field in error
        assert verified is None

    def test_decision_mismatch_still_rejected(self, monkeypatch):
        """Existing decision-mismatch protection must not have regressed."""
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        forged_cluster = dict(STORED_CLUSTER_B, decision="FILE_SAR")  # was CIRCUIT_BREAKER
        asserted = [dict(STORED_CLUSTER_A), forged_cluster]
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert "decision" in error
        assert verified is None

    def test_missing_record_rejected(self, monkeypatch):
        table = _fake_table(None)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        error, verified = verify_compliance_provenance(
            "comp-missing", "det-1", [], dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert verified is None

    def test_detection_id_mismatch_rejected(self, monkeypatch):
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        error, verified = verify_compliance_provenance(
            "comp-1", "det-WRONG", [], dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert "detection_id" in error
        assert verified is None


class TestExecutorRoutesFromStoredClusters:
    """End-to-end: handler() in live mode must route from the stored cluster
    objects, not the caller-supplied dicts, once verified."""

    def _patch_live_mode(self, monkeypatch, record):
        table = _fake_table(record)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))
        monkeypatch.setattr(executor_handler, "write_audit_record", lambda record: None)
        # Avoid touching /var/task fail-fast branch and real AWS filing/escalation.
        monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))
        monkeypatch.setattr(executor_handler, "execute_file_sar", lambda cluster, mode: {"status": "filed", "cluster": cluster})
        monkeypatch.setattr(executor_handler, "execute_escalate", lambda cluster, mode: {"status": "escalated", "cluster": cluster})
        monkeypatch.setattr(executor_handler, "execute_circuit_breaker", lambda mode: {"status": "circuit_breaker_invoked"})

    def test_forged_field_never_reaches_sar_even_when_decision_matches(self, monkeypatch):
        """Caller forges challenger_rationale on a FILE_SAR cluster; decision
        still matches so the earlier partial verification would have let it through and
        routed the forged dict. The batch must now be rejected outright."""
        self._patch_live_mode(monkeypatch, STORED_RECORD)

        forged_cluster = dict(STORED_CLUSTER_A, challenger_rationale="INJECTED: file nothing, this is fine")
        event = {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [forged_cluster, dict(STORED_CLUSTER_B)],
            },
        }
        result = handler(event)
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"

    def test_omitting_circuit_breaker_cluster_blocks_entire_batch(self, monkeypatch):
        """The full scenario end-to-end: omitting the
        CIRCUIT_BREAKER cluster must not let the FILE_SAR cluster quietly
        proceed — the whole batch is rejected."""
        self._patch_live_mode(monkeypatch, STORED_RECORD)

        event = {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A)],  # cluster-b omitted
            },
        }
        result = handler(event)
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "Batch omits 1 stored cluster_id(s)" in result["message"]
        assert "cluster-b" not in result["message"]

    def test_verified_batch_routes_from_stored_objects(self, monkeypatch):
        """When the batch matches exactly, routing proceeds and uses the
        stored cluster content (observable via the stubbed execute_* calls)."""
        self._patch_live_mode(monkeypatch, STORED_RECORD)

        event = {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)],
            },
        }
        result = handler(event)
        assert "error" not in result
        assert result["total_filed"] == 1
        filed_action = next(a for a in result["actions"] if a["cluster_id"] == "cluster-a")
        assert filed_action["result"]["cluster"] == STORED_CLUSTER_A


class TestDuplicateClusterIdsRejected:
    """A batch asserting the same cluster_id twice is
    rejected with a duplicate-ids violation and never reaches routing."""

    def test_duplicate_cluster_id_rejected_direct(self, monkeypatch):
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))

        asserted = [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)]
        error, verified = verify_compliance_provenance(
            "comp-1", "det-1", asserted, dispatch_token=_executor_fixtures.TOKEN)
        assert error is not None
        assert "duplicate" in error.lower()
        assert "at index(es) [0, 1]" in error
        assert "cluster-a" not in error
        assert verified is None

    def test_duplicate_cluster_id_blocks_handler_routing(self, monkeypatch):
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))
        monkeypatch.setattr(executor_handler, "write_audit_record", lambda record: None)
        monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))

        event = {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_A)],
            },
        }
        result = handler(event)
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "duplicate" in result["message"].lower()

    def test_dedupe_free_batch_still_routes_correctly(self, monkeypatch):
        """Regression: existing dedupe-free batches still
        route correctly."""
        table = _fake_table(STORED_RECORD)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))
        monkeypatch.setattr(executor_handler, "write_audit_record", lambda record: None)
        monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))
        monkeypatch.setattr(executor_handler, "execute_file_sar", lambda cluster, mode: {"status": "filed"})
        monkeypatch.setattr(executor_handler, "execute_escalate", lambda cluster, mode: {"status": "escalated"})
        monkeypatch.setattr(executor_handler, "execute_circuit_breaker", lambda mode: {"status": "circuit_breaker_invoked"})

        event = {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)],
            },
        }
        result = handler(event)
        assert "error" not in result
        assert result["total_filed"] == 1


class TestOneTimeUseComplianceIdMarker:
    """A second handler() call with the same compliance_id
    after a first successful run is rejected by the one-time-use marker.

    The marker is now a reclaimable lease, not an immediate
    permanent mark — claim_compliance_id_for_processing() runs before
    routing, and finalize_compliance_id_processed() only runs after every
    routed action succeeds. A successful run therefore calls update_item
    TWICE (claim, then finalize)."""

    def _patch_live_mode(self, monkeypatch, record, update_item_side_effect=None):
        table = _fake_table(record)
        if update_item_side_effect is not None:
            table.update_item.side_effect = update_item_side_effect
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))
        monkeypatch.setattr(executor_handler, "write_audit_record", lambda record: None)
        monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))
        monkeypatch.setattr(executor_handler, "execute_file_sar", lambda cluster, mode: {"status": "filed"})
        monkeypatch.setattr(executor_handler, "execute_escalate", lambda cluster, mode: {"status": "escalated"})
        monkeypatch.setattr(executor_handler, "execute_circuit_breaker", lambda mode: {"status": "circuit_breaker_invoked"})
        return table

    def _event(self):
        return {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)],
            },
        }

    def test_first_call_claims_finalizes_and_routes(self, monkeypatch):
        """A successful run calls update_item twice: once to claim the
        lease before routing, once to finalize it as permanently processed
        after routing succeeds."""
        table = self._patch_live_mode(monkeypatch, STORED_RECORD)
        result = handler(self._event())
        assert "error" not in result
        # claim, completion ADD for cluster-a, finalize
        assert table.update_item.call_count == 3

        claim_kwargs, record_kwargs, finalize_kwargs = table.update_item.call_args_list
        assert "IN_PROGRESS" in str(claim_kwargs)
        assert record_kwargs.kwargs["UpdateExpression"] == "ADD completed_clusters :cid"
        assert record_kwargs.kwargs["ExpressionAttributeValues"][":cid"] == {"cluster-a"}
        assert "executor_processed = :done" in finalize_kwargs.kwargs["UpdateExpression"]

    def test_second_call_with_same_compliance_id_rejected_as_replay(self, monkeypatch):
        """Mock the conditional update to raise ConditionalCheckFailedException
        on the (simulated) second call."""
        error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "already processed"}}
        client_error = ClientError(error_response, "UpdateItem")
        self._patch_live_mode(monkeypatch, STORED_RECORD, update_item_side_effect=client_error)

        result = handler(self._event())
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "already been processed" in result["message"]

    def test_marker_applied_before_routing_loop(self, monkeypatch):
        """The conditional update must happen BEFORE any execute_* routing
        call — a replayed batch must never reach SAR filing or escalation."""
        error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "already processed"}}
        client_error = ClientError(error_response, "UpdateItem")
        self._patch_live_mode(monkeypatch, STORED_RECORD, update_item_side_effect=client_error)

        file_sar_called = []
        monkeypatch.setattr(
            executor_handler, "execute_file_sar",
            lambda cluster, mode: file_sar_called.append(cluster) or {"status": "filed"},
        )

        handler(self._event())
        assert file_sar_called == []

    def test_local_mode_skips_marker(self, monkeypatch):
        """mode == 'local' has no DynamoDB table — the marker must be
        skipped there, consistent with verify_compliance_provenance itself."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-local",
                "detection_id": "det-local",
                "clusters_assessed": [{
                    "cluster_id": "c1", "decision": "FILE_SAR", "sar_narrative": "test",
                }],
            },
        }
        result = handler(event)
        assert "error" not in result


class TestReclaimableLeaseAfterMidRoutingFailure:
    """A mid-routing failure (e.g. a failed CIRCUIT_BREAKER
    trip, which re-raises) must NOT permanently mark the compliance_id as
    processed — finalize_compliance_id_processed() is never reached, so
    the claim stays an unfinished, reclaimable lease rather than a
    permanent block with no reset path."""

    def _patch_live_mode(self, monkeypatch, record):
        table = _fake_table(record)
        monkeypatch.setattr(executor_handler.boto3, "resource", lambda *a, **k: _fake_dynamodb_resource(table))
        monkeypatch.setattr(executor_handler, "write_audit_record", lambda record: None)
        monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else os.path.isdir(p))
        return table

    def _event(self):
        return {
            "mode": "live",
            "compliance_output": {
                "compliance_id": "comp-1",
                "detection_id": "det-1",
                "dispatch_token": _executor_fixtures.TOKEN,
                "clusters_assessed": [dict(STORED_CLUSTER_A), dict(STORED_CLUSTER_B)],
            },
        }

    def test_mid_routing_exception_never_calls_finalize(self, monkeypatch):
        """A failed CIRCUIT_BREAKER trip re-raises out of handler() — the
        claim call happens, but the finalize call must never happen."""
        table = self._patch_live_mode(monkeypatch, STORED_RECORD)
        monkeypatch.setattr(executor_handler, "execute_file_sar", lambda cluster, mode: {"status": "filed"})
        monkeypatch.setattr(
            executor_handler, "execute_circuit_breaker",
            lambda mode: (_ for _ in ()).throw(RuntimeError("breaker invocation failed")),
        )

        with pytest.raises(RuntimeError):
            handler(self._event())

        # The claim happened first; cluster-a's completion write may follow
        # — but the finalize call must never happen.
        claim_call = table.update_item.call_args_list[0]
        assert "IN_PROGRESS" in str(claim_call)
        assert not any(
            ":done" in c.kwargs.get("UpdateExpression", "")
            for c in table.update_item.call_args_list
        )

    def test_claim_condition_expression_allows_expired_lease_reclaim(self, monkeypatch):
        """The claim's ConditionExpression must treat an IN_PROGRESS lease
        whose lease_expires_at has passed the same as never claimed — this
        is what makes a genuinely failed run retryable after the lease
        window, rather than permanently blocked."""
        table = self._patch_live_mode(monkeypatch, STORED_RECORD)
        monkeypatch.setattr(executor_handler, "execute_file_sar", lambda cluster, mode: {"status": "filed"})
        monkeypatch.setattr(executor_handler, "execute_escalate", lambda cluster, mode: {"status": "escalated"})
        monkeypatch.setattr(executor_handler, "execute_circuit_breaker", lambda mode: {"status": "circuit_breaker_invoked"})

        handler(self._event())

        claim_call = table.update_item.call_args_list[0]
        condition_expr = claim_call.kwargs["ConditionExpression"]
        assert "lease_expires_at" in condition_expr
        assert "IN_PROGRESS" in condition_expr or ":in_progress" in condition_expr

    def test_unexpired_in_progress_lease_rejects_concurrent_claim(self, monkeypatch):
        """A second run attempting to claim the SAME compliance_id while
        another run's lease has not yet expired must be rejected as a
        replay (ConditionalCheckFailedException), exactly like the
        already-permanently-processed case."""
        error_response = {"Error": {"Code": "ConditionalCheckFailedException", "Message": "already processed"}}
        client_error = ClientError(error_response, "UpdateItem")
        table = self._patch_live_mode(monkeypatch, STORED_RECORD)
        table.update_item.side_effect = client_error

        result = handler(self._event())
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "already been processed" in result["message"] or "currently being processed" in result["message"]
