"""
Test: partial-failure retry does not duplicate completed side effects.

A partial failure leaves the replay
lease unfinalized, and the retry used to re-run the WHOLE routing loop,
re-filing SARs (S3) and re-escalating (SQS) clusters that had already
succeeded. The executor now records per-cluster completion in the
completed_clusters string set on the compliance-decisions item (conditional
on still holding the lease), reads it right after the claim, and skips
recorded clusters. CIRCUIT_BREAKER is never skipped or recorded. A failed
completion write fails closed (no finalize).
"""
import os
import re
import sys

import pytest
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError

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

_KEYWORDS = {"SET", "REMOVE", "ADD", "AND", "OR", "NOT",
             "attribute_not_exists", "attribute_exists", "if_not_exists"}


def _ccf():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "lease lost"}},
        "UpdateItem",
    )


class StatefulTable:
    """In-memory compliance-decisions item that persists across handler()
    calls. update_item serializes values like the real resource API (so the
    {cluster_id} set must serialize as SS) and evaluates the three executor
    UpdateItem shapes (claim, completion ADD, finalize) against stored state."""

    def __init__(self, clusters, completed=None):
        self.item = {
            "compliance_id": "comp-1",
            "detection_id": "det-1",
            "clusters_assessed": [dict(c) for c in clusters],
            **_executor_fixtures.VERIFIED_FIELDS,
        }
        if completed is not None:
            self.item["completed_clusters"] = completed
        self.update_calls = []
        self.get_calls = []
        self.serializer = TypeSerializer()
        self.fail_record = None      # exception to raise on completion ADD
        self.fail_projection = None  # exception to raise on projected GetItem

    def get_item(self, **kwargs):
        self.get_calls.append(kwargs)
        if "ProjectionExpression" in kwargs:
            if self.fail_projection is not None:
                raise self.fail_projection
            names = [n.strip() for n in kwargs["ProjectionExpression"].split(",")]
            return {"Item": {n: self.item[n] for n in names if n in self.item}}
        return {"Item": dict(self.item)}

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)
        values = kwargs.get("ExpressionAttributeValues", {})
        for value in values.values():
            self.serializer.serialize(value)
        expr = kwargs["UpdateExpression"]
        item = self.item
        if expr.startswith("ADD completed_clusters"):
            if self.fail_record is not None:
                raise self.fail_record
            if not (item.get("executor_processed") == values[":in_progress"]
                    and item.get("lease_expires_at") == values[":lease"]):
                raise _ccf()
            item["completed_clusters"] = set(item.get("completed_clusters", set())) | values[":cid"]
        elif "executor_processed = :done" in expr:
            item["executor_processed"] = values[":done"]
            item.pop("lease_expires_at", None)
        else:  # claim
            state = item.get("executor_processed")
            ok = (
                "executor_processed" not in item
                or state is False
                or (state == "IN_PROGRESS" and item.get("lease_expires_at", 0) < values[":now"])
            )
            if not ok:
                raise _ccf()
            item["executor_processed"] = values[":in_progress"]
            item["lease_expires_at"] = values[":lease_expires_at"]
        return {}

    def expire_lease(self):
        self.item["lease_expires_at"] = 0

    def finalized(self):
        return self.item.get("executor_processed") is True


class _Resource:
    def __init__(self, table):
        self.table = table

    def Table(self, name):  # noqa: N802 — boto3 API shape
        return self.table


@pytest.fixture
def live(monkeypatch):
    """Patch the executor into live mode against a StatefulTable. Returns a
    factory: live(clusters, completed=None) -> (table, audits, calls, status)
    where `status` is a mutable dict controlling sar/escalate outcomes."""
    audits = []
    calls = {"sar": [], "escalate": [], "breaker": 0}
    status = {"sar": "filed", "escalate": "escalated"}
    holder = {}

    monkeypatch.setattr(executor_handler.boto3, "resource",
                        lambda *a, **k: _Resource(holder["table"]))
    monkeypatch.setattr(executor_handler, "write_audit_record", audits.append)
    monkeypatch.setattr(os.path, "isdir",
                        lambda p, _orig=os.path.isdir: False if p == "/var/task" else _orig(p))

    def fake_sar(cluster, mode):
        calls["sar"].append(cluster["cluster_id"])
        return {"status": status["sar"]}

    def fake_escalate(cluster, mode):
        calls["escalate"].append(cluster["cluster_id"])
        return {"status": status["escalate"]}

    def fake_breaker(mode):
        calls["breaker"] += 1
        return {"status": "GOVERNANCE_HOLD"}

    monkeypatch.setattr(executor_handler, "execute_file_sar", fake_sar)
    monkeypatch.setattr(executor_handler, "execute_escalate", fake_escalate)
    monkeypatch.setattr(executor_handler, "execute_circuit_breaker", fake_breaker)

    def factory(clusters, completed=None):
        holder["table"] = StatefulTable(clusters, completed)
        return holder["table"], audits, calls, status

    return factory


def _event(clusters):
    return _executor_fixtures.event(clusters)


def _assert_rejected_as_sox_cluster_id(result, table, calls, completed=None):
    """A request carrying a non-str / empty / over-long / off-charset
    cluster_id is a SOX value violation: rejected before
    provenance and routing, so no side effect, no lease claim, no
    completion record and no finalize."""
    assert result.get("error") == "SOX_VIOLATION"
    assert "cluster_id" in result["message"]
    assert calls["sar"] == [] and calls["escalate"] == [] and calls["breaker"] == 0
    assert table.update_calls == []
    assert table.item.get("completed_clusters") == completed
    assert not table.finalized()


def _by_cluster(result):
    return {a["cluster_id"]: a for a in result["actions"]}


def _record_calls(table):
    return [c for c in table.update_calls if c["UpdateExpression"].startswith("ADD")]


class TestPartialFailureRetry:
    def test_retry_does_not_refile_completed_sar_and_retries_failed_escalation(self, live):
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW]
        table, _, calls, status = live(clusters)
        status["escalate"] = "ESCALATION_FAILED"

        first = handler(_event(clusters))
        assert {k: v["action_taken"] for k, v in _by_cluster(first).items()} == {
            "cluster-a": "FILED", "cluster-r": "ESCALATION_FAILED",
        }
        assert not table.finalized()
        assert table.item["completed_clusters"] == {"cluster-a"}

        table.expire_lease()
        status["escalate"] = "escalated"
        second = handler(_event(clusters))

        taken = {k: v["action_taken"] for k, v in _by_cluster(second).items()}
        assert taken == {"cluster-a": "ALREADY_COMPLETED", "cluster-r": "ESCALATED"}
        assert calls["sar"] == ["cluster-a"]  # never re-filed
        assert calls["escalate"] == ["cluster-r", "cluster-r"]  # failed one retried
        assert second["total_already_completed"] == 1
        assert table.finalized()

    def test_retry_does_not_reescalate_completed_cluster_and_retries_failed_sar(self, live):
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW]
        table, _, calls, status = live(clusters)
        status["sar"] = "FILING_FAILED"

        handler(_event(clusters))
        assert not table.finalized()
        assert table.item["completed_clusters"] == {"cluster-r"}

        table.expire_lease()
        status["sar"] = "filed"
        second = handler(_event(clusters))

        taken = {k: v["action_taken"] for k, v in _by_cluster(second).items()}
        assert taken == {"cluster-a": "FILED", "cluster-r": "ALREADY_COMPLETED"}
        assert calls["escalate"] == ["cluster-r"]
        assert calls["sar"] == ["cluster-a", "cluster-a"]
        assert table.finalized()

    def test_unexpired_lease_still_rejects_retry(self, live):
        """The replay lease is not weakened: while the first attempt's lease
        is live, a second call is still rejected before routing."""
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW]
        table, _, calls, status = live(clusters)
        status["escalate"] = "ESCALATION_FAILED"
        handler(_event(clusters))
        second = handler(_event(clusters))
        assert second.get("error") == "PROVENANCE_CHECK_FAILED"
        assert calls["sar"] == ["cluster-a"]

    def test_completion_recorded_with_lease_token_condition(self, live):
        table, _, _, _ = live([CLUSTER_SAR])
        handler(_event([CLUSTER_SAR]))
        claim = table.update_calls[0]
        (record,) = _record_calls(table)
        assert "executor_processed" in record["ConditionExpression"]
        assert "lease_expires_at" in record["ConditionExpression"]
        assert record["ExpressionAttributeValues"][":lease"] == \
            claim["ExpressionAttributeValues"][":lease_expires_at"]
        assert record["ExpressionAttributeValues"][":cid"] == {"cluster-a"}

    def test_failed_action_is_not_recorded_completed(self, live):
        table, _, _, status = live([CLUSTER_SAR])
        status["sar"] = "FILING_FAILED"
        result = handler(_event([CLUSTER_SAR]))
        assert _record_calls(table) == []
        assert "completed_clusters" not in table.item
        assert "completion_recorded" not in result["actions"][0]


class TestCompletionWriteFailsClosed:
    def test_completion_write_failure_does_not_finalize(self, live):
        table, audits, _, _ = live([CLUSTER_SAR])
        table.fail_record = ClientError(
            {"Error": {"Code": "InternalServerError",
                       "Message": "arn:aws:dynamodb:us-east-1:123456789012:table/secret"}},
            "UpdateItem",
        )
        result = handler(_event([CLUSTER_SAR]))
        action = result["actions"][0]
        assert action["action_taken"] == "FILED"  # truthful
        assert action["completion_recorded"] is False
        assert any(a.get("cluster_id") == "cluster-a" and a.get("completion_recorded") is False
                   for a in audits)
        assert not any(":done" in c["UpdateExpression"] for c in table.update_calls)
        assert not table.finalized()
        assert "123456789012" not in str(result)

    def test_completion_write_lease_lost_does_not_finalize(self, live):
        table, _, _, _ = live([CLUSTER_SAR])
        table.fail_record = _ccf()
        result = handler(_event([CLUSTER_SAR]))
        assert result["actions"][0]["completion_recorded"] is False
        assert not table.finalized()

    def test_non_client_error_completion_write_does_not_finalize(self, live):
        table, _, _, _ = live([CLUSTER_SAR])
        table.fail_record = TypeError("boom")
        result = handler(_event([CLUSTER_SAR]))
        assert result["actions"][0]["completion_recorded"] is False
        assert not table.finalized()

    def test_successful_record_marks_completion_recorded_true(self, live):
        table, _, _, _ = live([CLUSTER_SAR])
        result = handler(_event([CLUSTER_SAR]))
        assert result["actions"][0]["completion_recorded"] is True
        assert table.finalized()


class TestCircuitBreakerNeverSkipped:
    def test_circuit_breaker_reexecuted_on_retry_even_if_marked_completed(self, live):
        table, _, calls, _ = live([CLUSTER_BREAKER], completed={"cluster-b"})
        result = handler(_event([CLUSTER_BREAKER]))
        assert calls["breaker"] == 1
        assert result["actions"][0]["action_taken"] == "CIRCUIT_BREAKER_INVOKED"
        assert table.finalized()

    def test_circuit_breaker_never_recorded_completed(self, live):
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW, CLUSTER_BREAKER]
        table, _, _, _ = live(clusters)
        result = handler(_event(clusters))
        for call in _record_calls(table):
            assert "cluster-b" not in call["ExpressionAttributeValues"][":cid"]
        assert "cluster-b" not in table.item["completed_clusters"]
        assert "completion_recorded" not in _by_cluster(result)["cluster-b"]


class TestCompletionStateRead:
    def test_completion_state_read_uses_consistent_projection(self, live):
        table, _, _, _ = live([CLUSTER_SAR])
        handler(_event([CLUSTER_SAR]))
        projected = [g for g in table.get_calls if "ProjectionExpression" in g]
        assert len(projected) == 1
        assert projected[0]["ConsistentRead"] is True
        assert projected[0]["ProjectionExpression"] == "completed_clusters"

    def test_all_completed_from_prior_attempt_finalizes_without_side_effects(self, live):
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW]
        table, _, calls, _ = live(clusters, completed={"cluster-a", "cluster-r"})
        result = handler(_event(clusters))
        assert calls["sar"] == [] and calls["escalate"] == []
        assert result["total_already_completed"] == 2
        assert table.finalized()

    def test_completion_state_read_failure_skips_nothing(self, live):
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW]
        table, audits, calls, _ = live(clusters, completed={"cluster-a"})
        table.fail_projection = RuntimeError("read failed")
        result = handler(_event(clusters))
        assert calls["sar"] == ["cluster-a"] and calls["escalate"] == ["cluster-r"]
        assert result["total_already_completed"] == 0
        assert any(a.get("action_taken") == "COMPLETION_STATE_UNAVAILABLE" for a in audits)

    def test_malformed_completion_state_skips_nothing(self, live):
        table, audits, calls, _ = live([CLUSTER_SAR], completed="cluster-a")
        handler(_event([CLUSTER_SAR]))
        assert calls["sar"] == ["cluster-a"]
        assert any(a.get("action_taken") == "COMPLETION_STATE_UNAVAILABLE" for a in audits)

    def test_empty_cluster_id_is_recorded_and_finalizes(self, live):
        """The canonical completion key replaced the earlier behavior (empty id
        never recorded, finalize blocked forever): the id now records under its
        hashed key. A REQUEST carrying an empty id is now a SOX value violation,
        so it never reaches a side effect at all; the hashed key
        for "" stays covered by TestCanonicalCompletionKey's unit tests."""
        odd = dict(CLUSTER_SAR, cluster_id="")
        table, _, calls, _ = live([odd], completed={"x"})
        result = handler(_event([odd]))
        _assert_rejected_as_sox_cluster_id(result, table, calls, completed={"x"})
        key = executor_handler._completion_key("")
        assert key.startswith("sha256:") and key != ""

    def test_already_completed_cluster_is_audited(self, live):
        table, audits, _, _ = live([CLUSTER_SAR], completed={"cluster-a"})
        handler(_event([CLUSTER_SAR]))
        skipped = [a for a in audits if a.get("action_taken") == "ALREADY_COMPLETED"]
        assert len(skipped) == 1
        assert skipped[0]["cluster_id"] == "cluster-a"
        assert skipped[0]["result"] == {"status": "skipped_already_completed"}


def _attribute_names(expr):
    names = set()
    for token in re.findall(r"[A-Za-z_:][A-Za-z0-9_]*", expr or ""):
        if token.startswith(":") or token in _KEYWORDS:
            continue
        names.add(token)
    return names


class TestUpdateItemAttributeScope:
    def test_every_update_item_touches_only_allowed_attributes(self, live):
        """Every executor UpdateItem stays within the IAM
        dynamodb:Attributes allowlist."""
        allowed = set(executor_handler.COMPLIANCE_TABLE_WRITE_ATTRIBUTES)
        clusters = [CLUSTER_SAR, CLUSTER_REVIEW, CLUSTER_BREAKER]
        all_calls = []

        table, _, _, status = live(clusters)
        status["escalate"] = "ESCALATION_FAILED"
        handler(_event(clusters))
        table.expire_lease()
        status["escalate"] = "escalated"
        handler(_event(clusters))
        all_calls.extend(table.update_calls)

        shapes = {c["UpdateExpression"].split()[0] for c in all_calls}
        assert shapes == {"SET", "ADD"}  # claim/finalize and completion
        for call in all_calls:
            used = (_attribute_names(call["UpdateExpression"])
                    | _attribute_names(call.get("ConditionExpression"))
                    | set(call["Key"]))
            assert used <= allowed, used - allowed
            assert "ExpressionAttributeNames" not in call
            assert "ReturnValues" not in call


class TestLocalModeUnchanged:
    def test_local_mode_has_no_completion_tracking(self, monkeypatch, tmp_path):
        monkeypatch.setattr(executor_handler, "LOCAL_OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(executor_handler, "LOCAL_AUDIT_FILE", str(tmp_path / "audit.jsonl"))

        def no_aws(*a, **k):
            raise AssertionError("local mode must not touch DynamoDB")

        monkeypatch.setattr(executor_handler.boto3, "resource", no_aws)
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-local",
                "detection_id": "det-local",
                "clusters_assessed": [{"cluster_id": "c1", "decision": "FILE_SAR",
                                       "sar_narrative": "test"}],
            },
        }
        result = handler(event)
        assert result["actions"][0]["action_taken"] == "FILED"
        assert "completion_recorded" not in result["actions"][0]
        assert result["total_already_completed"] == 0


# ── Canonical completion key ──────────────────────────────────────────────────
# A stored empty / non-string / over-long cluster_id used to have no
# completion key, so its SAR/escalation succeeded but the lease was never
# finalized and the same verified payload could be replayed every lease
# period, re-filing indefinitely. Every stored id now has a key.

_ODD_IDS = [
    pytest.param("", id="empty"),
    pytest.param(7, id="int"),
    pytest.param(None, id="none"),
    pytest.param({"nested": ["a", 1]}, id="dict"),
    pytest.param("x" * 5000, id="overlong"),
    pytest.param("has space/and:colon", id="odd-charset"),
]

_SIDE_EFFECT = {"FILE_SAR": "sar", "NEEDS_REVIEW": "escalate"}


def _odd_cluster(cluster_id, decision):
    base = CLUSTER_SAR if decision == "FILE_SAR" else CLUSTER_REVIEW
    return dict(base, cluster_id=cluster_id)


class TestCanonicalCompletionKey:
    @pytest.mark.parametrize("decision", ["FILE_SAR", "NEEDS_REVIEW"])
    @pytest.mark.parametrize("cluster_id", _ODD_IDS)
    def test_odd_id_records_completion_finalizes_and_replay_rejected(
        self, live, cluster_id, decision
    ):
        """An odd request id is now a SOX value violation, so
        it can never produce an un-finalizable, replayable side effect —
        it never reaches one. Replaying it is rejected the same way."""
        odd = _odd_cluster(cluster_id, decision)
        table, _, calls, _ = live([odd])

        first = handler(_event([odd]))
        _assert_rejected_as_sox_cluster_id(first, table, calls)

        second = handler(_event([odd]))
        _assert_rejected_as_sox_cluster_id(second, table, calls)
        assert calls[_SIDE_EFFECT[decision]] == []

    @pytest.mark.parametrize("cluster_id", _ODD_IDS)
    def test_odd_id_skipped_on_partial_failure_retry(self, live, cluster_id):
        """Even if the lease is reclaimed (finalize blocked by ANOTHER
        cluster's failure), the recorded odd-id SAR is not re-filed."""
        # The whole batch is a SOX value violation, so neither
        # the odd-id SAR nor its sibling escalation is ever executed, on
        # the first attempt or the retry.
        odd = _odd_cluster(cluster_id, "FILE_SAR")
        clusters = [odd, CLUSTER_REVIEW]
        table, _, calls, status = live(clusters)
        status["escalate"] = "ESCALATION_FAILED"
        _assert_rejected_as_sox_cluster_id(handler(_event(clusters)), table, calls)

        table.expire_lease()
        status["escalate"] = "escalated"
        second = handler(_event(clusters))
        _assert_rejected_as_sox_cluster_id(second, table, calls)

    @pytest.mark.parametrize("cluster_id", _ODD_IDS)
    def test_odd_id_completion_write_failure_does_not_finalize(self, live, cluster_id):
        # Rejected before any side effect, so there is no
        # completion write to fail and nothing is finalized.
        odd = _odd_cluster(cluster_id, "FILE_SAR")
        table, _, calls, _ = live([odd])
        table.fail_record = _ccf()
        result = handler(_event([odd]))
        _assert_rejected_as_sox_cluster_id(result, table, calls)

    @pytest.mark.parametrize("cluster_id", [c.values[0] for c in _ODD_IDS])
    def test_key_is_bounded_nonempty_string(self, cluster_id):
        key = executor_handler._completion_key(cluster_id)
        assert isinstance(key, str) and 0 < len(key) <= 128
        assert key.startswith("sha256:")

    def test_plain_ids_are_verbatim(self):
        for cid in ("cluster-a", "c1", "e2f3a4b5-6c7d-8e9f-0a1b-2c3d4e5f6a7b"):
            assert executor_handler._completion_key(cid) == cid

    def test_distinct_ids_never_collide(self):
        from decimal import Decimal
        ids = [1, "1", True, "True", None, "None", "", [], {}, [1], ["1"],
               {"a": 1}, {"a": "1"}, 1.5, "1.5", b"1",
               "sha256:" + "0" * 64, "x" * 129, "x" * 128]
        keys = [executor_handler._completion_key(v) for v in ids]
        assert len(set(keys)) == len(ids)
        # Hashed keys always contain ':'; verbatim keys never do.
        for v, k in zip(ids, keys):
            assert (":" in k) == (k != v)
        # Equal numbers agree across int (request JSON) / Decimal (DynamoDB).
        assert executor_handler._completion_key(1) == executor_handler._completion_key(Decimal("1"))
        assert executor_handler._completion_key(1.0) == executor_handler._completion_key(Decimal("1.00"))

    def test_int_and_str_ids_do_not_collide_in_handler(self, live):
        """An int request id is a SOX value violation, so an
        int id can never be filed under (or collide with) a str id's
        completion key; key distinctness itself stays pinned by
        test_distinct_ids_never_collide."""
        as_int = dict(CLUSTER_SAR, cluster_id=1)
        as_str = dict(CLUSTER_SAR, cluster_id="1")
        table, _, calls, _ = live([as_int, as_str])
        result = handler(_event([as_int, as_str]))
        _assert_rejected_as_sox_cluster_id(result, table, calls)
        assert executor_handler._completion_key(1) != executor_handler._completion_key("1")

    def test_completed_str_id_does_not_skip_int_id(self, live):
        """A completed str "1" never causes an int 1 to be skipped as
        ALREADY_COMPLETED; the int request is rejected outright instead."""
        as_int = dict(CLUSTER_SAR, cluster_id=1)
        table, _, calls, _ = live([as_int], completed={"1"})
        result = handler(_event([as_int]))
        _assert_rejected_as_sox_cluster_id(result, table, calls, completed={"1"})
        assert "actions" not in result

    def test_key_is_deterministic_across_processes(self):
        """Set / map ids must not depend on per-process hash order."""
        import subprocess
        code = (
            "import sys; sys.path.insert(0, %r); "
            "import lambdas.executor_agent.handler as h; "
            "print(h._completion_key({'k': frozenset({'a', 'b', 'c', 'd'}), 'z': 1, 'b': [2]}))"
            % PROJECT_ROOT
        )
        outputs = set()
        for seed in ("1", "2", "3"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            outputs.add(subprocess.run(
                [sys.executable, "-c", code], env=env, capture_output=True,
                text=True, check=True,
            ).stdout.strip())
        assert len(outputs) == 1

    def test_odd_id_update_items_stay_within_iam_attribute_allowlist(self, live):
        # An odd request id is rejected before any UpdateItem.
        odd = dict(CLUSTER_SAR, cluster_id={"nested": 1})
        table, _, calls, _ = live([odd])
        result = handler(_event([odd]))
        _assert_rejected_as_sox_cluster_id(result, table, calls)
        assert table.update_calls == []

    def test_plain_id_update_items_stay_within_iam_attribute_allowlist(self, live):
        """Sibling of the odd-id case: the original used <= allowed property
        over real claim / completion / finalize UpdateItems."""
        allowed = set(executor_handler.COMPLIANCE_TABLE_WRITE_ATTRIBUTES)
        plain = dict(CLUSTER_SAR, cluster_id="cluster-plain")
        table, _, _, _ = live([plain])
        handler(_event([plain]))
        assert table.finalized()
        assert len(table.update_calls) == 3  # claim, completion ADD, finalize
        for call in table.update_calls:
            used = (_attribute_names(call["UpdateExpression"])
                    | _attribute_names(call.get("ConditionExpression"))
                    | set(call["Key"]))
            assert used <= allowed, used - allowed


class TestProvenanceWithCanonicalIds:
    def test_duplicate_unhashable_ids_rejected_without_crash(self, live):
        a = dict(CLUSTER_SAR, cluster_id={"x": 1})
        b = dict(CLUSTER_REVIEW, cluster_id="cluster-r")
        table, _, calls, _ = live([a, b])
        result = handler(_event([a, a]))
        # The unhashable request id is a SOX value violation,
        # rejected without crashing and before provenance / routing.
        _assert_rejected_as_sox_cluster_id(result, table, calls)

    def test_duplicate_plain_ids_still_rejected(self, live):
        table, _, calls, _ = live([CLUSTER_SAR, CLUSTER_REVIEW])
        result = handler(_event([CLUSTER_SAR, CLUSTER_SAR]))
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "duplicate" in result["message"].lower()
        assert "at index(es) [0, 1]" in result["message"]
        assert "cluster-a" not in result["message"]
        assert calls["sar"] == []

    def test_bool_id_does_not_match_stored_int_id(self, live):
        """True == 1 in Python; canonical keys keep them distinct, so a
        caller cannot substitute one for the other."""
        stored = dict(CLUSTER_SAR, cluster_id=1)
        table, _, calls, _ = live([stored])
        result = handler(_event([dict(stored, cluster_id=True)]))
        # A bool request id is a SOX value violation, so it
        # can never be substituted for the stored int id.
        _assert_rejected_as_sox_cluster_id(result, table, calls)

    def test_mixed_type_missing_ids_reported_without_crash(self, live):
        table, _, calls, _ = live([dict(CLUSTER_SAR, cluster_id=1),
                                   dict(CLUSTER_REVIEW, cluster_id="r")])
        result = handler(_event([dict(CLUSTER_REVIEW, cluster_id="r")]))
        assert result.get("error") == "PROVENANCE_CHECK_FAILED"
        assert "omits" in result["message"]
        assert calls["escalate"] == []
