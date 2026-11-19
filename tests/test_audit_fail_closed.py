"""
Audit evidence fails closed — detection part:
no rejection cap in durable storage. Refs beyond the inline 500 go to chunk
items written BEFORE the main item; a chunk write failure raises with no
main-item write. Compliance / executor / breaker parts follow below.
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from _detection_fixtures import P, capture_audit  # noqa: E402


def _pan_batch(n):
    return [{"txn_id": f"p{i}", "card": P} for i in range(n)]


def test_1200_rejections_chunked_before_main_item(monkeypatch):
    items = capture_audit(monkeypatch, h)
    out = h.handler({"mode": "cpu", "transactions_inline": _pan_batch(1200)})
    did = out["detection_id"]
    assert [i["detection_id"] for i in items] == [f"{did}#rejections#0001", f"{did}#rejections#0002", did]
    chunk1, chunk2, main = items
    assert len(main["pan_rejection_refs"]) == 500
    assert main["pan_rejection_ref_chunks"] == 2
    for chunk in (chunk1, chunk2):
        assert chunk["record_type"] == "PAN_REJECTION_REFS"
        assert chunk["parent_detection_id"] == did
        assert "record_day" not in chunk
    assert [len(chunk1["refs"]), len(chunk2["refs"])] == [500, 200]
    union = main["pan_rejection_refs"] + chunk1["refs"] + chunk2["refs"]
    assert sorted(r["index"] for r in union) == list(range(1200))
    assert all({"index", "txn_ref", "rule"} == set(r) for r in union)
    # The invoker sees indices only, capped.
    assert len(out["pan_rejected_indices"]) == 500 and out["pan_rejected_indices_truncated"] is True


def test_under_cap_writes_no_chunks(monkeypatch):
    items = capture_audit(monkeypatch, h)
    out = h.handler({"mode": "cpu", "transactions_inline": _pan_batch(3)})
    assert [i["detection_id"] for i in items] == [out["detection_id"]]
    assert items[0]["pan_rejection_ref_chunks"] == 0
    assert items[0]["schema_rejection_ref_chunks"] == 0


def test_chunk_write_failure_raises_without_main_item(monkeypatch):
    items = capture_audit(monkeypatch, h, fail_when=lambda item: item["detection_id"].endswith("#0002"))
    with pytest.raises(RuntimeError, match="ddb down"):
        h.handler({"mode": "cpu", "transactions_inline": _pan_batch(1200)})
    assert len(items) == 1
    assert items[0]["detection_id"].endswith("#rejections#0001")


def test_schema_rejection_refs_chunked(monkeypatch):
    items = capture_audit(monkeypatch, h)
    bad = [{"txn_id": f"s{i}", "sender_id": "a", "receiver_id": "a", "amount": 1.0,
            "timestamp": "2026-01-01T00:00:00"} for i in range(600)]
    out = h.handler({"mode": "cpu", "transactions_inline": bad})
    did = out["detection_id"]
    assert out["error"] == "All transactions rejected by schema validation"
    assert [i["detection_id"] for i in items] == [f"{did}#schema-rejections#0001", did]
    assert items[0]["record_type"] == "SCHEMA_REJECTION_REFS"
    assert len(items[0]["refs"]) == 100
    assert len(items[1]["schema_rejection_refs"]) == 500
    assert items[1]["schema_rejection_ref_chunks"] == 1
    assert {r["reason_code"] for r in items[1]["schema_rejection_refs"]} == {"SELF_LOOP"}


# ─── Compliance part: the durable decision write fails closed ─────

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import FakeAws, detection_output, load_compliance_shim, post  # noqa: E402


def _verified(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch)
    aws.det = detection_output()
    aws.store_detection(aws.det)
    return aws


def test_compliance_write_failure_raises(monkeypatch):
    aws = _verified(monkeypatch)
    aws.write_error = RuntimeError("ddb down")
    with pytest.raises(ch.ComplianceAuditWriteError):
        ch.handler({"mode": "live", "detection_output": aws.det})
    assert aws.metrics == []


def test_compliance_unverified_write_failure_raises(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    aws = FakeAws().install(monkeypatch, ch)
    aws.write_error = RuntimeError("ddb down")
    with pytest.raises(ch.ComplianceAuditWriteError):
        ch.handler({"mode": "live", "detection_output": detection_output()})


def test_compliance_shim_returns_500_without_decisions(monkeypatch):
    aws = _verified(monkeypatch)
    aws.write_error = RuntimeError("ddb down for arn:aws:iam::123456789012:role/x")
    shim = load_compliance_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    status, body = post(shim, {"detection_output": aws.det})
    assert status == 500
    assert body["error"] == "AGENT_ERROR"
    assert "clusters_assessed" not in body and "dispatch_token" not in body
    assert "123456789012" not in json.dumps(body)


def test_compliance_write_to_dynamodb_keeps_its_name():
    assert callable(ch.write_to_dynamodb)


def test_no_non_fatal_audit_handling_in_compliance_handler():
    path = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py")
    with open(path, encoding="utf-8") as f:
        assert "non-fatal" not in f.read().lower()


# ─── Executor: write-ahead intent + outcome records ─
import _executor_fixtures as fx  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402


def _executor(monkeypatch, clusters):
    return fx.FakeExecutorAws(fx.stored_record(clusters)).install(monkeypatch, ex)


def _fail_on(action_taken):
    return lambda item: item.get("action_taken") == action_taken


def test_no_non_fatal_audit_handling_in_executor_handler():
    path = os.path.join(PROJECT_ROOT, "lambdas", "executor_agent", "handler.py")
    with open(path, encoding="utf-8") as f:
        assert "non-fatal" not in f.read().lower()


@pytest.mark.parametrize("cluster, effect", [(fx.CLUSTER_SAR, "sar"),
                                             (fx.CLUSTER_REVIEW, "escalate"),
                                             (fx.CLUSTER_BREAKER, "breaker")])
def test_intent_record_precedes_each_side_effect(monkeypatch, cluster, effect):
    aws = _executor(monkeypatch, [cluster])
    out = ex.handler(fx.event([cluster]))
    kinds = aws.kinds()
    assert kinds.index("audit") < kinds.index(effect)
    (intent,) = aws.audits("ACTION_INTENT")
    action = out["actions"][0]
    assert intent["action_id"] == f"intent-{action['action_id']}"
    assert intent["intended_action"] == cluster["decision"]
    assert intent["cluster_id"] == cluster["cluster_id"]
    assert intent["compliance_id"] == "comp-1" and intent["detection_id"] == "det-1"
    assert intent["record_day"] == intent["timestamp"][:10]
    assert "intent_recorded" not in action and "audit_incomplete" not in out
    assert aws.finalized()


def test_intent_write_failure_blocks_file_sar(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.audit_fail = _fail_on("ACTION_INTENT")
    out = ex.handler(fx.event([fx.CLUSTER_SAR]))
    (action,) = out["actions"]
    assert action["action_taken"] == "AUDIT_UNAVAILABLE"
    assert action["intent_recorded"] is False
    assert aws.side_effects() == []
    assert not aws.finalized()
    assert "AuditWriteFailure" in aws.metrics
    assert out["total_filed"] == 0
    assert aws.audits("AUDIT_UNAVAILABLE")  # the outcome itself is recorded


def test_intent_write_failure_blocks_escalation(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_REVIEW])
    aws.audit_fail = _fail_on("ACTION_INTENT")
    out = ex.handler(fx.event([fx.CLUSTER_REVIEW]))
    assert out["actions"][0]["action_taken"] == "AUDIT_UNAVAILABLE"
    assert aws.side_effects() == [] and not aws.finalized()


def test_intent_write_failure_still_trips_circuit_breaker(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_BREAKER])
    aws.audit_fail = _fail_on("ACTION_INTENT")
    out = ex.handler(fx.event([fx.CLUSTER_BREAKER]))
    (action,) = out["actions"]
    assert aws.side_effects() == [("breaker", None)]
    assert action["action_taken"] == "CIRCUIT_BREAKER_INVOKED"
    assert action["intent_recorded"] is False
    (outcome,) = aws.audits("CIRCUIT_BREAKER_INVOKED")
    assert outcome["intent_recorded"] is False
    assert "AuditWriteFailure" in aws.metrics


def test_outcome_write_failure_after_s3_put_is_not_finalized(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.audit_fail = _fail_on("FILED")
    out = ex.handler(fx.event([fx.CLUSTER_SAR]))
    (action,) = out["actions"]
    assert aws.side_effects() == [("sar", "cluster-a")]
    assert action["action_taken"] == "FILED"
    assert action["outcome_recorded"] is False
    assert action["completion_recorded"] is True  # recorded before the outcome write
    assert out["audit_incomplete"] is True
    assert "AuditWriteFailure" in aws.metrics
    assert not aws.finalized()


def test_outcome_failure_retry_converges_via_already_completed(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.audit_fail = _fail_on("FILED")
    ex.handler(fx.event([fx.CLUSTER_SAR]))
    # Lease expires; the completion set already holds the cluster.
    aws.state = None
    aws.record["completed_clusters"] = {"cluster-a"}
    aws.audit_fail = None
    out = ex.handler(fx.event([fx.CLUSTER_SAR]))
    assert out["actions"][0]["action_taken"] == "ALREADY_COMPLETED"
    assert aws.side_effects() == [("sar", "cluster-a")]  # never re-filed
    assert aws.audits("ALREADY_COMPLETED") and aws.finalized()
    assert "audit_incomplete" not in out


def test_already_completed_record_failure_blocks_finalize(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.record["completed_clusters"] = {"cluster-a"}
    aws.audit_fail = _fail_on("ALREADY_COMPLETED")
    out = ex.handler(fx.event([fx.CLUSTER_SAR]))
    assert out["actions"][0]["outcome_recorded"] is False
    assert out["audit_incomplete"] is True and not aws.finalized()


def test_breaker_failure_record_write_failure_still_raises(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_BREAKER])
    monkeypatch.setattr(ex, "execute_circuit_breaker",
                        lambda mode: (_ for _ in ()).throw(RuntimeError("trip failed")))
    aws.audit_fail = _fail_on("CIRCUIT_BREAKER_INVOCATION_FAILED")
    with pytest.raises(RuntimeError, match="trip failed"):
        ex.handler(fx.event([fx.CLUSTER_BREAKER]))
    assert not aws.finalized() and "AuditWriteFailure" in aws.metrics


def test_sox_rejection_with_audit_failure_is_still_rejected(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.audit_fail = lambda item: True
    out = ex.handler(fx.event([fx.CLUSTER_SAR], override=True))
    assert out["error"] == "SOX_VIOLATION"
    assert out["audit_recorded"] is False
    assert "AuditWriteFailure" in aws.metrics
    assert aws.side_effects() == [] and not aws.claimed()


def test_envelope_sox_rejection_with_audit_failure(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    aws.audit_fail = lambda item: True
    event = dict(fx.event([fx.CLUSTER_SAR]), force_approve=True)
    out = ex.handler(event)
    assert out["error"] == "SOX_VIOLATION" and out["audit_recorded"] is False


@pytest.mark.parametrize("prepare", ["provenance", "replay"])
def test_provenance_and_replay_rejection_with_audit_failure(monkeypatch, prepare):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    if prepare == "provenance":
        aws.record["provenance_status"] = "UNVERIFIED"
    else:
        aws.state = True  # already finalized
    aws.audit_fail = lambda item: True
    out = ex.handler(fx.event([fx.CLUSTER_SAR]))
    assert out["error"] == "PROVENANCE_CHECK_FAILED"
    assert out["audit_recorded"] is False
    assert aws.side_effects() == []


def test_successful_rejection_has_no_audit_recorded_flag(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    out = ex.handler(fx.event([fx.CLUSTER_SAR], override=True))
    assert out["error"] == "SOX_VIOLATION" and "audit_recorded" not in out
    assert aws.audits("SOX_VIOLATION_REJECTED")


def test_local_mode_audit_failure_emits_no_aws_metric(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("local mode must not reach AWS")

    monkeypatch.setattr(ex.boto3, "client", boom)
    monkeypatch.setattr(ex.boto3, "resource", boom)
    monkeypatch.setattr(ex, "write_audit_record_local",
                        lambda record: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr(ex, "execute_file_sar", lambda cluster, mode: {"status": "filed_locally"})
    out = ex.handler(fx.event([fx.CLUSTER_SAR], mode="local", token=None))
    assert out["actions"][0]["outcome_recorded"] is False and out["audit_incomplete"] is True
    sox = ex.handler(fx.event([fx.CLUSTER_SAR], mode="local", token=None, override=True))
    assert sox["error"] == "SOX_VIOLATION" and sox["audit_recorded"] is False


# ─── Executor SOX value rules ────────────────────────────────
def _payload(**cluster_overrides):
    payload = fx.event([dict(fx.CLUSTER_SAR, **cluster_overrides)])["compliance_output"]
    return payload


@pytest.mark.parametrize("overrides, field", [
    ({"decision": "APPROVED"}, "decision"),
    ({"challenger_failed": "false"}, "challenger_failed"),
    ({"guardrail_triggered": 0}, "guardrail_triggered"),
    ({"challenger_opinion": "MAYBE"}, "challenger_opinion"),
    ({"cluster_id": 7}, "cluster_id"),
    ({"cluster_id": "has space"}, "cluster_id"),
    ({"cluster_id": "x" * 129}, "cluster_id"),
    ({"sar_narrative": "n" * 8001}, "sar_narrative"),
    ({"sar_narrative": None}, "sar_narrative"),
    ({"challenger_rationale": "r" * 4001}, "challenger_rationale"),
    ({"model_metadata": {"sar_call": {"override": 1}}}, "model_metadata"),
    ({"model_metadata": {"a": [{"b": {"Bypass": 1}}]}}, "model_metadata"),
    ({"model_metadata": {"a": {"b": {"c": {"d": {"e": 1}}}}}}, "model_metadata"),  # 5 levels
    ({"model_metadata": {"a": [[[[1]]]]}}, "model_metadata"),  # lists count as levels
    ({"model_metadata": "flat"}, "model_metadata"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_cluster_value_violations(overrides, field):
    violation = ex.check_sox_violation_payload(_payload(**overrides))
    assert violation is not None and f"'{field}'" in violation
    for value in overrides.values():
        if isinstance(value, str) and len(value) > 3:
            assert value not in violation  # names the field, never the value


@pytest.mark.parametrize("key, value", [
    ("compliance_id", "has space"), ("compliance_id", 1), ("detection_id", "x" * 129),
    ("timestamp", "t" * 41), ("timestamp", 1700000000), ("provenance_status", "TRUSTED"),
    ("dispatch_token", "abc"), ("dispatch_token", 1), ("request_ref", "not-a-uuid"),
    ("clusters_assessed", "c1"),
])
def test_payload_value_violations(key, value):
    payload = _payload()
    payload[key] = value
    violation = ex.check_sox_violation_payload(payload)
    assert violation is not None and f"'{key}'" in violation


def test_non_dict_cluster_is_a_violation():
    payload = _payload()
    payload["clusters_assessed"].append("c2")
    assert "index 1" in ex.check_sox_violation_payload(payload)


def test_model_metadata_depth_four_is_allowed():
    # model_metadata itself is level 1.
    assert ex.check_sox_violation_payload(_payload(model_metadata={"a": {"b": {"c": 1}}})) is None
    assert ex.check_sox_violation_payload(_payload(model_metadata={"a": {"b": {"c": {"d": 1}}}})) is None


def test_prose_containing_override_is_not_a_violation():
    narrative = "The analyst asked us to override and bypass review; we decline."
    assert ex.check_sox_violation_payload(_payload(sar_narrative=narrative)) is None
    assert ex.check_sox_violation_payload(_payload(challenger_rationale="approve? reopen?")) is None


def test_hostile_model_metadata_nesting_does_not_recurse():
    deep = {}
    node = deep
    for _ in range(10000):
        node["k"] = {}
        node = node["k"]
    assert "model_metadata" in ex.check_sox_violation_payload(_payload(model_metadata=deep))


def test_value_violation_reaches_handler_as_sox(monkeypatch):
    aws = _executor(monkeypatch, [fx.CLUSTER_SAR])
    out = ex.handler(fx.event([dict(fx.CLUSTER_SAR, decision="APPROVED")]))
    assert out["error"] == "SOX_VIOLATION" and "decision" in out["message"]
    assert aws.kinds() == ["audit"] and aws.side_effects() == []


# ─── Breaker: hold intent and release completion ───

import circuit_breaker.handler as cb  # noqa: E402
from _breaker_fixtures import FakeBreakerAws, client_error  # noqa: E402


def test_breaker_intent_failure_still_trips_then_raises(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.gov.put_error["GOVERNANCE_HOLD_INTENT"] = RuntimeError("ddb down")
    with pytest.raises(cb.GovernanceAuditWriteError):
        cb.invoke_circuit_breaker(reason="test", mode="live")
    assert [e[1] for e in aws.log if e[0] == "attach"] == list(cb.AGENT_ROLES)
    assert aws.iam.held == set(cb.AGENT_ROLES)  # the hold is verified in place
    assert aws.gov.by_type("GOVERNANCE_HOLD")  # the post-attach record still written


def test_breaker_intent_record_precedes_attach(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    cb.invoke_circuit_breaker(reason="test", mode="live")
    kinds = [(e[0], e[1] if len(e) > 1 else None) for e in aws.log]
    assert kinds.index(("put", "GOVERNANCE_HOLD_INTENT")) < kinds.index(("attach", cb.AGENT_ROLES[0]))
    (intent,) = aws.gov.by_type("GOVERNANCE_HOLD_INTENT")
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert intent["event_id"] == "intent-" + hold["event_id"]
    assert intent["roles_targeted"] == list(cb.AGENT_ROLES)


def test_breaker_hold_record_failure_is_still_fatal(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.gov.put_error["GOVERNANCE_HOLD"] = RuntimeError("ddb down")
    with pytest.raises(cb.GovernanceAuditWriteError):
        cb.invoke_circuit_breaker(reason="test", mode="live")


_APPROVAL = {"release_request_id": "r-1", "hold_event_id": "hold-A", "hold_generation": 1,
             "requested_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-operator/alice",
             "approved_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-approver/bob"}


def test_release_completion_record_after_detach_with_per_role_results(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.record_hold("hold-A")
    aws.iam.detach_error[cb.AGENT_ROLES[2]] = client_error("AccessDenied", "DetachRolePolicy")
    result = cb._perform_release(dict(_APPROVAL))
    assert result["status"] == "GOVERNANCE_HOLD" and set(result["detach_failures"]) == {cb.AGENT_ROLES[2]}
    completed_at = next(i for i, e in enumerate(aws.log) if e[:2] == ("put", "GOVERNANCE_HOLD_RELEASE_COMPLETED"))
    assert max(i for i, e in enumerate(aws.log) if e[0] == "detach") < completed_at
    (done,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert done["roles_detached"] == list(cb.AGENT_ROLES[:2])
    assert set(done["detach_failures"]) == {cb.AGENT_ROLES[2]}
    assert done["final_status"] == "GOVERNANCE_HOLD" and done["release_request_id"] == "r-1"
    assert "audit_incomplete" not in result


def test_release_completion_write_failure_sets_audit_incomplete(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.record_hold("hold-A")
    aws.gov.put_error["GOVERNANCE_HOLD_RELEASE_COMPLETED"] = RuntimeError("ddb down")
    result = cb._perform_release(dict(_APPROVAL))
    assert result["status"] == "ACTIVE" and result["audit_incomplete"] is True
    assert aws.gov.by_type("GOVERNANCE_HOLD_RELEASED")
