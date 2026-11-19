"""
Single decision per detection + dispatch capability token — compliance part,
then the executor-side enforcement (verify_compliance_provenance with
dispatch_token).
"""
import hashlib
import logging
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import (  # noqa: E402
    FakeAws, canceled, cluster, detection_output, load_compliance_shim, post,
)

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.delenv("ALLOW_UNVERIFIED_EVALUATION", raising=False)
    fake = FakeAws().install(monkeypatch, ch)
    fake.det = detection_output([cluster("c1"), cluster("c2")])
    fake.store_detection(fake.det)
    return fake


def _run(aws):
    return ch.handler({"mode": "live", "detection_output": aws.det})


def test_first_verified_run_writes_decision_and_marker_conditionally(aws):
    out = _run(aws)
    assert out["provenance_status"] == "VERIFIED"
    (items,) = aws.transactions
    assert len(items) == 2
    decision, marker = items[0]["Put"], items[1]["Put"]
    for put in (decision, marker):
        assert put["TableName"] == "compliance-decisions"
        assert put["ConditionExpression"] == "attribute_not_exists(compliance_id)"
    assert decision["Item"]["compliance_id"] == {"S": out["compliance_id"]}
    assert marker["Item"] == {
        "compliance_id": {"S": "detection#det-0001"},
        "decision_compliance_id": {"S": out["compliance_id"]},
        "timestamp": {"S": out["timestamp"]},
        "record_type": {"S": "DETECTION_DECISION_MARKER"},
    }
    # Pre-check ran first, consistently, on the marker key.
    pre = [e for e in aws.events if e[0] == "get_item" and e[1] == "compliance-decisions"]
    assert pre == [("get_item", "compliance-decisions", {"compliance_id": "detection#det-0001"}, True)]
    assert aws.kinds().index("get_item") < aws.kinds().index("converse")


def test_decision_item_shape(aws):
    out = _run(aws)
    item = aws.decision_item()
    assert item["record_day"] == out["timestamp"][:10]
    assert item["provenance_status"] == "VERIFIED"
    assert item["drift_counts"]["clusters"] == 2
    assert "record_day" not in aws.transactions[0][1]["Put"]["Item"]  # marker stays out of by_day_ts
    assert [c["cluster_id"] for c in item["clusters_assessed"]] == ["c1", "c2"]


def test_second_run_is_409_without_bedrock(aws):
    aws.store_marker("det-0001")
    assert _run(aws) == {"error": "DUPLICATE_DECISION",
                         "message": "a decision already exists for this detection"}
    assert "bedrock-runtime" not in aws.clients_built
    assert aws.transactions == [] and aws.metrics == []


def test_shim_maps_duplicate_to_409(aws, monkeypatch):
    aws.store_marker("det-0001")
    shim = load_compliance_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    status, body = post(shim, {"detection_output": aws.det})
    assert status == 409 and body["error"] == "DUPLICATE_DECISION"


def test_race_on_marker_is_409_and_assessment_discarded(aws):
    aws.write_error = canceled(("None", "ConditionalCheckFailed"))
    out = _run(aws)
    assert out == {"error": "DUPLICATE_DECISION",
                   "message": "a decision already exists for this detection"}
    assert "clusters_assessed" not in out and "dispatch_token" not in out
    assert aws.metrics == []


@pytest.mark.parametrize("error", [
    canceled(("ConditionalCheckFailed", "None")),   # decision item itself
    canceled(("None", "None")),
    RuntimeError("ddb down"),
], ids=["decision-condition", "other-cancel", "runtime"])
def test_other_transaction_failures_raise_audit_write_error(aws, error):
    aws.write_error = error
    with pytest.raises(ch.ComplianceAuditWriteError):
        _run(aws)
    assert aws.metrics == []


def test_precheck_lookup_failure_fails_closed_without_bedrock(aws, monkeypatch):
    calls = []
    real = ch.decision_exists

    def failing(detection_id):
        calls.append(detection_id)
        aws.get_item_error = RuntimeError("down")
        return real(detection_id)

    monkeypatch.setattr(ch, "decision_exists", failing)
    with pytest.raises(ch.ComplianceAuditWriteError):
        _run(aws)
    assert calls == ["det-0001"] and "bedrock-runtime" not in aws.clients_built


def test_dispatch_token_returned_only_hash_stored_never_logged(aws, caplog):
    caplog.set_level(logging.DEBUG)
    out = _run(aws)
    token = out["dispatch_token"]
    assert TOKEN_RE.fullmatch(token)
    item = aws.decision_item()
    assert "dispatch_token" not in item
    assert item["dispatch_token_sha256"] == hashlib.sha256(token.encode("ascii")).hexdigest()
    assert token not in repr(aws.transactions)
    assert token not in caplog.text
    assert item["dispatch_token_sha256"] not in caplog.text


def test_tokens_are_unique_per_decision(monkeypatch):
    tokens = set()
    for n in range(3):
        aws = FakeAws().install(monkeypatch, ch)
        det = detection_output(detection_id=f"det-{n}")
        aws.store_detection(det)
        tokens.add(ch.handler({"mode": "live", "detection_output": det})["dispatch_token"])
    assert len(tokens) == 3


def test_unverified_issues_no_token_and_writes_no_marker(aws, monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    aws.tables["detection-results"].clear()
    out = _run(aws)
    assert out["provenance_status"] == "UNVERIFIED"
    assert "dispatch_token" not in out
    assert aws.transactions == []
    assert not any(str(p.get("compliance_id", "")).startswith("detection#") for p in aws.puts)
    assert "dispatch_token_sha256" not in aws.puts[0]
    # No duplicate pre-check on UNVERIFIED runs either.
    assert not [e for e in aws.events if e[0] == "get_item" and e[1] == "compliance-decisions"]


def test_not_checked_issues_no_token(monkeypatch):
    FakeAws().install(monkeypatch, ch, durable=False)
    out = ch.handler({"mode": "live", "detection_output": detection_output()})
    assert out["provenance_status"] == "NOT_CHECKED" and "dispatch_token" not in out


# ─── Executor-side enforcement ───────
import json  # noqa: E402

import _executor_fixtures as fx  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402
from app import invoke_live  # noqa: E402

CLUSTERS = [fx.CLUSTER_SAR, fx.CLUSTER_REVIEW]


@pytest.fixture
def ex_aws(monkeypatch):
    return fx.FakeExecutorAws(fx.stored_record(CLUSTERS)).install(monkeypatch, ex)


def test_dispatch_token_is_keyword_only_with_no_default(ex_aws):
    with pytest.raises(TypeError):
        ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS)  # noqa
    with pytest.raises(TypeError):
        ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS, fx.TOKEN)  # noqa
    assert ex_aws.events == []  # TypeError before any lookup


def test_provenance_status_checked_before_token(ex_aws):
    ex_aws.record["provenance_status"] = "UNVERIFIED"
    error, verified = ex.verify_compliance_provenance(
        "comp-1", "det-1", CLUSTERS, dispatch_token="w" * 43)
    assert error == "compliance record is not provenance-verified" and verified is None


@pytest.mark.parametrize("status", [None, "UNVERIFIED", "NOT_CHECKED", "verified"])
def test_record_must_be_verified(ex_aws, status):
    if status is None:
        del ex_aws.record["provenance_status"]
    else:
        ex_aws.record["provenance_status"] = status
    error, _ = ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS, dispatch_token=fx.TOKEN)
    assert error == "compliance record is not provenance-verified"


def test_cluster_check_still_applies_after_a_valid_token(ex_aws):
    forged = [dict(fx.CLUSTER_SAR, sar_narrative="forged"), fx.CLUSTER_REVIEW]
    error, _ = ex.verify_compliance_provenance("comp-1", "det-1", forged, dispatch_token=fx.TOKEN)
    assert error.startswith("field mismatch for cluster index 0: sar_narrative")
    assert "forged" not in error


@pytest.mark.parametrize("token", [None, "", "abc", "w" * 43, fx.TOKEN + "x", 43, fx.TOKEN.upper()],
                         ids=repr)
def test_bad_token_rejected_without_leaking(ex_aws, token):
    error, verified = ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS, dispatch_token=token)
    assert error == "dispatch token invalid" and verified is None
    assert fx.TOKEN_SHA256 not in error


@pytest.mark.parametrize("stored", [None, "", "ABC", fx.TOKEN_SHA256.upper(), fx.TOKEN_SHA256[:-1]],
                         ids=repr)
def test_malformed_stored_hash_rejected(ex_aws, stored):
    if stored is None:
        del ex_aws.record["dispatch_token_sha256"]
    else:
        ex_aws.record["dispatch_token_sha256"] = stored
    error, _ = ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS, dispatch_token=fx.TOKEN)
    assert error == "dispatch token invalid"


def test_lookup_is_consistent_read(ex_aws, monkeypatch):
    seen = {}
    real = fx._ComplianceTable.get_item

    def spy(self, Key, ConsistentRead=False, ProjectionExpression=None):  # noqa: N803
        if ProjectionExpression is None:
            seen["consistent"] = ConsistentRead
        return real(self, Key, ConsistentRead, ProjectionExpression)

    monkeypatch.setattr(fx._ComplianceTable, "get_item", spy)
    ex.verify_compliance_provenance("comp-1", "det-1", CLUSTERS, dispatch_token=fx.TOKEN)
    assert seen == {"consistent": True}


@pytest.mark.parametrize("token", [None, "w" * 43], ids=["missing", "wrong"])
def test_handler_without_valid_token_never_claims_lease(ex_aws, token):
    out = ex.handler(fx.event(CLUSTERS, token=token))
    assert out["error"] == "PROVENANCE_CHECK_FAILED"
    assert "dispatch token invalid" in out["message"]
    assert not ex_aws.claimed() and ex_aws.side_effects() == []
    (rejection,) = ex_aws.audits("PROVENANCE_CHECK_FAILED")
    assert rejection["violation_type"] == "dispatch token invalid"


def test_handler_unverified_record_never_claims_lease(ex_aws):
    ex_aws.record["provenance_status"] = "UNVERIFIED"
    out = ex.handler(fx.event(CLUSTERS))
    assert out["error"] == "PROVENANCE_CHECK_FAILED"
    assert "not provenance-verified" in out["message"]
    assert not ex_aws.claimed() and ex_aws.side_effects() == []


def test_correct_token_routes_then_replay_rejected(ex_aws):
    out = ex.handler(fx.event(CLUSTERS))
    assert "error" not in out and out["total_filed"] == 1 and out["total_escalated"] == 1
    assert ex_aws.finalized()
    replay = ex.handler(fx.event(CLUSTERS))
    assert replay["error"] == "PROVENANCE_CHECK_FAILED"
    assert ex_aws.audits("PROVENANCE_CHECK_FAILED")[-1]["violation_type"] == "REPLAY_REJECTED"
    assert len(ex_aws.side_effects()) == 2  # no second side effect


def test_token_never_in_audit_records_response_or_logs(ex_aws, caplog):
    caplog.set_level(logging.DEBUG)
    out = ex.handler(fx.event(CLUSTERS))
    bad = ex.handler(fx.event(CLUSTERS, token=fx.TOKEN[:-1] + "Z"))
    sox = ex.handler(fx.event(CLUSTERS, override=True))
    for blob in (json.dumps(ex_aws.audit_items, default=str), json.dumps(out), json.dumps(bad),
                 json.dumps(sox), caplog.text):
        assert fx.TOKEN not in blob and fx.TOKEN_SHA256 not in blob
    assert ex_aws.audits("SOX_VIOLATION_REJECTED")


def test_sox_payload_without_token_is_sox_not_provenance(ex_aws):
    out = ex.handler(fx.event(CLUSTERS, token=None, override_decision="FILE_SAR"))
    assert out["error"] == "SOX_VIOLATION"
    assert ex_aws.events[0] == ("audit", "SOX_VIOLATION_REJECTED")  # no lookup first


def test_malformed_token_is_sox_violation_naming_it(ex_aws):
    out = ex.handler(fx.event(CLUSTERS, token="abc"))
    assert out["error"] == "SOX_VIOLATION"
    assert "dispatch_token" in out["message"] and "abc" not in out["message"]
    assert not ex_aws.claimed()


def test_digest_parity_with_console_helper(ex_aws):
    payload = {"compliance_output": dict(fx.event(CLUSTERS)["compliance_output"], override=1)}
    shim_event = {"mode": "live", "compliance_output": payload["compliance_output"]}
    executor_input = ex._redact_dispatch_token(shim_event)
    console_input = invoke_live._executor_event_for_digest(payload)
    assert ex._event_digest(executor_input) == invoke_live._event_digest(console_input)
    for digest_input in (executor_input, console_input):
        assert fx.TOKEN not in json.dumps(digest_input)
        assert digest_input["compliance_output"]["dispatch_token"] == "<redacted>"
    assert shim_event["compliance_output"]["dispatch_token"] == fx.TOKEN  # input not mutated
    # The SOX rejection record carries exactly that digest.
    ex.handler(shim_event)
    (record,) = ex_aws.audits("SOX_VIOLATION_REJECTED")
    assert record["event_hash"] == invoke_live._event_digest(console_input)


def test_digest_unchanged_for_events_without_token():
    event = {"mode": "live", "compliance_output": {"compliance_id": "c"}}
    assert ex._redact_dispatch_token(event) is event
    assert ex._event_digest(event) == invoke_live._event_digest(
        invoke_live._executor_event_for_digest({"compliance_output": {"compliance_id": "c"}}))
