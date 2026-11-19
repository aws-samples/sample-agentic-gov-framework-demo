"""
Rejections never echo caller text or stored narratives: the executor's
SOX / provenance / replay paths and the circuit breaker's alarm and
auto-trip refusals write only fixed text, field names, locations and
cluster indices into logs, audit items and responses.
"""
import json
import logging
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _executor_fixtures as fx  # noqa: E402
import circuit_breaker.handler as cb  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402

CARD = "4111111111111111"  # standard test card number, not a real account
STORED_MARKER = "STORED-NARRATIVE-MARKER-7f3a"
FORGED_MARKER = "FORGED-NARRATIVE-MARKER-c91e"
LONG_ID = "".join(chr(ord("a") + (i * 7) % 26) for i in range(100_000))


@pytest.fixture
def aws(monkeypatch):
    stored = [
        dict(fx.CLUSTER_SAR, sar_narrative=STORED_MARKER + " A"),
        dict(fx.CLUSTER_REVIEW, sar_narrative=STORED_MARKER + " R"),
    ]
    return fx.FakeExecutorAws(fx.stored_record(stored)).install(monkeypatch, ex)


def _captured(caplog, aws, result):
    """Everything a rejection can leave behind: log text, audit items, response."""
    logs = "\n".join(r.getMessage() for r in caplog.records)
    items = json.dumps(aws.audit_items, default=str)
    return logs + "\n" + items + "\n" + json.dumps(result, default=str)


def _assert_bounded(aws):
    assert aws.audit_items, "rejection must be audited"
    for item in aws.audit_items:
        assert len(item["violation_type"]) <= ex.MAX_VIOLATION_TYPE_CHARS
        assert len(json.dumps(item, default=str)) < 4096


def _assert_no_long_id_slice(text):
    for start in range(0, len(LONG_ID) - 20, 997):
        assert LONG_ID[start:start + 20] not in text


def test_card_number_as_envelope_key_is_not_echoed(aws, caplog):
    caplog.set_level(logging.DEBUG)
    event = fx.event([fx.CLUSTER_SAR])
    event[CARD] = True
    result = ex.handler(event)
    assert result["error"] == "SOX_VIOLATION"
    assert CARD not in _captured(caplog, aws, result)
    assert aws.audit_items[0]["violation_type"] == "Unexpected key in request envelope (not on allow-list)"
    _assert_bounded(aws)


def test_card_number_as_payload_key_is_not_echoed(aws, caplog):
    caplog.set_level(logging.DEBUG)
    event = fx.event([fx.CLUSTER_SAR])
    event["compliance_output"][CARD] = "x"
    result = ex.handler(event)
    assert result["error"] == "SOX_VIOLATION"
    assert CARD not in _captured(caplog, aws, result)
    assert aws.audit_items[0]["violation_type"] == "Unexpected key in compliance_output (not on allow-list)"
    _assert_bounded(aws)


def test_cluster_with_unexpected_key_and_long_id_is_not_echoed(aws, caplog):
    caplog.set_level(logging.DEBUG)
    cluster = dict(fx.CLUSTER_SAR, cluster_id=LONG_ID)
    cluster[CARD] = 1
    result = ex.handler(fx.event([fx.CLUSTER_REVIEW, cluster]))
    assert result["error"] == "SOX_VIOLATION"
    text = _captured(caplog, aws, result)
    assert CARD not in text
    _assert_no_long_id_slice(text)
    assert aws.audit_items[0]["violation_type"] == "Unexpected key in cluster index 1 (not on allow-list)"
    _assert_bounded(aws)


def test_long_cluster_id_value_is_not_echoed(aws, caplog):
    caplog.set_level(logging.DEBUG)
    result = ex.handler(fx.event([dict(fx.CLUSTER_SAR, cluster_id=LONG_ID)]))
    assert result["error"] == "SOX_VIOLATION"
    _assert_no_long_id_slice(_captured(caplog, aws, result))
    assert aws.audit_items[0]["violation_type"] == "Invalid value for field 'cluster_id' in cluster index 0"
    _assert_bounded(aws)


def test_forged_narrative_mismatch_names_field_and_index_only(aws, caplog):
    caplog.set_level(logging.DEBUG)
    asserted = [
        dict(fx.CLUSTER_SAR, sar_narrative=STORED_MARKER + " A"),
        dict(fx.CLUSTER_REVIEW, sar_narrative=FORGED_MARKER),
    ]
    result = ex.handler(fx.event(asserted))
    assert result["error"] == "PROVENANCE_CHECK_FAILED"
    text = _captured(caplog, aws, result)
    assert STORED_MARKER not in text
    assert FORGED_MARKER not in text
    (item,) = aws.audit_items
    assert item["violation_type"] == "field mismatch for cluster index 1: sar_narrative"
    assert aws.side_effects() == []
    _assert_bounded(aws)


def test_pan_shaped_compliance_id_is_not_stored_or_echoed(aws, caplog):
    caplog.set_level(logging.DEBUG)
    aws.record = None  # no stored record for this id
    result = ex.handler(fx.event([fx.CLUSTER_SAR], compliance_id=CARD, detection_id=CARD))
    assert result["error"] == "PROVENANCE_CHECK_FAILED"
    assert CARD not in _captured(caplog, aws, result)
    (item,) = aws.audit_items
    assert item["violation_type"] == "No stored compliance record for compliance_id"
    assert item["compliance_id"] == "invalid"
    assert item["detection_id"] == "invalid"
    _assert_bounded(aws)


def test_replay_rejection_does_not_echo_compliance_id(aws, caplog):
    caplog.set_level(logging.DEBUG)
    aws.state = True  # already processed
    asserted = [
        dict(fx.CLUSTER_SAR, sar_narrative=STORED_MARKER + " A"),
        dict(fx.CLUSTER_REVIEW, sar_narrative=STORED_MARKER + " R"),
    ]
    result = ex.handler(fx.event(asserted))
    assert result["error"] == "PROVENANCE_CHECK_FAILED"
    assert "comp-1" not in result["message"]
    assert "replay rejected" in result["message"]
    assert "comp-1" not in "\n".join(r.getMessage() for r in caplog.records)
    _assert_bounded(aws)


def test_safe_violation_bounds_and_screens():
    assert len(ex._safe_violation("x" * 10_000)) == ex.MAX_VIOLATION_TYPE_CHARS
    assert ex._safe_violation(f"bad {CARD} here") == ex.VIOLATION_WITHHELD
    assert ex._safe_record_id("comp-1") == "comp-1"
    assert ex._safe_record_id(CARD) == "invalid"
    assert ex._safe_record_id(LONG_ID) == "invalid"
    assert ex._safe_record_id({"x": 1}) == "invalid"


# ── circuit breaker ──
TRUSTED = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:fsi-challenger-dispute-rate-breach"


def _log_text(caplog):
    return "\n".join(r.getMessage() for r in caplog.records)


def test_breaker_untrusted_alarm_arn_is_not_echoed(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
    event = {
        "source": "aws.cloudwatch",
        "alarmArn": f"arn:aws:cloudwatch:us-east-1:999999999999:alarm:{CARD}",
        "alarmData": {"alarmName": CARD, "state": {"value": CARD}},
    }
    result = cb.handler(event)
    assert result["status"] == "REJECTED"
    assert CARD not in _log_text(caplog) + json.dumps(result)


def test_breaker_alarm_name_and_state_are_not_echoed(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
    event = {
        "source": "aws.cloudwatch",
        "alarmArn": TRUSTED,
        "alarmData": {"alarmName": CARD, "state": {"value": CARD}},
    }
    result = cb.handler(event)
    assert result["status"] == "IGNORED"
    assert result["message"] == "Alarm state is unrecognized, not ALARM — no action"
    assert CARD not in _log_text(caplog) + json.dumps(result)


@pytest.mark.parametrize("state", ["OK", "INSUFFICIENT_DATA"])
def test_breaker_known_states_are_still_reported(monkeypatch, state):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
    event = {"source": "aws.cloudwatch", "alarmArn": TRUSTED,
             "alarmData": {"state": {"value": state}}}
    assert cb.handler(event)["message"] == f"Alarm state is {state}, not ALARM — no action"


def test_breaker_unknown_trip_source_is_not_echoed(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS",
                        ["arn:aws:iam::123456789012:role/executor-agent-role"])
    monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
    result = cb.handler({"action": "auto_trip", "trip_source": CARD}, None)
    assert result["status"] == "REJECTED"
    assert CARD not in _log_text(caplog) + json.dumps(result)
