"""
record_day on every executor audit record. The executor-audit by_day_ts index is keyed on
record_day, so a record without it (the SOX / provenance / replay records
before this change) is invisible to the console audit reader and the SOX
demo lookup. Records go through the REAL write_audit_record against a fake
table; nothing reaches AWS.
"""
import json
import os
import sys
from datetime import datetime, timezone

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _executor_fixtures as fx  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402


def _today():
    return datetime.now(timezone.utc).date().isoformat()


@pytest.fixture
def aws(monkeypatch):
    return fx.FakeExecutorAws(fx.stored_record([fx.CLUSTER_SAR, fx.CLUSTER_BREAKER])).install(
        monkeypatch, ex)


def _assert_day_matches_timestamp(item):
    assert item["record_day"] == ex._utc_day(item["timestamp"])
    assert item["record_day"] == datetime.fromisoformat(item["timestamp"]).astimezone(
        timezone.utc).date().isoformat()


def test_sox_violation_record_has_record_day(aws):
    ex.handler(fx.event([fx.CLUSTER_SAR], override=True))
    (item,) = aws.audits("SOX_VIOLATION_REJECTED")
    _assert_day_matches_timestamp(item)


def test_envelope_sox_violation_record_has_record_day(aws):
    ex.handler(dict(fx.event([fx.CLUSTER_SAR]), bypass=True))
    (item,) = aws.audits("SOX_VIOLATION_REJECTED")
    _assert_day_matches_timestamp(item)


def test_provenance_rejection_record_has_record_day(aws):
    ex.handler(fx.event([fx.CLUSTER_SAR, fx.CLUSTER_BREAKER], token=None))
    (item,) = aws.audits("PROVENANCE_CHECK_FAILED")
    assert item["violation_type"] == "dispatch token invalid"
    _assert_day_matches_timestamp(item)


def test_replay_rejection_record_has_record_day(aws):
    aws.state = True
    ex.handler(fx.event([fx.CLUSTER_SAR, fx.CLUSTER_BREAKER]))
    (item,) = aws.audits("PROVENANCE_CHECK_FAILED")
    assert item["violation_type"] == "REPLAY_REJECTED"
    _assert_day_matches_timestamp(item)


def test_intent_and_action_records_have_record_day(aws):
    ex.handler(fx.event([fx.CLUSTER_SAR, fx.CLUSTER_BREAKER]))
    taken = {i["action_taken"] for i in aws.audit_items}
    assert {"ACTION_INTENT", "FILED", "CIRCUIT_BREAKER_INVOKED"} <= taken
    for item in aws.audit_items:
        _assert_day_matches_timestamp(item)


def test_existing_record_day_is_kept(aws):
    ex.write_audit_record({"action_id": "a", "timestamp": "2026-01-02T03:04:05+00:00",
                           "record_day": "2026-01-01"})
    assert aws.audit_items[-1]["record_day"] == "2026-01-01"


@pytest.mark.parametrize("ts, day", [
    ("2026-03-04T23:30:00-05:00", "2026-03-05"),   # aware, converted to UTC
    ("2026-03-04T23:30:00", "2026-03-04"),          # naive taken as UTC
    ("2026-03-04T00:00:01+00:00", "2026-03-04"),
])
def test_utc_day_conversion(ts, day):
    assert ex._utc_day(ts) == day


@pytest.mark.parametrize("ts", ["not a time", None, 12, ""])
def test_unparsable_timestamp_falls_back_to_today(aws, ts):
    record = {"action_id": "a"}
    if ts is not None:
        record["timestamp"] = ts
    ex.write_audit_record(record)
    assert aws.audit_items[-1]["record_day"] == _today()


def test_local_sink_uses_the_same_default(monkeypatch, tmp_path):
    sink = tmp_path / "executor_audit.jsonl"
    monkeypatch.setattr(ex, "LOCAL_AUDIT_FILE", str(sink))
    ex.write_audit_record_local({"action_id": "a", "timestamp": "2026-03-04T23:30:00-05:00"})
    ex.write_audit_record_local({"action_id": "b", "timestamp": "x", "record_day": "2026-01-01"})
    first, second = [json.loads(line) for line in sink.read_text(encoding="utf-8").splitlines()]
    assert first["record_day"] == "2026-03-05"
    assert second["record_day"] == "2026-01-01"
