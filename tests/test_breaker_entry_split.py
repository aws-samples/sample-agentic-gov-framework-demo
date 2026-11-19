"""
Breaker entry-point split (BREAKER_ENTRY). Humans can't reach the alarm / auto_trip / check paths,
and the automated function refuses human actions. Live mode, mocked AWS.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import FakeBreakerAws, cb, principal  # noqa: E402

TRUSTED = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:fsi-challenger-dispute-rate-breach"
ALARM_EVENT = {"source": "aws.cloudwatch", "alarmArn": TRUSTED,
               "alarmData": {"alarmName": "fsi-challenger-dispute-rate-breach", "state": {"value": "ALARM"}}}


@pytest.fixture
def human(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
    monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS",
                        ["arn:aws:iam::123456789012:role/executor-agent-role"])
    return FakeBreakerAws().install(monkeypatch, entry="human")


@pytest.mark.parametrize("event", [
    ALARM_EVENT,
    {"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"},
    {"action": "check", "metrics": {"dispute_rate": 0.99}},
])
def test_human_entry_refuses_automated_paths(human, event):
    result = cb.handler(dict(event))
    assert result == {"status": "REJECTED", "http_status": 403,
                      "message": "action not available on this entry point"}
    assert "attach" not in human.kinds()


def test_human_entry_refuses_alarm_events_even_in_local_mode(human):
    result = cb.handler(dict(ALARM_EVENT, mode="local"))
    assert result["http_status"] == 403


@pytest.mark.parametrize("entry", ["automated", None, "bogus"])
@pytest.mark.parametrize("action", ["invoke", "request_release", "approve_release"])
def test_automated_entry_refuses_human_actions_without_sts(monkeypatch, entry, action):
    aws = FakeBreakerAws().install(monkeypatch, entry=entry)
    aws.record_hold()
    event = {"action": action, "trigger_reason_code": "OPERATOR_PRECAUTION",
             "release_request_id": "0" * 8 + "-0000-4000-8000-" + "0" * 12,
             **aws.proof(principal("fsi-breaker-approver", "bob"), "x")}
    result = cb.handler(event)
    assert result["http_status"] == 403 and result["message"] == "action not available on this entry point"
    assert aws.verified == []
    assert not [e for e in aws.log if e[0] in ("attach", "detach", "put")]


@pytest.mark.parametrize("entry", ["automated", None, "bogus"])
def test_automated_entry_still_serves_alarm_and_auto_trip(monkeypatch, entry):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
    monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS",
                        ["arn:aws:iam::123456789012:role/executor-agent-role"])
    FakeBreakerAws().install(monkeypatch, entry=entry)
    trips = []
    monkeypatch.setattr(cb, "invoke_circuit_breaker",
                        lambda reason, mode="local", **k: trips.append(reason) or {"status": "GOVERNANCE_HOLD"})
    assert cb.handler(dict(ALARM_EVENT))["status"] == "GOVERNANCE_HOLD"
    assert cb.handler({"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"})["status"] == "GOVERNANCE_HOLD"
    assert cb.handler({"action": "check", "metrics": {"dispute_rate": 0.99}})["status"] == "BREACH_DETECTED"
    assert len(trips) == 2


@pytest.mark.parametrize("entry", ["automated", "human"])
def test_status_served_on_both(monkeypatch, entry):
    FakeBreakerAws().install(monkeypatch, entry=entry)
    assert cb.handler({"action": "status"})["status"] == "ACTIVE"


def test_local_mode_with_entry_unset_still_simulates(monkeypatch, tmp_path):
    monkeypatch.delenv("BREAKER_ENTRY", raising=False)
    monkeypatch.setattr(cb, "STATE_FILE", str(tmp_path / "state.json"))
    result = cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "dev"})
    assert result["status"] == "GOVERNANCE_HOLD" and result["http_status"] == 503
