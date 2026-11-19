"""
Test: Circuit Breaker — alarm-source verification and
fail-closed trip.

handle_alarm_event must reject any alarm-shaped event whose alarmArn is not
on the trusted allow-list, and must never fabricate an audit justification
from caller-supplied state_reason text.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import circuit_breaker.handler as cb


TRUSTED = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:fsi-challenger-dispute-rate-breach"


class TestAlarmSourceVerification:
    def test_forged_alarm_arn_rejected(self, monkeypatch):
        """An alarm-shaped event with an attacker ARN is rejected, not trusted."""
        monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
        event = {
            "source": "aws.cloudwatch",
            "alarmArn": "arn:aws:cloudwatch:us-east-1:999999999999:alarm:evil",
            "alarmData": {"alarmName": "evil", "state": {"value": "ALARM", "reason": "hacked"}},
        }
        result = cb.handler(event)
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403

    def test_missing_allowlist_rejects(self, monkeypatch):
        """With no TRUSTED_ALARM_ARNS configured, no alarm source can be verified."""
        monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [])
        event = {
            "source": "aws.cloudwatch",
            "alarmArn": TRUSTED,
            "alarmData": {"alarmName": "x", "state": {"value": "ALARM", "reason": "r"}},
        }
        result = cb.handler(event)
        assert result["status"] == "REJECTED"

    def test_trusted_arn_uses_known_reason_not_caller_text(self, monkeypatch):
        """A trusted ARN trips with the KNOWN reason, never the caller's
        state_reason text."""
        monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
        captured = {}

        def fake_invoke(reason, mode="local", **kwargs):
            captured["reason"] = reason
            captured["mode"] = mode
            return {"status": "GOVERNANCE_HOLD", "http_status": 503}

        monkeypatch.setattr(cb, "invoke_circuit_breaker", fake_invoke)
        # Stored records corroborate the alarm.
        monkeypatch.setattr(cb, "corroborate", lambda name, **k: {"corroborated": True})
        event = {
            "source": "aws.cloudwatch",
            "alarmArn": TRUSTED,
            "alarmData": {
                "alarmName": "fsi-challenger-dispute-rate-breach",
                "state": {"value": "ALARM", "reason": "ATTACKER CONTROLLED TEXT"},
            },
        }
        result = cb.handler(event)
        assert result["http_status"] == 503
        assert captured["mode"] == "live"
        assert "ATTACKER CONTROLLED TEXT" not in captured["reason"]
        assert captured["reason"] == cb.KNOWN_ALARM_REASONS["fsi-challenger-dispute-rate-breach"]

    def test_non_alarm_state_ignored(self, monkeypatch):
        monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [TRUSTED])
        event = {
            "source": "aws.cloudwatch",
            "alarmArn": TRUSTED,
            "alarmData": {
                "alarmName": "fsi-challenger-dispute-rate-breach",
                "state": {"value": "OK", "reason": "recovered"},
            },
        }
        result = cb.handler(event)
        assert result["status"] == "IGNORED"


class TestTripFailsClosed:
    def test_trip_raises_when_attach_not_confirmed(self, monkeypatch):
        """If the deny policy cannot be confirmed attached to every role, the
        trip raises instead of falsely reporting GOVERNANCE_HOLD."""
        # Fake IAM: attach succeeds silently but get_status confirms nothing.
        fake_iam = MagicMock()
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        # get_status returns ACTIVE (nothing actually attached)
        monkeypatch.setattr(cb, "get_status", lambda mode: {"status": "ACTIVE"})
        monkeypatch.setattr(cb, "write_governance_hold_event", lambda *a, **k: None)
        # post-trip reconcile audit and state claim: never a real table
        monkeypatch.setattr(cb, "_governance_table", lambda: MagicMock())
        monkeypatch.setattr(cb, "_state_table", lambda: MagicMock())

        with pytest.raises(cb.GovernanceHoldEnforcementError):
            cb.invoke_circuit_breaker(reason="test", mode="live")

    def test_trip_succeeds_when_all_roles_confirmed(self, monkeypatch):
        fake_iam = MagicMock()
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        monkeypatch.setattr(
            cb, "get_status",
            lambda mode: {"status": "GOVERNANCE_HOLD", "revoked_roles": list(cb.AGENT_ROLES)},
        )
        monkeypatch.setattr(cb, "write_governance_hold_event", lambda *a, **k: None)
        # post-trip reconcile audit and state claim: never a real table
        monkeypatch.setattr(cb, "_governance_table", lambda: MagicMock())
        monkeypatch.setattr(cb, "_state_table", lambda: MagicMock())

        result = cb.invoke_circuit_breaker(reason="test", mode="live")
        assert result["status"] == "GOVERNANCE_HOLD"
        assert result["http_status"] == 503
        assert set(result["roles_revoked"]) == set(cb.AGENT_ROLES)
