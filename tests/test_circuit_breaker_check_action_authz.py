"""
Test: Circuit Breaker — default/unspecified action=="check" must never trip
the kill switch with no authorization, reason enum, or attribution.

`action` defaults to "check" when the caller omits it entirely. Unlike
action=="invoke" (TRUSTED_BREAK_GLASS_ARNS + KNOWN_MANUAL_TRIGGER_REASONS)
and action=="auto_trip" (TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS +
KNOWN_AUTOMATED_TRIP_SOURCES), this path has no caller allow-list — any
principal with lambda:InvokeFunction can reach it. check_thresholds() must
therefore be evaluation-only in live mode: a breach is reported but never
reaches invoke_circuit_breaker(). The local-mode CLI/dev-demo/test
simulation path (used by test_circuit_breaker_fires.py) is unaffected.
"""
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import circuit_breaker.handler as cb


class TestCheckActionIsEvaluationOnlyInLiveMode:
    """action=="check" (including the default when action is
    omitted entirely) must never reach invoke_circuit_breaker() in live
    mode — it has no caller allow-list and no reason enum, so it cannot be
    held to the same authorization bar as invoke/auto_trip. Fix: make it
    report-only."""

    def test_default_omitted_action_with_breach_does_not_trip_in_live_mode(self, monkeypatch):
        """The exact gap: no 'action' key at all, mode resolves to live,
        metrics breach a threshold. Must NOT call invoke_circuit_breaker."""
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        tripped = {"called": False}

        def fake_invoke(reason, mode="local"):
            tripped["called"] = True
            return {"status": "GOVERNANCE_HOLD", "http_status": 503}

        monkeypatch.setattr(cb, "invoke_circuit_breaker", fake_invoke)

        result = cb.handler({
            "metrics": {
                "dispute_rate": 0.99,
                "guardrail_intervention_rate": 0.99,
                "detection_volume_multiplier": 99.0,
            }
        })

        assert tripped["called"] is False
        assert result["status"] != "GOVERNANCE_HOLD"
        assert result["status"] == "BREACH_DETECTED"
        assert "trigger_reason" in result

    def test_explicit_check_action_with_breach_does_not_trip_in_live_mode(self, monkeypatch):
        """Same gap, but with action=="check" supplied explicitly rather
        than omitted."""
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        tripped = {"called": False}
        monkeypatch.setattr(
            cb, "invoke_circuit_breaker",
            lambda reason, mode="local": tripped.update(called=True) or {"status": "GOVERNANCE_HOLD"},
        )

        result = cb.handler({
            "action": "check",
            "metrics": {"dispute_rate": 0.60, "guardrail_intervention_rate": 0.0, "detection_volume_multiplier": 1.0},
        })

        assert tripped["called"] is False
        assert result["status"] == "BREACH_DETECTED"

    def test_healthy_metrics_in_live_mode_still_report_ok(self, monkeypatch):
        """No breach -> still just OK, no change in behavior."""
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        result = cb.handler({
            "action": "check",
            "metrics": {"dispute_rate": 0.1, "guardrail_intervention_rate": 0.01, "detection_volume_multiplier": 1.0},
        })
        assert result["status"] == "OK"

    def test_local_mode_check_still_trips_for_dev_cli_simulation(self):
        """mode="local" is the no-AWS CLI/test simulation path — existing
        behavior (test_circuit_breaker_fires.py) must be unchanged."""
        if os.path.exists(cb.STATE_FILE):
            os.remove(cb.STATE_FILE)
        try:
            result = cb.handler({
                "action": "check",
                "mode": "local",
                "metrics": {"dispute_rate": 0.60, "guardrail_intervention_rate": 0.0, "detection_volume_multiplier": 1.0},
            })
            assert result["status"] == "GOVERNANCE_HOLD"
        finally:
            if os.path.exists(cb.STATE_FILE):
                os.remove(cb.STATE_FILE)


class TestUnknownActionNeverTrips:
    """The else-branch (an unrecognized action string) must return an error
    and never fall through to check_thresholds or any trip path."""

    def test_unknown_action_returns_error_not_a_trip(self, monkeypatch):
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        tripped = {"called": False}
        monkeypatch.setattr(
            cb, "invoke_circuit_breaker",
            lambda reason, mode="local": tripped.update(called=True) or {},
        )
        result = cb.handler({"action": "totally_made_up_action"})
        assert tripped["called"] is False
        assert "error" in result
