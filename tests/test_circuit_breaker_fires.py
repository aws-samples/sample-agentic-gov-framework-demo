"""
Test: Circuit Breaker — Fires when threshold breached, roles revoked.
"""
import pytest
import json
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker.handler import handler as cb_handler, re_enable, STATE_FILE


class TestCircuitBreakerFires:
    """Verify circuit breaker fires on threshold breach."""

    def setup_method(self):
        """Clean up state file before each test."""
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def teardown_method(self):
        """Clean up state file after each test."""
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def test_dispute_rate_breach_triggers_circuit_breaker(self):
        """Dispute rate > 51% triggers circuit breaker."""
        result = cb_handler({
            "action": "check",
            "mode": "local",
            "metrics": {"dispute_rate": 0.52, "guardrail_intervention_rate": 0.03, "detection_volume_multiplier": 1.0}
        })
        assert result["status"] == "GOVERNANCE_HOLD"
        assert "dispute rate" in result["trigger_reason"].lower()

    def test_guardrail_rate_breach_triggers_circuit_breaker(self):
        """Guardrail rate > 10% triggers circuit breaker."""
        result = cb_handler({
            "action": "check",
            "mode": "local",
            "metrics": {"dispute_rate": 0.20, "guardrail_intervention_rate": 0.15, "detection_volume_multiplier": 1.0}
        })
        assert result["status"] == "GOVERNANCE_HOLD"

    def test_volume_anomaly_triggers_circuit_breaker(self):
        """Volume > 3x baseline triggers circuit breaker."""
        result = cb_handler({
            "action": "check",
            "mode": "local",
            "metrics": {"dispute_rate": 0.10, "guardrail_intervention_rate": 0.02, "detection_volume_multiplier": 4.5}
        })
        assert result["status"] == "GOVERNANCE_HOLD"

    def test_healthy_metrics_no_trigger(self):
        """Metrics within thresholds do NOT trigger."""
        result = cb_handler({
            "action": "check",
            "mode": "local",
            "metrics": {"dispute_rate": 0.20, "guardrail_intervention_rate": 0.05, "detection_volume_multiplier": 1.5}
        })
        assert result["status"] == "OK"

    def test_roles_listed_in_result(self):
        """Circuit breaker result lists all revoked roles."""
        result = cb_handler({
            "action": "invoke",
            "mode": "local",
            "trigger_reason": "Test invocation"
        })
        assert "roles_revoked" in result
        assert len(result["roles_revoked"]) == 3
