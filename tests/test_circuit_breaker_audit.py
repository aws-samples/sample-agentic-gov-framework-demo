"""
Test: Circuit Breaker — GOVERNANCE_HOLD event written correctly.
"""
import pytest
import json
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker.handler import handler as cb_handler, STATE_FILE


class TestCircuitBreakerAudit:
    """Verify circuit breaker writes proper audit events."""

    def setup_method(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def teardown_method(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def test_state_file_written_on_invoke(self):
        """Circuit breaker writes state file in local mode."""
        cb_handler({
            "action": "invoke",
            "mode": "local",
            "trigger_reason": "Audit test"
        })
        assert os.path.exists(STATE_FILE)

    def test_state_contains_required_fields(self):
        """State file contains all required audit fields."""
        cb_handler({
            "action": "invoke",
            "mode": "local",
            "trigger_reason": "Field test"
        })
        with open(STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)

        assert "status" in state
        assert state["status"] == "GOVERNANCE_HOLD"
        assert "event_id" in state
        assert "timestamp" in state
        assert "trigger_reason" in state
        assert "roles_revoked" in state

    def test_trigger_reason_captured(self):
        """Trigger reason is captured in the state."""
        reason = "Dispute rate 52% exceeded 51% threshold"
        cb_handler({
            "action": "invoke",
            "mode": "local",
            "trigger_reason": reason
        })
        with open(STATE_FILE, encoding="utf-8") as f:
            state = json.load(f)
        assert state["trigger_reason"] == reason
