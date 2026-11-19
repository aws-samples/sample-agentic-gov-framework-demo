"""
Test: Circuit Breaker — After disable, agents return 503.
"""
import pytest
import json
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker.handler import handler as cb_handler, get_status, re_enable, STATE_FILE


class TestCircuitBreaker503:
    """Verify 503 Governance Hold behavior after circuit breaker fires."""

    def setup_method(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def teardown_method(self):
        if os.path.exists(STATE_FILE):
            os.remove(STATE_FILE)

    def test_invoke_returns_503(self):
        """Circuit breaker invocation returns http_status 503."""
        result = cb_handler({
            "action": "invoke",
            "mode": "local",
            "trigger_reason": "503 test"
        })
        assert result["http_status"] == 503

    def test_status_shows_governance_hold(self):
        """After invoke, status check shows GOVERNANCE_HOLD."""
        cb_handler({"action": "invoke", "mode": "local", "trigger_reason": "status test"})
        status = get_status("local")
        assert status["status"] == "GOVERNANCE_HOLD"

    def test_re_enable_restores_active(self):
        """Re-enable returns system to ACTIVE state."""
        cb_handler({"action": "invoke", "mode": "local", "trigger_reason": "re-enable test"})
        re_enable("local")
        status = get_status("local")
        assert status["status"] == "ACTIVE"

    def test_not_engaged_shows_active(self):
        """When circuit breaker has not fired, status is ACTIVE."""
        status = get_status("local")
        assert status["status"] == "ACTIVE"
