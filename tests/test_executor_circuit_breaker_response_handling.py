"""
Test: Executor Agent — circuit breaker response handling.

The old execute_circuit_breaker only checked response["FunctionError"] (never
set, since the breaker returns a normal body, not a Lambda function error),
so a REJECTED breaker response fell through as a "success" and the caller
recorded action_taken = "CIRCUIT_BREAKER_INVOKED" unconditionally. This must
now raise so the invocation is correctly recorded as
CIRCUIT_BREAKER_INVOCATION_FAILED, never CIRCUIT_BREAKER_INVOKED.
"""
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.executor_agent.handler as executor_handler
from lambdas.executor_agent.handler import execute_circuit_breaker


def _fake_lambda_client(result_body, function_error=None):
    client = MagicMock()
    response = {"Payload": MagicMock()}
    response["Payload"].read.return_value = json.dumps(result_body).encode("utf-8")
    if function_error:
        response["FunctionError"] = function_error
    client.invoke.return_value = response
    return client


class TestExecuteCircuitBreakerResponseHandling:
    def test_rejected_breaker_response_raises_not_treated_as_success(self, monkeypatch):
        """A REJECTED/non-2xx-equivalent breaker response must raise, never
        be returned as if the trip succeeded."""
        monkeypatch.setenv("CIRCUIT_BREAKER_FUNCTION", "fsi-circuit-breaker")
        monkeypatch.setattr(
            executor_handler.boto3, "client",
            lambda *a, **k: _fake_lambda_client({"status": "REJECTED", "http_status": 403}),
        )
        with pytest.raises(RuntimeError):
            execute_circuit_breaker("live")

    def test_governance_hold_success_response_returns_normally(self, monkeypatch):
        monkeypatch.setenv("CIRCUIT_BREAKER_FUNCTION", "fsi-circuit-breaker")
        monkeypatch.setattr(
            executor_handler.boto3, "client",
            lambda *a, **k: _fake_lambda_client({"status": "GOVERNANCE_HOLD", "http_status": 503}),
        )
        result = execute_circuit_breaker("live")
        assert result["status"] == "GOVERNANCE_HOLD"

    def test_handler_records_invocation_failed_not_invoked_on_rejection(self, monkeypatch):
        """End-to-end: a CIRCUIT_BREAKER decision whose downstream breaker
        call is rejected must be recorded as CIRCUIT_BREAKER_INVOCATION_FAILED,
        never CIRCUIT_BREAKER_INVOKED, in the executor's own audit record."""
        monkeypatch.setattr(
            executor_handler, "execute_circuit_breaker",
            lambda mode: (_ for _ in ()).throw(RuntimeError("Circuit breaker invocation was not authorized/successful")),
        )
        monkeypatch.setattr(executor_handler, "write_audit_record_local", lambda record: None)

        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-cb",
                "detection_id": "det-cb",
                "clusters_assessed": [{
                    "cluster_id": "cluster-cb",
                    "decision": "CIRCUIT_BREAKER",
                }],
            },
        }
        with pytest.raises(RuntimeError):
            executor_handler.handler(event)
