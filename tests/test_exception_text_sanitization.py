"""
Test: exception text sanitization at the 4 fail-open-logging sites
— lambdas/executor_agent/handler.py's execute_file_sar
(FILING_FAILED) and execute_escalate (ESCALATION_FAILED), and
circuit_breaker/handler.py's invoke_circuit_breaker (attach_failures) and
_perform_release (detach_failures).

Each site previously returned `"error": str(e)` directly to the caller. A
raw AWS exception message can carry a bucket name, queue URL, role ARN, or
other account-specific detail that should only ever reach server-side logs.
Each site must now log server-side with a generated error_id (reusing the
error_id + exc_info=True pattern agentcore/executor_agent/main.py already
established for this control) and return only error_id plus a coarse error
class — never the literal exception text.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.executor_agent.handler as executor_handler
import circuit_breaker.handler as cb

_DISTINCTIVE_BUCKET = "fsi-sar-filings-prod-us-east-1-acct-123456789012"
_DISTINCTIVE_QUEUE = "https://sqs.us-east-1.amazonaws.com/123456789012/fsi-analyst-queue-secret-path"
_DISTINCTIVE_ROLE_ARN = "arn:aws:iam::123456789012:role/executor-agent-role-super-secret-suffix"


def _client_error(message: str, code: str = "AccessDenied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "SomeOperation")


class TestExecuteFileSarErrorSanitization:
    def test_filing_failed_never_returns_raw_exception_text(self, monkeypatch):
        error = _client_error(f"Access denied on bucket {_DISTINCTIVE_BUCKET}")
        fake_s3 = MagicMock()
        fake_s3.put_object.side_effect = error
        monkeypatch.setattr(executor_handler.boto3, "client", lambda *a, **k: fake_s3)
        monkeypatch.setattr(executor_handler, "_account_id", lambda: "123456789012")
        monkeypatch.setattr(executor_handler, "_emit_delivery_failure_metric", lambda name: None)

        result = executor_handler.execute_file_sar({"cluster_id": "c1", "sar_narrative": "x"}, "live")

        assert result["status"] == "FILING_FAILED"
        assert "error" not in result
        assert _DISTINCTIVE_BUCKET not in str(result)
        assert "error_id" in result
        assert "error_class" in result
        assert result["error_class"] == "AccessDenied"

    def test_filing_failed_logs_real_exception_server_side(self, monkeypatch, caplog):
        import logging
        error = _client_error(f"Access denied on bucket {_DISTINCTIVE_BUCKET}")
        fake_s3 = MagicMock()
        fake_s3.put_object.side_effect = error
        monkeypatch.setattr(executor_handler.boto3, "client", lambda *a, **k: fake_s3)
        monkeypatch.setattr(executor_handler, "_account_id", lambda: "123456789012")
        monkeypatch.setattr(executor_handler, "_emit_delivery_failure_metric", lambda name: None)

        with caplog.at_level(logging.ERROR):
            result = executor_handler.execute_file_sar({"cluster_id": "c1", "sar_narrative": "x"}, "live")

        assert any(_DISTINCTIVE_BUCKET in record.getMessage() or _DISTINCTIVE_BUCKET in str(record.args)
                   for record in caplog.records)
        assert any(result["error_id"] in record.getMessage() for record in caplog.records)


class TestExecuteEscalateErrorSanitization:
    def test_escalation_failed_never_returns_raw_exception_text(self, monkeypatch):
        error = _client_error(f"Queue not found: {_DISTINCTIVE_QUEUE}", code="ResourceNotFoundException")
        fake_sqs = MagicMock()
        fake_sqs.send_message.side_effect = error
        monkeypatch.setattr(executor_handler.boto3, "client", lambda *a, **k: fake_sqs)
        monkeypatch.setattr(executor_handler, "_emit_delivery_failure_metric", lambda name: None)
        monkeypatch.setattr(executor_handler, "ANALYST_QUEUE_URL", _DISTINCTIVE_QUEUE)

        result = executor_handler.execute_escalate({"cluster_id": "c1"}, "live")

        assert result["status"] == "ESCALATION_FAILED"
        assert "error" not in result
        assert _DISTINCTIVE_QUEUE not in str(result)
        assert "error_id" in result
        assert result["error_class"] == "ResourceNotFound"

    def test_escalation_failed_logs_real_exception_server_side(self, monkeypatch, caplog):
        import logging
        error = _client_error(f"Queue not found: {_DISTINCTIVE_QUEUE}", code="ResourceNotFoundException")
        fake_sqs = MagicMock()
        fake_sqs.send_message.side_effect = error
        monkeypatch.setattr(executor_handler.boto3, "client", lambda *a, **k: fake_sqs)
        monkeypatch.setattr(executor_handler, "_emit_delivery_failure_metric", lambda name: None)
        monkeypatch.setattr(executor_handler, "ANALYST_QUEUE_URL", _DISTINCTIVE_QUEUE)

        with caplog.at_level(logging.ERROR):
            result = executor_handler.execute_escalate({"cluster_id": "c1"}, "live")

        assert any(_DISTINCTIVE_QUEUE in record.getMessage() or _DISTINCTIVE_QUEUE in str(record.args)
                   for record in caplog.records)
        assert any(result["error_id"] in record.getMessage() for record in caplog.records)


class TestCircuitBreakerAttachFailuresErrorSanitization:
    def test_attach_failures_never_contains_raw_exception_text(self, monkeypatch):
        error = _client_error(f"Cannot attach policy to {_DISTINCTIVE_ROLE_ARN}")
        fake_iam = MagicMock()
        fake_iam.attach_role_policy.side_effect = error
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        monkeypatch.setattr(cb, "get_status", lambda mode: {"status": "ACTIVE"})
        monkeypatch.setattr(cb, "write_governance_hold_event", lambda *a, **k: None)
        # post-trip reconcile audit and state claim: never a real table
        monkeypatch.setattr(cb, "_governance_table", lambda: MagicMock())
        monkeypatch.setattr(cb, "_state_table", lambda: MagicMock())

        with pytest.raises(cb.GovernanceHoldEnforcementError) as exc_info:
            cb.invoke_circuit_breaker(reason="test", mode="live")

        attach_failures = exc_info.value.attach_failures
        assert attach_failures  # at least one role failed
        for role, failure in attach_failures.items():
            assert _DISTINCTIVE_ROLE_ARN not in str(failure)
            assert "error_id" in failure
            assert "error_class" in failure
            assert failure["error_class"] == "AccessDenied"

    def test_attach_failures_logs_real_exception_server_side(self, monkeypatch, caplog):
        import logging
        error = _client_error(f"Cannot attach policy to {_DISTINCTIVE_ROLE_ARN}")
        fake_iam = MagicMock()
        fake_iam.attach_role_policy.side_effect = error
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        monkeypatch.setattr(cb, "get_status", lambda mode: {"status": "ACTIVE"})
        monkeypatch.setattr(cb, "write_governance_hold_event", lambda *a, **k: None)
        # post-trip reconcile audit and state claim: never a real table
        monkeypatch.setattr(cb, "_governance_table", lambda: MagicMock())
        monkeypatch.setattr(cb, "_state_table", lambda: MagicMock())

        with caplog.at_level(logging.ERROR):
            with pytest.raises(cb.GovernanceHoldEnforcementError):
                cb.invoke_circuit_breaker(reason="test", mode="live")

        assert any(_DISTINCTIVE_ROLE_ARN in record.getMessage() or _DISTINCTIVE_ROLE_ARN in str(record.args)
                   for record in caplog.records)


# The live detach now runs only in _perform_release, after an approved
# two-person release; re_enable(mode="live") no longer exists.
_APPROVAL = {"release_request_id": "r-1", "hold_event_id": "evt-1", "hold_generation": 1,
             "requested_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-operator/alice",
             "approved_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-approver/bob"}


def _released_state(monkeypatch):
    """The approved generation is claimed and stays current after the detach."""
    monkeypatch.setattr(cb, "_state_table", lambda: MagicMock())
    monkeypatch.setattr(cb, "_governance_table", lambda: MagicMock())
    monkeypatch.setattr(cb.governance_state, "claim_release", lambda *a, **k: "CLAIMED")
    monkeypatch.setattr(cb.governance_state, "read", lambda table: {
        "generation": 1, "status": "RELEASED", "hold_event_id": "evt-1", "release_request_id": "r-1"})
    monkeypatch.setattr(cb.hold_sweep, "unclaimed_hold", lambda table, state: None)


class TestCircuitBreakerDetachFailuresErrorSanitization:
    def test_detach_failures_never_contains_raw_exception_text(self, monkeypatch):
        error = _client_error(f"Cannot detach policy from {_DISTINCTIVE_ROLE_ARN}")
        fake_iam = MagicMock()
        fake_iam.detach_role_policy.side_effect = error
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        monkeypatch.setattr(cb, "write_governance_release_event", lambda *a, **k: True)
        monkeypatch.setattr(cb, "write_release_completed_event", lambda *a, **k: True)
        _released_state(monkeypatch)
        monkeypatch.setattr(cb, "get_status", lambda mode: {"status": "GOVERNANCE_HOLD", "event_id": "evt-1"})

        result = cb._perform_release(_APPROVAL)

        assert result["status"] == "GOVERNANCE_HOLD"
        detach_failures = result["detach_failures"]
        assert detach_failures
        for role, failure in detach_failures.items():
            assert _DISTINCTIVE_ROLE_ARN not in str(failure)
            assert "error_id" in failure
            assert "error_class" in failure
            assert failure["error_class"] == "AccessDenied"

    def test_detach_failures_logs_real_exception_server_side(self, monkeypatch, caplog):
        import logging
        error = _client_error(f"Cannot detach policy from {_DISTINCTIVE_ROLE_ARN}")
        fake_iam = MagicMock()
        fake_iam.detach_role_policy.side_effect = error
        monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: fake_iam)
        monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: "arn:aws:iam::123456789012:policy/governance-hold-deny-all")
        monkeypatch.setattr(cb, "write_governance_release_event", lambda *a, **k: True)
        monkeypatch.setattr(cb, "write_release_completed_event", lambda *a, **k: True)
        _released_state(monkeypatch)
        monkeypatch.setattr(cb, "get_status", lambda mode: {"status": "GOVERNANCE_HOLD", "event_id": "evt-1"})

        with caplog.at_level(logging.ERROR):
            cb._perform_release(_APPROVAL)

        assert any(_DISTINCTIVE_ROLE_ARN in record.getMessage() or _DISTINCTIVE_ROLE_ARN in str(record.args)
                   for record in caplog.records)
