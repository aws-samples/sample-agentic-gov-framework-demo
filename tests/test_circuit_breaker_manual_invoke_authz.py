"""
Test: Circuit Breaker — manual action=="invoke" authorization and
caller-identity resolution.

The direct action=="invoke" dispatch must be gated on an
authorized, verified caller and resolve its reason from a fixed enum.

The breaker must never authorize on a caller-independent value
(context.invoked_function_arn, the literal "UNKNOWN", or a Lambda context
identity a plain SigV4 invoke can't carry). The only identity is a
server-verified STS proof; without one the caller is rejected. Local mode
still simulates.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import circuit_breaker.handler as cb
from _breaker_fixtures import FakeBreakerAws, principal  # noqa: E402

TRUSTED_PRINCIPAL = principal("fsi-breaker-operator", "alice")


def _context_with_identity(arn):
    ctx = MagicMock()
    identity = MagicMock()
    identity.arn = arn
    identity.cognito_identity_id = None
    ctx.identity = identity
    ctx.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:fsi-circuit-breaker-human"
    return ctx


def _context_with_no_identity():
    ctx = MagicMock()
    ctx.identity = None
    ctx.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:fsi-circuit-breaker-human"
    return ctx


@pytest.fixture
def aws(monkeypatch):
    return FakeBreakerAws().install(monkeypatch, entry="human")


class TestNoCallerIndependentIdentity:
    """No caller-independent value is ever treated as the caller."""

    @pytest.mark.parametrize("ctx", [None, _context_with_no_identity(),
                                     _context_with_identity(TRUSTED_PRINCIPAL.arn)])
    def test_no_proof_is_rejected_whatever_the_context(self, aws, ctx):
        result = cb.handler({"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION"}, ctx)
        assert result["status"] == "REJECTED" and result["http_status"] == 403
        assert "attach" not in aws.kinds()

    def test_never_falls_back_to_function_arn_or_unknown(self, aws):
        trips = []
        cb_invoke = cb.invoke_circuit_breaker
        try:
            cb.invoke_circuit_breaker = lambda **k: trips.append(k) or {"status": "GOVERNANCE_HOLD"}
            cb.handler({"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
                        **aws.proof(TRUSTED_PRINCIPAL, "t")}, _context_with_no_identity())
        finally:
            cb.invoke_circuit_breaker = cb_invoke
        assert [t["triggered_by"] for t in trips] == [TRUSTED_PRINCIPAL.arn]
        assert trips[0]["triggered_by"] not in ("UNKNOWN", _context_with_no_identity().invoked_function_arn)


class TestReEnableIsGone:
    def test_handler_re_enable_is_rejected(self, aws):
        """action=="re_enable" can't release anything any more: 410, IAM untouched."""
        result = cb.handler({"action": "re_enable"}, _context_with_identity(TRUSTED_PRINCIPAL.arn))
        assert result["http_status"] == 410
        assert result["status"] == "REJECTED"
        assert "detach" not in aws.kinds()


class TestManualInvokeAuthorization:
    """Manual invoke needs an authorized, verified caller and an enum reason."""

    def test_live_mode_rejects_unverified_proof(self, aws):
        result = cb.handler(
            {"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
             "caller_identity_presigned_url": "https://sts.us-east-1.amazonaws.com/",
             "caller_identity_nonce": "not-issued"}, _context_with_identity(TRUSTED_PRINCIPAL.arn))
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403

    def test_live_mode_rejects_untrusted_principal(self, aws):
        result = cb.handler(
            {"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
             **aws.proof(principal("random-caller", "x", account="999999999999"), "t")},
            _context_with_no_identity())
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403

    def test_live_mode_rejects_unattributed_caller(self, aws):
        """A caller with no verifiable identity is rejected even though
        trip-capable roles exist."""
        result = cb.handler(
            {"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION"}, _context_with_no_identity()
        )
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403

    def test_live_mode_rejects_unknown_reason_code(self, aws):
        """trigger_reason_code must be a known enum value — free-form
        caller text must never reach the audit trail as the reason."""
        result = cb.handler(
            {"action": "invoke", "trigger_reason_code": "ATTACKER CONTROLLED FREE TEXT",
             **aws.proof(TRUSTED_PRINCIPAL, "t")}, _context_with_no_identity()
        )
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 400

    def test_live_mode_accepts_trusted_principal_with_known_reason_code(self, aws, monkeypatch):
        """An authorized principal with a known reason code trips the breaker,
        and the audit reason comes from the enum, never caller text."""
        captured = {}

        def fake_invoke(reason, mode="local", triggered_by=None, **kwargs):
            captured["reason"] = reason
            captured["mode"] = mode
            return {"status": "GOVERNANCE_HOLD", "http_status": 503}

        monkeypatch.setattr(cb, "invoke_circuit_breaker", fake_invoke)
        result = cb.handler(
            {"action": "invoke", "trigger_reason_code": "SUSPECTED_COMPROMISE",
             **aws.proof(TRUSTED_PRINCIPAL, "t")}, _context_with_no_identity()
        )
        assert result["http_status"] == 503
        assert captured["reason"] == cb.KNOWN_MANUAL_TRIGGER_REASONS["SUSPECTED_COMPROMISE"]

    def test_local_mode_still_works_for_dev_cli_simulation(self):
        """mode="local" is the no-AWS CLI/test simulation path used
        throughout this module (get_status, re_enable, invoke_circuit_breaker
        all skip their live-only checks there too) — action=="invoke" in
        local mode must keep working unauthenticated, matching the
        existing test suite's usage (test_circuit_breaker_503.py /
        test_circuit_breaker_audit.py / test_circuit_breaker_fires.py)."""
        result = cb.handler({"action": "invoke", "mode": "local", "trigger_reason": "dev test"})
        assert result["http_status"] == 503
        assert result["trigger_reason"] == "dev test"
        # cleanup the local state file this test wrote
        if os.path.exists(cb.STATE_FILE):
            os.remove(cb.STATE_FILE)
