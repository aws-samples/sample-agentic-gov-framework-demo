"""
Test: Circuit Breaker — automated action=="auto_trip" authorization.

The executor agent's automated, service-to-service containment trip must be
authorized through a SEPARATE allow-list (TRUSTED_AUTOMATED_TRIP_PRINCIPAL_
ARNS) and a separate enum (KNOWN_AUTOMATED_TRIP_SOURCES) from the human
action=="invoke" path (verified identity + role capability /
KNOWN_MANUAL_TRIGGER_REASONS). This allow-list authorizes TRIP only; it must
be structurally incapable of authorizing a RELEASE, which now needs a
two-person request/approve on the human entry point regardless
of which allow-list a caller's identity happens to appear on.

IMPORTANT (review follow-up): a real SigV4 lambda:InvokeFunction call — the
only way the executor ever reaches this action — never populates
context.identity; AWS Lambda only forwards caller identity into `context`
for mobile SDK / Amazon Cognito identity pool invokes. The REAL caller shape
for this action therefore has context.identity == None, exactly like
_context_with_no_identity() below. auto_trip's authorization intentionally
does NOT depend on context.identity at all — it is gated only on
TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS being configured (a deploy-time
acknowledgement that the IAM resource policy has been scoped) and
trip_source resolving through the fixed enum. Every positive-authorization
test below uses the REAL no-identity context shape, not a mocked
context.identity.arn that cannot occur in production for this caller.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import circuit_breaker.handler as cb
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import FakeBreakerAws, principal  # noqa: E402

EXECUTOR_ROLE_ARN = "arn:aws:iam::123456789012:role/executor-agent-role"


def _context_with_identity(arn):
    ctx = MagicMock()
    identity = MagicMock()
    identity.arn = arn
    identity.cognito_identity_id = None
    ctx.identity = identity
    ctx.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:fsi-circuit-breaker"
    return ctx


def _context_with_no_identity():
    """The REAL shape of the Lambda context for a plain SigV4
    lambda:InvokeFunction call (e.g. the executor's execute_circuit_breaker)
    — AWS does not forward caller identity into `context` for this call
    shape, so context.identity is None. This is the only context shape
    auto_trip's authorization can ever actually see in production."""
    ctx = MagicMock()
    ctx.identity = None
    ctx.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:fsi-circuit-breaker"
    return ctx


class TestAutoTripAuthorization:
    """The automated-trip path is authorized by the IAM
    resource policy (scoping lambda:InvokeFunction to the executor role)
    plus a deploy-time-acknowledged allow-list and a fixed reason enum —
    NOT by resolving a caller identity that a real SigV4 invoke can never
    carry."""

    def test_live_mode_rejects_with_no_allowlist_configured(self, monkeypatch):
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [])
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        ctx = _context_with_no_identity()
        result = cb.handler(
            {"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"}, ctx
        )
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403

    def test_live_mode_rejects_unknown_trip_source(self, monkeypatch):
        """trip_source must be a known enum value — free-form caller text
        must never reach the audit trail as the reason."""
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [EXECUTOR_ROLE_ARN])
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        ctx = _context_with_no_identity()
        result = cb.handler(
            {"action": "auto_trip", "trip_source": "ATTACKER CONTROLLED FREE TEXT"}, ctx
        )
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 400

    def test_automated_trip_from_executor_role_performs_deny_all_attach(self, monkeypatch):
        """Required test: the automated executor trip is now authorized and
        performs the deny-all attach (observed via invoke_circuit_breaker
        being reached with the correct, enum-resolved reason), using the
        REAL SigV4 caller shape (context.identity is None) — not a mocked
        context.identity.arn that cannot occur in production for this
        caller."""
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [EXECUTOR_ROLE_ARN])
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        captured = {}

        def fake_invoke(reason, mode="local"):
            captured["reason"] = reason
            captured["mode"] = mode
            return {"status": "GOVERNANCE_HOLD", "http_status": 503}

        monkeypatch.setattr(cb, "invoke_circuit_breaker", fake_invoke)
        ctx = _context_with_no_identity()
        result = cb.handler(
            {"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"}, ctx
        )
        assert result["http_status"] == 503
        assert captured["reason"] == cb.KNOWN_AUTOMATED_TRIP_SOURCES["EXECUTOR_CONTAINMENT"]
        assert captured["mode"] == "live"

    def test_automated_trip_also_succeeds_with_no_context_at_all(self, monkeypatch):
        """Required test (real SigV4 caller shape): context itself can be
        None (e.g. local CLI/boto3 invocation shapes used in some test
        harnesses) and auto_trip must still authorize correctly, since it
        never dereferences context for this action."""
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [EXECUTOR_ROLE_ARN])
        monkeypatch.setattr(cb, "_resolve_mode", lambda event: "live")
        monkeypatch.setattr(
            cb, "invoke_circuit_breaker",
            lambda reason, mode="local": {"status": "GOVERNANCE_HOLD", "http_status": 503},
        )
        result = cb.handler(
            {"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"}, None
        )
        assert result["http_status"] == 503

    def test_local_mode_still_works_for_dev_cli_simulation(self):
        """mode="local" is the no-AWS CLI/test simulation path, unauthenticated
        like every other action in this module in local mode."""
        result = cb.handler({
            "action": "auto_trip", "mode": "local", "trip_source": "EXECUTOR_CONTAINMENT",
        })
        assert result["http_status"] == 503
        assert result["trigger_reason"] == cb.KNOWN_AUTOMATED_TRIP_SOURCES["EXECUTOR_CONTAINMENT"]
        if os.path.exists(cb.STATE_FILE):
            os.remove(cb.STATE_FILE)


class TestAutoTripCannotAuthorizeRelease:
    """Required test: a human-only release attempt through the
    automated-trip path is still rejected — proves the automated allow-list
    does not accidentally authorize releases."""

    def test_release_via_re_enable_rejected_even_if_caller_on_auto_trip_allowlist(self, monkeypatch):
        """The executor role (on TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS) can't
        release: re_enable is gone (410) and IAM is never touched."""
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [EXECUTOR_ROLE_ARN])
        aws = FakeBreakerAws().install(monkeypatch, entry="automated")
        aws.record_hold()
        result = cb.handler({"action": "re_enable"}, _context_with_identity(EXECUTOR_ROLE_ARN))
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 410
        assert "detach" not in aws.kinds()

    def test_release_actions_rejected_on_the_automated_entry_point(self, monkeypatch):
        """request_release / approve_release are not served by the function
        the executor can invoke, whatever identity proof is attached."""
        monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", [EXECUTOR_ROLE_ARN])
        aws = FakeBreakerAws().install(monkeypatch, entry="automated")
        aws.record_hold()
        approver = principal("fsi-breaker-approver", "bob")
        for action in ("request_release", "approve_release"):
            result = cb.handler({"action": action,
                                 "release_request_id": "0" * 8 + "-0000-4000-8000-" + "0" * 12,
                                 **aws.proof(approver, action)}, _context_with_no_identity())
            assert result["status"] == "REJECTED" and result["http_status"] == 403
        assert "detach" not in aws.kinds() and aws.verified == []


class TestManualReleasePathStillWorks:
    """Required test: the human release path still works and still requires
    an authorized (approver-capable, distinct) principal."""

    def test_release_succeeds_for_authorized_two_person_flow(self, monkeypatch):
        aws = FakeBreakerAws().install(monkeypatch, entry="human")
        aws.record_hold()
        rid = cb.handler({"action": "request_release",
                          **aws.proof(principal("fsi-breaker-operator", "alice"), "r")})["release_request_id"]
        result = cb.handler({"action": "approve_release", "release_request_id": rid,
                             **aws.proof(principal("fsi-breaker-approver", "bob"), "a")})
        assert result["status"] == "ACTIVE"
        assert len([e for e in aws.log if e[0] == "detach"]) == len(cb.AGENT_ROLES)

    def test_release_rejected_for_unauthorized_principal(self, monkeypatch):
        aws = FakeBreakerAws().install(monkeypatch, entry="human")
        aws.record_hold()
        rid = cb.handler({"action": "request_release",
                          **aws.proof(principal("fsi-breaker-operator", "alice"), "r")})["release_request_id"]
        result = cb.handler({"action": "approve_release", "release_request_id": rid,
                             **aws.proof(principal("random-caller", "x", account="999999999999"), "a")})
        assert result["status"] == "REJECTED"
        assert result["http_status"] == 403
        assert "detach" not in aws.kinds()
