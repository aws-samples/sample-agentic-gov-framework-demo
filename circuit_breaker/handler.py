"""
Circuit Breaker — Automated Agent Disable.

============================================================================
BLUEPRINT 4 — DRIFT CONTROL (the circuit breaker itself)
============================================================================
The enforcement end of drift control. When a CloudWatch drift alarm fires
(dispute rate, guardrail rate, or volume breach), this handler is invoked
automatically and puts all three agents into GOVERNANCE_HOLD by attaching an
explicit deny-all IAM policy. Trigger is automated; re-enable is manual
(asymmetric safety). Every hold is written to the governance audit trail.
============================================================================

Triggered by CloudWatch alarm when drift metrics exceed thresholds.
When invoked:
1. Revokes all three agent IAM roles (attaches explicit deny policy)
2. Writes GOVERNANCE_HOLD event to audit trail
3. Returns 503 Governance Hold for subsequent requests

Release is a two-person, server-verified action: one verified
individual requests it (request_release), a DIFFERENT verified individual on
the same identity channel approves it (approve_release), and only while the
request still refers to the current hold. Identity comes from a presigned
sts:GetCallerIdentity proof with a single-use nonce (identity_proof.py);
authorization is IAM role membership bound by RoleId and path (authz.py).

The same asset is deployed three times (BREAKER_ENTRY): fsi-circuit-breaker
serves the automated paths (alarm events, auto_trip, check, recheck_alarms,
status) and no human role can invoke it; fsi-circuit-breaker-human serves the
human paths (invoke, request_release, approve_release, status);
fsi-governance-hold-sweep (BREAKER_ENTRY=sweep, its own attach-only role)
serves only reconcile_hold, which re-attaches the deny-all to any agent role
missing it while the hold is active and never detaches.

Drift thresholds (configurable):
- Challenger dispute rate > 51% over 1-hour window
- Guardrail intervention rate > 10% over 1-hour window
- Detection volume anomaly > 3x baseline
"""
import json
import logging
import os
import re
import sys
import uuid
import argparse
import boto3
import ssl
import time
import urllib.request
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from botocore.exceptions import BotoCoreError, ClientError

# Same top-level module names in the Lambda asset (/var/task, no package) and
# in tests/clients that import circuit_breaker.handler from the repo root.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import identity_proof  # noqa: E402
import authz  # noqa: E402
import hold_sweep  # noqa: E402
import governance_state  # noqa: E402

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
REGION = os.environ.get("AWS_REGION", "us-east-1")
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".circuit_breaker_state.json")
# Local-simulation pending release request (kept separate from STATE_FILE so a
# local re-trip does not erase it and the approval can detect a stale request).
RELEASE_REQUEST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    ".circuit_breaker_release_request.json")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "governance-audit")
STATE_TABLE = os.environ.get("GOVERNANCE_STATE_TABLE", "governance-state")
COMPLIANCE_TABLE = os.environ.get("COMPLIANCE_TABLE", "compliance-decisions")
RETENTION_EXPIRES = "2033-08-17T00:00:00Z"
RELEASE_REQUEST_TTL_SECONDS = 900
RELEASE_REQUEST_ID_RE = re.compile(r"^[0-9a-f-]{36}$")
GOVERNANCE_INTEGRITY_NAMESPACE = "FSI/GovernanceIntegrity"

# Deploy-time entry point (set per deployed function).
ENTRY_AUTOMATED = "automated"
ENTRY_HUMAN = "human"
ENTRY_SWEEP = "sweep"
SWEEP_ACTION = "reconcile_hold"
# Emitted once per completed scheduled sweep (liveness, not a finding).
HOLD_SWEEP_HEARTBEAT_METRIC = "HoldSweepHeartbeat"
AUTOMATED_ONLY_ACTIONS = frozenset({"auto_trip", "check", "recheck_alarms"})
HUMAN_ONLY_ACTIONS = frozenset({"invoke", "request_release", "approve_release"})
WRONG_ENTRY_MESSAGE = "action not available on this entry point"

# Agent IAM roles to revoke
AGENT_ROLES = [
    os.environ.get("DETECTION_ROLE", "detection-agent-role"),
    os.environ.get("COMPLIANCE_ROLE", "compliance-agent-role"),
    os.environ.get("EXECUTOR_ROLE", "executor-agent-role"),
]

# Well-known name of the governance-hold policy created in cdk/agents_stack.py.
DENY_POLICY_NAME = "governance-hold-deny-all"

_resolved_deny_policy_arn = None  # lazily resolved — see resolve_deny_policy_arn()


def resolve_deny_policy_arn() -> str:
    """
    Resolve the deny-all policy ARN from the account id at runtime and
    assert it matches the well-known governance-hold policy name, rather
    than trusting DENY_POLICY_ARN from the environment unchecked
    — the circuit breaker's own IAM grant is now pinned (via iam:PolicyARN)
    to exactly this policy, so attaching a different ARN would fail anyway,
    but this keeps a misconfigured/tampered environment variable from ever
    being used in the first place.

    Resolved lazily (only when a live-mode IAM call is about to happen) and
    cached, so importing this module or running in local mode never makes an
    STS call.
    """
    global _resolved_deny_policy_arn
    if _resolved_deny_policy_arn is not None:
        return _resolved_deny_policy_arn

    account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    expected = f"arn:aws:iam::{account_id}:policy/{DENY_POLICY_NAME}"

    configured = os.environ.get("DENY_POLICY_ARN")
    if configured and configured != expected:
        logger.error(
            "DENY_POLICY_ARN env var (%s) does not match the expected governance-hold "
            "policy ARN (%s) for this account — ignoring the env var and using the "
            "well-known ARN.",
            configured, expected,
        )
    _resolved_deny_policy_arn = expected
    return expected

# BLUEPRINT 4 — DRIFT CONTROL: a manual trip (action=="invoke") is served
# only by fsi-circuit-breaker-human and needs a verified identity whose role
# carries the "trip" capability (authz.py), never an env allow-list.

# Fixed enum of manual-invoke trigger reasons. trigger_reason
# for action=="invoke" is resolved from this table keyed on a reason CODE
# the caller supplies, never from caller-supplied free text — mirroring how
# handle_alarm_event resolves its reason from KNOWN_ALARM_REASONS rather
# than from the alarm payload's own state_reason field.
KNOWN_MANUAL_TRIGGER_REASONS = {
    "SUSPECTED_COMPROMISE": "Manual break-glass trip: suspected credential or model compromise",
    "DATA_INTEGRITY_CONCERN": "Manual break-glass trip: data integrity concern in agent pipeline",
    "OPERATOR_PRECAUTION": "Manual break-glass trip: operator precautionary hold",
}

# BLUEPRINT 4 — DRIFT CONTROL: automated-trip authorization.
#
# TRIP and RELEASE are two different operations with two different risk
# profiles, and must never share an allow-list or a dispatch path:
#   - TRIP (this allow-list, plus TRUSTED_ALARM_ARNS above) only ever calls
#     invoke_circuit_breaker — it can make the system MORE restrictive. It
#     is authorized by a known, IAM-scoped SERVICE principal (no human
#     attribution required), mirroring how TRUSTED_ALARM_ARNS backstops the
#     CloudWatch alarm's own lambda:InvokeFunction grant.
#   - RELEASE (request_release + approve_release) can make the system LESS
#     restrictive. It is served only by fsi-circuit-breaker-human, needs two
#     distinct STS-verified individuals, and is never reachable from this
#     action: "auto_trip" only ever calls invoke_circuit_breaker.
#
# This allow-list is for a known automated SERVICE caller (the executor-agent
# role) whose IAM grant already scopes it to exactly fsi-circuit-breaker
# (cdk/agents_stack.py). Populated by cdk/agents_stack.py as a
# comma-separated list of the automated-trip principal ARN(s).
#
# IMPORTANT — this list is NOT checked against a resolved caller identity
# for action=="auto_trip" (see _handle_auto_trip's docstring): AWS Lambda
# does not forward SigV4 caller identity into `context` for an ordinary
# lambda:InvokeFunction call, which is how the executor invokes this
# function, so context.identity is always empty for that caller and any
# code-side identity check against it would always reject. This list's
# only remaining job for auto_trip is to require a non-empty value as a
# deploy-time acknowledgement that the IAM resource policy has in fact
# been scoped to the intended automated caller — the ARN values
# themselves are not individually matched against anything at runtime for
# this action.
TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS = [
    a.strip() for a in os.environ.get("TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS", "").split(",") if a.strip()
]

# Fixed enum of automated-trip sources (mirrors KNOWN_MANUAL_TRIGGER_REASONS
# for the human path). trip_source for action=="auto_trip" is resolved from
# this table keyed on a caller-supplied CODE, never from caller-supplied
# free text.
KNOWN_AUTOMATED_TRIP_SOURCES = {
    "EXECUTOR_CONTAINMENT": "Automated containment trip: executor agent routed a CIRCUIT_BREAKER decision",
}

# BLUEPRINT 4 — DRIFT CONTROL: the CloudWatch alarm ARNs that are the ONLY
# trusted automatic triggers for the circuit breaker. An alarm-shaped event
# whose alarmArn is not on this allow-list is rejected rather than trusted by
# payload shape. Populated by cdk/agents_stack.py as a
# comma-separated list of the dispute/guardrail/volume/sustained-dispute
# alarm ARNs.
TRUSTED_ALARM_ARNS = [
    a.strip() for a in os.environ.get("TRUSTED_ALARM_ARNS", "").split(",") if a.strip()
]

# Map of the known alarm NAMES to their human-readable trigger reason. The
# reason is always resolved from the verified alarm, never from caller text.
# Values must stay distinct: the hold event's trigger_source is derived from
# the resolved reason (_derive_trigger_source).
KNOWN_ALARM_REASONS = {
    "fsi-challenger-dispute-rate-breach": "CloudWatch Alarm: Challenger dispute rate exceeded 51% threshold",
    "fsi-guardrail-intervention-rate-breach": "CloudWatch Alarm: Guardrail intervention rate exceeded 10% threshold",
    "fsi-detection-volume-anomaly": "CloudWatch Alarm: Detection volume spike exceeded 3x baseline",
    "fsi-challenger-dispute-rate-sustained": (
        "CloudWatch Alarm: Challenger dispute rate exceeded 51% over 1 hour "
        "(low-volume sustained drift)"),
}

# Corroboration of alarms from durable, VERIFIED compliance records.
# An alarm the stored records don't corroborate
# never attaches deny-all: it is recorded as ALARM_UNCORROBORATED and alerts.
# Must equal MIN_CLUSTERS_FOR_ALARM_RATE (cdk/agents_stack.py) and
# MIN_CLUSTERS_FOR_RATE (lambdas/drift_metric_publisher/handler.py).
MIN_CLUSTERS_FOR_CORROBORATION = 20
CORROBORATION_SLACK_MINUTES = 3
CORROBORATION_BASELINE_MINUTES = 60
CORROBORATION_DEADLINE_SECONDS = 10
CORROBORATION_RETRY_MIN_BUDGET_SECONDS = 4
CORROBORATION_RETRY_SLEEP_SECONDS = 3
SHAPING_MIN_RECORDS = 10
SHAPING_INVOCATION_RATIO = Decimal("3.0")
VOLUME_MULTIPLIER = Decimal("3.0")

# Per-alarm table: stored drift_counts numerator (None for volume), the
# alarm threshold and the alarm window in minutes. The window drives the
# recent window, recent_start = now - (window + slack).
CorroborationRule = namedtuple("CorroborationRule", "numerator threshold window_minutes")
CORROBORATION_RULES = {
    "fsi-challenger-dispute-rate-breach": CorroborationRule("disputes", Decimal("0.51"), 5),
    "fsi-guardrail-intervention-rate-breach": CorroborationRule("guardrail_hits", Decimal("0.10"), 5),
    "fsi-detection-volume-anomaly": CorroborationRule(None, VOLUME_MULTIPLIER, 5),
    "fsi-challenger-dispute-rate-sustained": CorroborationRule("disputes", Decimal("0.51"), 60),
}
# The per-minute alarms fire when ALARM_DATAPOINTS_TO_ALARM of
# ALARM_EVALUATION_PERIODS one-minute periods each have >= 20 clusters and a
# rate over threshold (pinned to the synthesized alarms by a CDK test).
PER_MINUTE_ALARMS = {
    "fsi-challenger-dispute-rate-breach": ("disputes", Decimal("0.51")),
    "fsi-guardrail-intervention-rate-breach": ("guardrail_hits", Decimal("0.10")),
}
ALARM_EVALUATION_PERIODS = 3
ALARM_DATAPOINTS_TO_ALARM = 2

# Time budget within the breaker Lambda timeout (cdk/agents_stack.py
# BREAKER_TIMEOUT_SECONDS): a 10 s corroboration or a 12 s recheck pre-trip
# phase, plus a trip path of at most TRIP_PATH_BUDGET_MS (about 15 s of IAM
# and audit calls plus at most 6.2 s of governance-state claims), plus
# POST_TRIP_MARGIN_MS, must fit in the timeout.
BREAKER_TIMEOUT_SECONDS = 45
TRIP_PATH_BUDGET_MS = 21500
POST_TRIP_MARGIN_MS = 5000
# Pause before the one retry of a failed governance-state claim.
CLAIM_RETRY_SLEEP_SECONDS = 0.2

# recheck_alarms budget (scheduled every 2 minutes).
RECHECK_PRETRIP_BUDGET_SECONDS = 12
RECHECK_MIN_TRIP_HEADROOM_MS = TRIP_PATH_BUDGET_MS
RECHECK_IN_FLIGHT_SECONDS = 60

# Identical to lambdas/drift_metric_publisher/handler.py (parity test).
DRIFT_COUNT_KEYS = ("clusters", "disputes", "guardrail_hits", "challenger_failures", "output_rejections")
MAX_DRIFT_COUNT = 10000
CORROBORATION_MAX_ITEMS = 1000
CORROBORATION_ATTRIBUTES = ("compliance_id", "record_day", "timestamp", "drift_counts",
                            "provenance_status")

# BLUEPRINT 4 — DRIFT CONTROL: the drift thresholds that define "too far off."
# These mirror the CloudWatch alarm thresholds in agents_stack.py and are used
# by check_thresholds() when the circuit breaker is invoked directly with metrics.
THRESHOLDS = {
    "challenger_dispute_rate": float(os.environ.get("THRESHOLD_DISPUTE_RATE", "0.51")),
    "guardrail_intervention_rate": float(os.environ.get("THRESHOLD_GUARDRAIL_RATE", "0.10")),
    "detection_volume_multiplier": float(os.environ.get("THRESHOLD_VOLUME_MULTIPLIER", "3.0")),
}


class GovernanceHoldEnforcementError(RuntimeError):
    """Raised when the circuit breaker could not confirm the deny-all policy
    is attached to every agent role. The trip must fail loudly rather than
    report a hold that is not actually enforced."""

    def __init__(self, message, confirmed_roles=None, unconfirmed_roles=None, attach_failures=None):
        super().__init__(message)
        self.confirmed_roles = confirmed_roles or []
        self.unconfirmed_roles = unconfirmed_roles or []
        self.attach_failures = attach_failures or {}


class GovernanceAuditWriteError(RuntimeError):
    """Raised when a governance-audit write fails. A hold (or release) must
    never occur without a durable audit record."""


class GovernanceStateWriteError(GovernanceAuditWriteError):
    """Raised (after the hold is verified) when a trip could not claim the
    governance-state item on either attempt. The hold is enforced; the sweep
    treats the unclaimed trip as the active hold until a re-trip claims it."""


def _classify_aws_error(e: Exception) -> str:
    """
    Coarse, non-sensitive error class for a failed IAM call —
    one of "AccessDenied", "Throttling", "ResourceNotFound", or "Unknown".
    Used instead of returning str(e) in the attach_failures/detach_failures
    maps: a raw exception message can carry role/policy ARNs or other
    account-specific detail that should only ever reach server-side logs,
    never an audit record or API response a caller receives.
    """
    code = ""
    response = getattr(e, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code", "")
    if code in ("AccessDenied", "AccessDeniedException"):
        return "AccessDenied"
    if code in ("Throttling", "ThrottlingException"):
        return "Throttling"
    if code == "ResourceNotFoundException":
        return "ResourceNotFound"
    return "Unknown"


def _resolve_mode(event: dict) -> str:
    """
    Resolve the execution mode for a direct invocation.

    In the DEPLOYED Lambda, 'local' simulated mode must never be reachable:
    STATE_FILE lives under the read-only /var/task, so
    get_status/re_enable's local branches silently report a false ACTIVE/
    success reading of the system's only containment control, and
    invoke_circuit_breaker's local branch fails outright. Detect the
    deployed runtime via AWS_LAMBDA_FUNCTION_NAME (set by the Lambda service
    itself, not by the caller) and force mode="live" there regardless of
    what the caller's event asks for — a deployed function must not accept
    a simulated state store. Only outside Lambda (CLI / tests) does the
    caller-supplied (or default-local) mode apply.
    """
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "live"
    return event.get("mode", "local")


def _breaker_entry() -> str:
    """BREAKER_ENTRY, read at call time. Anything other than human/sweep
    (including unset) is treated as automated."""
    value = os.environ.get("BREAKER_ENTRY", ENTRY_AUTOMATED)
    return value if value in (ENTRY_HUMAN, ENTRY_SWEEP) else ENTRY_AUTOMATED


def _rejected(http_status: int, message: str, code: str = None) -> dict:
    result = {"status": "REJECTED", "http_status": http_status, "message": message}
    if code:
        result["code"] = code
    return result


def handler(event: dict, context=None) -> dict:
    """
    Lambda handler for circuit breaker.

    Args:
        event: Lambda event — either:
            - CloudWatch Alarm event (automatic trigger): contains 'alarmData' with alarm details
            - Direct invocation: action (check|auto_trip|status on fsi-circuit-breaker;
              invoke|request_release|approve_release|status on fsi-circuit-breaker-human), mode, ...
        context: Lambda context object (None in local mode). Never used for
            authorization: plain SigV4 invokes carry no caller identity in it.

    Returns:
        Circuit breaker result dict.
    """
    alarm_shaped = "alarmData" in event or "source" in event
    action = event.get("action", "check")
    mode = _resolve_mode(event)

    # The sweep entry serves exactly one action, in every mode.
    if _breaker_entry() == ENTRY_SWEEP:
        if alarm_shaped or action != SWEEP_ACTION:
            logger.warning("Refusing %s on the sweep entry point", "alarm event" if alarm_shaped else action)
            return _rejected(403, WRONG_ENTRY_MESSAGE)
        if mode == "local":
            return {"status": "NO_HOLD"}
        return _handle_reconcile_hold()
    if action == SWEEP_ACTION:
        if mode == "local":
            return {"status": "NO_HOLD"}
        logger.warning("Refusing %s outside the sweep entry point", action)
        return _rejected(403, WRONG_ENTRY_MESSAGE)

    if not alarm_shaped and action == "re_enable":
        return _rejected(410, "re_enable is replaced by request_release + approve_release")

    # Entry-point split. The alarm path always acts live, so it
    # is checked regardless of the event's mode; in local mode (a no-AWS
    # simulation never reachable in Lambda) every other action stays available.
    entry = _breaker_entry()
    if alarm_shaped or mode != "local":
        wrong = (
            (entry == ENTRY_HUMAN and (alarm_shaped or action in AUTOMATED_ONLY_ACTIONS))
            or (entry == ENTRY_AUTOMATED and not alarm_shaped and action in HUMAN_ONLY_ACTIONS)
        )
        if wrong:
            logger.warning("Refusing %s on the %s entry point",
                           "alarm event" if alarm_shaped else action, entry)
            return _rejected(403, WRONG_ENTRY_MESSAGE)

    if alarm_shaped:
        return handle_alarm_event(event)

    if action == "status":
        return get_status(mode)
    elif action == "invoke":
        return _handle_manual_invoke(event, mode)
    elif action == "auto_trip":
        return _handle_auto_trip(event, context, mode)
    elif action == "request_release":
        if mode == "local":
            return request_release_local(event.get("principal_id"))
        return _handle_request_release(event)
    elif action == "approve_release":
        if mode == "local":
            return approve_release_local(event.get("release_request_id"), event.get("principal_id"))
        return _handle_approve_release(event)
    elif action == "check":
        return check_thresholds(event.get("metrics", {}), mode)
    elif action == "recheck_alarms":
        # No caller check, like "check": the scheduled EventBridge invoke
        # carries no identity, every event field other than action is
        # ignored, and it can only cause a trip the stored records
        # corroborate (attach-only).
        if mode == "local":
            return {"status": "NO_ALARMS"}
        return recheck_alarms(context=context)
    else:
        # Unknown/unrecognized action — never falls through to check_thresholds
        # or any trip path: an unrecognized action string must
        # not be silently treated as evaluation-only or as a trip request.
        return {"error": f"Unknown action: {action}"}


def _handle_reconcile_hold() -> dict:
    """fsi-governance-hold-sweep: attach-only reconcile of the deny-all.
    An audit-write failure re-raises as GovernanceAuditWriteError
    (async retry, then the DLQ)."""
    try:
        result = hold_sweep.reconcile_hold(
            boto3.client("iam", region_name=REGION), _governance_table(),
            roles=AGENT_ROLES, deny_policy_arn=resolve_deny_policy_arn(), trigger="schedule",
            emit_metric=_emit_integrity_metric,
            read_state=lambda: governance_state.read(_state_table()))
    except hold_sweep.HoldReconcileAuditError as e:
        raise GovernanceAuditWriteError(str(e)) from e
    # Liveness: one datapoint per completed sweep. fsi-hold-sweep-not-running
    # alarms when it is absent (rule disabled, function failing, or the
    # sweep erroring) for three sweep periods.
    if result.get("status") != "ERROR":
        _emit_integrity_metric(HOLD_SWEEP_HEARTBEAT_METRIC, 1)
    return result


def _sts_https_opener() -> urllib.request.OpenerDirector:
    """HTTPS-only, no-redirect opener for the presigned STS fetch.

    Built by hand rather than with urllib.request.build_opener(), because
    build_opener() always installs the default HTTP, FTP, file:, data:,
    proxy and redirect handlers. Only the four handlers below are present,
    so a file://, http://, ftp:// or data: URL raises URLError (via
    UnknownHandler) and any 3xx response raises HTTPError (there is no
    HTTPRedirectHandler) — a redirect can never carry the signed request
    off the allowlisted STS host. No ProxyHandler: the Lambda has no proxy
    environment configured.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        urllib.request.HTTPDefaultErrorHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.UnknownHandler(),
    ):
        opener.add_handler(handler)
    return opener


def _governance_table():
    return boto3.resource("dynamodb", region_name=REGION).Table(AUDIT_TABLE)


def _state_table():
    """The governance-state table on a single-attempt client (each call
    <= 3 s), so every state call stays inside the breaker's time budget."""
    return boto3.resource("dynamodb", region_name=REGION,
                          config=_corroboration_client_config()).Table(STATE_TABLE)


_own_account = None


def _own_account_id() -> str:
    """The breaker's own account id (cached; one STS call per container)."""
    global _own_account
    if _own_account is None:
        _own_account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    return _own_account


def _verify_caller(event: dict, action: str, target: str, capability: str):
    """Verify the caller's identity proof and capability.

    Returns (principal, authorization, None) or (None, None, rejection).
    identity_proof and authz are referenced as module attributes so tests
    can monkeypatch handler.identity_proof.verify_identity / handler.authz.classify.
    """
    principal = identity_proof.verify_identity(
        event.get("caller_identity_presigned_url"),
        event.get("caller_identity_nonce"),
        action, target,
        region=REGION,
        nonce_table_factory=_governance_table,
        opener_factory=_sts_https_opener,
    )
    if principal is None:
        return None, None, _rejected(403, "caller identity could not be verified")
    try:
        account_id = _own_account_id()
        authorization = authz.classify(principal, account_id, boto3.client("iam", region_name=REGION))
    except Exception as e:  # noqa: BLE001 - fail closed
        error_id = str(uuid.uuid4())
        logger.error("Breaker authz lookup failed [%s] (%s)", error_id, type(e).__name__)
        authorization = None
    if authorization is None or capability not in authorization.capabilities:
        logger.warning("Refusing %s: principal %s lacks the %s capability",
                       action, principal.arn, capability)
        return None, None, _rejected(403, f"caller is not authorized to {capability.replace('_', ' ')}")
    return principal, authorization, None


def _handle_manual_invoke(event: dict, mode: str) -> dict:
    """
    Handle a direct action=="invoke" (manual trip) request,
    served only by fsi-circuit-breaker-human in live mode.

    Authorization (live mode only; mode="local" is the no-AWS CLI/test
    simulation that _resolve_mode() makes unreachable inside Lambda):
      1. A verified identity proof bound to action "trip" / target "trip",
         single-use (identity_proof.verify_identity).
      2. The caller's role carries the "trip" capability (authz.classify).
      3. trigger_reason is a CODE looked up in KNOWN_MANUAL_TRIGGER_REASONS,
         never caller-supplied prose.
    No second approver: a trip only makes the system more restrictive.
    """
    if mode == "local":
        return invoke_circuit_breaker(
            reason=event.get("trigger_reason", "Manual invocation (local)"),
            mode=mode,
        )

    principal, _authz, rejection = _verify_caller(event, "trip", "trip", authz.TRIP)
    if rejection:
        return rejection

    reason_code = event.get("trigger_reason_code")
    reason = KNOWN_MANUAL_TRIGGER_REASONS.get(reason_code) if isinstance(reason_code, str) else None
    if reason is None:
        logger.error(
            "Refusing manual invoke: trigger_reason_code is not a known reason "
            "code — refusing to fabricate a free-text justification."
        )
        return _rejected(400, (
            "Manual invoke denied: trigger_reason_code must be one of "
            + ", ".join(sorted(KNOWN_MANUAL_TRIGGER_REASONS))
        ))

    logger.info("Circuit breaker manually invoked by verified principal: %s", principal.arn)
    return invoke_circuit_breaker(reason=reason, mode=mode, triggered_by=principal.arn,
                                  trigger_source=f"MANUAL:{reason_code}")


def _handle_auto_trip(event: dict, context, mode: str) -> dict:
    """
    Handle a direct action=="auto_trip" request — the
    automated, service-to-service containment trip path (currently used by
    the executor agent's own CIRCUIT_BREAKER routing decision,
    lambdas/executor_agent/handler.py:execute_circuit_breaker). Served only
    by fsi-circuit-breaker (BREAKER_ENTRY=automated); no human role can
    invoke that function.

    This is DELIBERATELY NOT the same dispatch branch as action=="invoke"
    (_handle_manual_invoke, a HUMAN with a verified identity and the "trip"
    capability). This path is for a known automated SERVICE principal and
    is gated on TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS with its own enum,
    KNOWN_AUTOMATED_TRIP_SOURCES.

    The real-world authorization boundary for this action IS the IAM
    policy scoping lambda:InvokeFunction on fsi-circuit-breaker to exactly
    the executor-agent role (cdk/agents_stack.py) — not a code-side
    identity check. A plain SigV4 lambda:InvokeFunction call (how
    execute_circuit_breaker() invokes this function) carries no caller
    identity into `context`, and there is no identity-forwarding mechanism
    in front of this Lambda, so this path does NOT attempt caller-identity
    resolution. Authorization has two layers, mirroring handle_alarm_event:
      1. IAM scopes lambda:InvokeFunction on this function to the executor
         role (plus the alarm actions' resource policy).
      2. TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS must be configured
         (non-empty) as the deploy-time acknowledgement that layer 1's IAM
         grant has in fact been scoped that way, and trip_source must
         resolve through the fixed KNOWN_AUTOMATED_TRIP_SOURCES enum rather
         than caller-supplied free text — both fail closed if unmet.

    This action is structurally incapable of releasing a hold: it only
    ever calls invoke_circuit_breaker. Release lives on the human entry
    point and needs two distinct verified individuals.
    """
    if mode == "local":
        return invoke_circuit_breaker(
            reason=KNOWN_AUTOMATED_TRIP_SOURCES.get(
                event.get("trip_source"), "Automated trip (local)"
            ),
            mode=mode,
        )

    if not TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS:
        logger.error(
            "Refusing auto_trip: TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS is not "
            "configured, so the IAM-scoped automated caller has not been "
            "deploy-time acknowledged. Rejecting the event."
        )
        return {
            "status": "REJECTED",
            "message": "Automated trip denied: no automated-trip allow-list configured.",
            "http_status": 403,
        }

    trip_source = event.get("trip_source")
    reason = KNOWN_AUTOMATED_TRIP_SOURCES.get(trip_source)
    if reason is None:
        logger.error(
            "Refusing auto_trip: trip_source is not on the automated-trip "
            "allow-list — refusing to fabricate a free-text justification."
        )
        return {
            "status": "REJECTED",
            "message": (
                "Automated trip denied: trip_source must be one of "
                + ", ".join(sorted(KNOWN_AUTOMATED_TRIP_SOURCES))
            ),
            "http_status": 400,
        }

    logger.info(
        "Circuit breaker automatically tripped via auto_trip (IAM-scoped "
        "lambda:InvokeFunction grant + deploy-time acknowledged allow-list); "
        "trip_source=%s", trip_source,
    )
    return invoke_circuit_breaker(reason=reason, mode=mode)


def handle_alarm_event(event: dict) -> dict:
    """
    Handle CloudWatch Alarm event — automatic circuit breaker trigger.

    Time budget: the 10 s corroboration deadline plus the trip path
    (TRIP_PATH_BUDGET_MS, 21.5 s) plus POST_TRIP_MARGIN_MS (5 s) fit in the
    45 s breaker timeout.

    CloudWatch Alarm Lambda action sends events with this structure:
    {
        "source": "aws.cloudwatch",
        "alarmArn": "arn:aws:cloudwatch:...:alarm:fsi-challenger-dispute-rate-breach",
        "alarmData": {
            "alarmName": "fsi-challenger-dispute-rate-breach",
            "state": {"value": "ALARM", "reason": "..."},
            "previousState": {"value": "OK"},
            "configuration": {"metrics": [...]}
        }
    }
    """
    alarm_arn = event.get("alarmArn", "")
    alarm_data = event.get("alarmData", {})
    alarm_name = alarm_data.get("alarmName", "")
    state = alarm_data.get("state", {})
    state_value = state.get("value", "UNKNOWN")

    # ── Source verification ────────────────────────────────────
    # Do NOT trust an event just because it is alarm-shaped. The alarmArn must
    # be one of the three alarms this stack owns (TRUSTED_ALARM_ARNS). An
    # unverifiable or unknown ARN cannot trip the live kill switch and cannot
    # write a fabricated "CloudWatch Alarm" justification into the audit trail.
    if not TRUSTED_ALARM_ARNS:
        logger.error(
            "Refusing alarm trigger: TRUSTED_ALARM_ARNS is not configured, so no "
            "CloudWatch source can be verified. Rejecting the event."
        )
        return {
            "status": "REJECTED",
            "message": "Alarm source cannot be verified (TRUSTED_ALARM_ARNS unset).",
            "http_status": 403,
        }
    if alarm_arn not in TRUSTED_ALARM_ARNS:
        logger.error(
            "Refusing alarm trigger from an untrusted or absent alarmArn — not on "
            "the allow-list of this stack's alarms."
        )
        return {
            "status": "REJECTED",
            "message": "Alarm source ARN is not on the trusted allow-list.",
            "http_status": 403,
        }

    # Resolve the alarm NAME from the verified ARN, not from caller-supplied
    # alarmData — the ARN's final segment after ":alarm:" is the alarm name.
    verified_name = alarm_arn.split(":alarm:")[-1] if ":alarm:" in alarm_arn else alarm_arn
    if alarm_name and alarm_name != verified_name:
        logger.warning(
            "alarmData.alarmName does not match the verified ARN name; using %s",
            verified_name,
        )
    alarm_name = verified_name

    # Only trigger on ALARM state (not on OK transitions)
    if state_value != "ALARM":
        # state.value is caller text: echo only the known non-ALARM states.
        shown_state = state_value if state_value in ("OK", "INSUFFICIENT_DATA") else "unrecognized"
        logger.info("Alarm %s transitioned to %s — no action taken", alarm_name, shown_state)
        return {
            "status": "IGNORED",
            "message": f"Alarm state is {shown_state}, not ALARM — no action",
            "alarm_name": alarm_name,
        }

    # The trigger reason is resolved from the known-alarm table keyed on the
    # VERIFIED name — never built from caller-supplied state_reason text. A
    # verified ARN whose name is somehow not in the table still refuses to
    # fabricate free-text justification.
    reason = KNOWN_ALARM_REASONS.get(alarm_name)
    if reason is None:
        logger.error(
            "Verified alarm ARN %r resolved to unknown alarm name %r — refusing to "
            "trip on an alarm with no known drift reason.", alarm_arn, alarm_name,
        )
        return {
            "status": "REJECTED",
            "message": f"Verified alarm {alarm_name} has no known drift reason.",
            "http_status": 403,
        }

    logger.info("Verified CloudWatch Alarm %s in ALARM; corroborating", alarm_name)

    # Corroborate against stored VERIFIED decisions BEFORE any deny-all.
    # One 10 s budget; one retry on False if >= 4 s remain
    # (GSI propagation).
    deadline = time.monotonic() + CORROBORATION_DEADLINE_SECONDS
    corroboration = corroborate(alarm_name, deadline=deadline)
    if (corroboration["corroborated"] is False
            and deadline - time.monotonic() >= CORROBORATION_RETRY_MIN_BUDGET_SECONDS):
        time.sleep(CORROBORATION_RETRY_SLEEP_SECONDS)  # nosemgrep: arbitrary-sleep -- one bounded 3 s GSI-propagation retry, only if >= 4 s of the 10 s corroboration budget remain
        corroboration = corroborate(alarm_name, deadline=deadline)

    verdict = corroboration["corroborated"]
    if verdict is False:
        # No matching VERIFIED decisions: never attach. Audited, alerts.
        record_uncorroborated_alarm(alarm_name, reason, corroboration)
        logger.error("uncorroborated drift alarm %s; hold NOT attached", alarm_name)
        _emit_integrity_metric("UncorroboratedAlarm", 1)
        if corroboration.get("shaping_suspected"):
            _emit_integrity_metric("ShapingSuspected", 1)
        return {"status": "UNCORROBORATED", "http_status": 409, "alarm_name": alarm_name,
                "corroborated": False}

    # True -> trip. None (read failure or deadline) -> trip anyway:
    # containment over availability; a forced trip here needs a forged
    # datapoint AND a forced DynamoDB failure. Metrics after the trip, so
    # a slow metric call never delays containment.
    try:
        return invoke_circuit_breaker(reason=reason, mode="live", corroboration=corroboration)
    finally:
        if verdict is None:
            _emit_integrity_metric("CorroborationUnavailable", 1)
        if corroboration.get("shaping_suspected"):
            _emit_integrity_metric("ShapingSuspected", 1)


def record_uncorroborated_alarm(alarm_name: str, reason: str, corroboration: dict) -> str:
    """ALARM_UNCORROBORATED audit record. A write failure raises
    GovernanceAuditWriteError (async retry, then the DLQ)."""
    event_id = f"alarm-uncorroborated#{uuid.uuid4()}"
    try:
        _governance_table().put_item(
            Item={
                "event_id": event_id,
                "event_type": "ALARM_UNCORROBORATED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alarm_name": alarm_name,
                "trigger_reason": reason,
                "trigger_source": f"ALARM:{alarm_name}",
                "corroboration": corroboration,
                "retention_expires": RETENTION_EXPIRES,
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except Exception as e:  # noqa: BLE001 - every failure is fatal here
        logger.error("ALARM_UNCORROBORATED write failed (%s)", type(e).__name__)  # nosemgrep: logging-error-without-handling -- fail-closed: governance-audit write failure stays ERROR, re-raised as GovernanceAuditWriteError; class name only
        raise GovernanceAuditWriteError("governance-audit write failed (ALARM_UNCORROBORATED)") from e
    return event_id


def recheck_alarms(now: datetime = None, context=None) -> dict:
    """Re-run corroboration while a trusted alarm stays in ALARM (scheduled
    every 2 minutes). A CloudWatch alarm action fires once per
    transition into ALARM, so one False verdict would otherwise be final.

    Attach-only: it can only reach invoke_circuit_breaker, and only when the
    stored records corroborate. The alarm identity always comes from
    DescribeAlarms, never from the event. The pre-trip phase shares one
    12 s deadline on single-attempt clients, and a trip starts only with
    >= RECHECK_MIN_TRIP_HEADROOM_MS (the 21.5 s trip path) of Lambda time
    left, so it can't leave an INTENT without a GOVERNANCE_HOLD: 12 s +
    21.5 s + the 5 s margin fit in the 45 s timeout.

    The hold state is the governance-state item (consistent read): HELD, or
    a trip that never claimed it, means the hold is active. Before the item
    exists the index fallback (hold_sweep.hold_active) applies.
    """
    now = now or datetime.now(timezone.utc)
    deadline = time.monotonic() + RECHECK_PRETRIP_BUDGET_SECONDS

    # Every metric on this path uses the single-attempt client (<= 3 s), and
    # CorroborationUnavailable is emitted at most once per run, so a DEFERRED
    # or no-trip run can't run past the Lambda timeout into the DLQ.
    unavailable_emitted = []

    def emit_unavailable():
        if not unavailable_emitted:
            unavailable_emitted.append(True)
            _emit_integrity_metric("CorroborationUnavailable", 1,
                                   config=_corroboration_client_config())

    def deferred(why):
        emit_unavailable()
        logger.warning("recheck: %s; next run retries", why)
        return {"status": "DEFERRED"}

    try:
        cw = boto3.client("cloudwatch", region_name=REGION, config=_corroboration_client_config())
        in_alarm = []
        kwargs = {"AlarmNames": list(KNOWN_ALARM_REASONS), "StateValue": "ALARM",
                  "AlarmTypes": ["MetricAlarm"]}
        while True:
            if time.monotonic() >= deadline:
                return deferred("pre-trip deadline passed")
            page = cw.describe_alarms(**kwargs)
            in_alarm.extend(a for a in page.get("MetricAlarms", [])
                            if a.get("AlarmArn") in TRUSTED_ALARM_ARNS)
            if not page.get("NextToken"):
                break
            kwargs["NextToken"] = page["NextToken"]
    except (ClientError, BotoCoreError) as e:
        emit_unavailable()
        logger.warning("recheck: DescribeAlarms failed (%s); no trip", type(e).__name__)
        return {"status": "ERROR"}
    if not in_alarm:
        return {"status": "NO_ALARMS"}

    if time.monotonic() >= deadline:
        return deferred("pre-trip deadline passed")
    try:
        gov = boto3.resource("dynamodb", region_name=REGION,
                             config=_corroboration_client_config()).Table(AUDIT_TABLE)
        state, unclaimed = hold_sweep.current_hold(
            gov, lambda: governance_state.read(_state_table()), now)
    except (ClientError, BotoCoreError) as e:
        emit_unavailable()
        logger.warning("recheck: hold-state query failed (%s); no trip", type(e).__name__)
        return {"status": "ERROR"}
    if unclaimed is not None:
        logger.error("recheck: a trip never claimed the governance-state item; treating it as "
                     "the active hold")
        _emit_integrity_metric("HoldStateWriteFailed", 1, config=_corroboration_client_config())
    if state.active:
        return {"status": "HOLD_ACTIVE"}
    last = state.newest_event_at

    by_name = {a.get("AlarmName"): a for a in in_alarm}
    checked = []
    for name in KNOWN_ALARM_REASONS:
        alarm = by_name.get(name)
        if alarm is None:
            continue
        # The episode starts when StateValue last changed; never
        # StateUpdatedTimestamp (it also moves on EvaluationState changes).
        episode_start = alarm.get("StateTransitionedTimestamp")
        if not isinstance(episode_start, datetime):
            logger.warning("recheck: %s has no StateTransitionedTimestamp; skipped", name)
            continue
        if episode_start.tzinfo is None:
            episode_start = episode_start.replace(tzinfo=timezone.utc)
        if now - episode_start < timedelta(seconds=RECHECK_IN_FLIGHT_SECONDS):
            continue  # the transition's own alarm action is still in flight
        if last is not None and last >= episode_start:
            continue  # a hold or release already happened in this episode
        if time.monotonic() >= deadline:
            return deferred("pre-trip deadline passed")
        c = corroborate(name, now=now, deadline=deadline)
        checked.append({"alarm_name": name, "corroborated": c["corroborated"]})
        if c["corroborated"] is None:
            # Already evaluated with readable data as False for this
            # episode; a read failure on a recheck never becomes a trip.
            emit_unavailable()
            logger.warning("recheck: corroboration unavailable for %s; no trip", name)
            continue
        if c["corroborated"] is False:
            continue
        if context is not None and context.get_remaining_time_in_millis() < RECHECK_MIN_TRIP_HEADROOM_MS:
            return deferred("insufficient time to trip safely")
        invoke_circuit_breaker(KNOWN_ALARM_REASONS[name], "live",
                               corroboration={**c, "trigger": "recheck"})
        if c.get("shaping_suspected"):
            _emit_integrity_metric("ShapingSuspected", 1, config=_corroboration_client_config())
        return {"status": "RECHECKED", "alarms": checked, "tripped": name}
    return {"status": "RECHECKED", "alarms": checked, "tripped": None}


def check_thresholds(metrics: dict, mode: str) -> dict:
    """
    Check caller-supplied drift metrics against thresholds.

    This is the action=="check" path, reachable by ANY principal holding
    lambda:InvokeFunction on this function — unlike action=="invoke" and
    action=="auto_trip", it has no caller allow-list, because its purpose
    is to let any caller preview/evaluate a metrics snapshot against the
    configured thresholds (e.g. for dashboards or dry-run tooling).

    Because of that, this path must NEVER be able to actually trip the
    circuit breaker in live mode — a breach is reported to the
    caller, but invoke_circuit_breaker() is only called in "local" mode
    (the no-AWS CLI/dev-demo/test simulation path used throughout this
    module), exactly like how _resolve_mode() already guarantees "local"
    can never be reached inside the deployed Lambda. In live mode this
    function is evaluation-only: a breach is reported as BREACH_DETECTED
    with no trip side effect, so an unauthenticated/unauthorized caller
    cannot use the default/omitted-action path to reach
    invoke_circuit_breaker() with a free-text reason and no principal
    check — the exact gap action=="invoke"/auto_trip were hardened
    against. Real automatic trips on these same thresholds happen via the
    CloudWatch alarms (handle_alarm_event, TRUSTED_ALARM_ARNS) or the
    executor's auto_trip path, both of which carry their own
    authorization.
    """
    breaches = []

    dispute_rate = metrics.get("dispute_rate", 0)
    if dispute_rate > THRESHOLDS["challenger_dispute_rate"]:
        breaches.append(
            f"Challenger dispute rate {dispute_rate:.0%} > threshold {THRESHOLDS['challenger_dispute_rate']:.0%}"
        )

    guardrail_rate = metrics.get("guardrail_intervention_rate", 0)
    if guardrail_rate > THRESHOLDS["guardrail_intervention_rate"]:
        breaches.append(
            f"Guardrail intervention rate {guardrail_rate:.0%} > threshold {THRESHOLDS['guardrail_intervention_rate']:.0%}"
        )

    volume_multiplier = metrics.get("detection_volume_multiplier", 1.0)
    if volume_multiplier > THRESHOLDS["detection_volume_multiplier"]:
        breaches.append(
            f"Detection volume {volume_multiplier:.1f}x > threshold {THRESHOLDS['detection_volume_multiplier']:.1f}x"
        )

    if breaches:
        reason = "Drift threshold breach: " + "; ".join(breaches)
        if mode == "local":
            return invoke_circuit_breaker(reason=reason, mode=mode)
        # Live mode: evaluation-only. Report the breach without tripping —
        # action=="check" has no caller allow-list, so it must never reach
        # invoke_circuit_breaker() outside the local dev/test simulation.
        logger.warning(
            "check_thresholds (action=\"check\") observed a threshold breach in "
            "live mode but is evaluation-only — no trip side effect. "
            "reason=%s", reason,
        )
        return {
            "status": "BREACH_DETECTED",
            "message": (
                "Threshold breach detected, but action=\"check\" is evaluation-only "
                "and does not trip the circuit breaker. Use the authorized alarm, "
                "auto_trip, or invoke path to trip it."
            ),
            "trigger_reason": reason,
            "metrics_checked": metrics,
            "thresholds": THRESHOLDS,
        }
    else:
        return {
            "status": "OK",
            "message": "All metrics within thresholds",
            "metrics_checked": metrics,
            "thresholds": THRESHOLDS,
        }


def _derive_trigger_source(reason: str):
    """ALARM:<name> / AUTO_TRIP:<code> / MANUAL:<code> from an enum-resolved
    reason. Every trip path resolves its reason from one of the
    fixed tables, so the mapping is exact; anything else -> None."""
    for name, text in KNOWN_ALARM_REASONS.items():
        if reason == text:
            return f"ALARM:{name}"
    for code, text in KNOWN_AUTOMATED_TRIP_SOURCES.items():
        if reason == text:
            return f"AUTO_TRIP:{code}"
    for code, text in KNOWN_MANUAL_TRIGGER_REASONS.items():
        if reason == text:
            return f"MANUAL:{code}"
    return None


def _bounded_client_config():
    """Short timeouts for the best-effort integrity metric, so it can't eat
    the 30 s budget."""
    from botocore.config import Config
    return Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2})


def _corroboration_client_config():
    """Clients on the corroboration / recheck pre-trip path: one attempt
    (total_max_attempts=1; "max_attempts" would mean retries), connect 1 s,
    read 2 s, so one call is <= 3 s and the deadlines hold."""
    from botocore.config import Config
    return Config(connect_timeout=1, read_timeout=2,
                  retries={"total_max_attempts": 1, "mode": "standard"})


def validate_drift_counts(raw):
    """The stored drift counts as plain ints, or None when malformed.
    Identical to lambdas/drift_metric_publisher/handler.validate_drift_counts
    (tests/test_drift_counts_parity.py)."""
    if not isinstance(raw, dict) or set(raw) != set(DRIFT_COUNT_KEYS):
        return None
    counts = {}
    for key in DRIFT_COUNT_KEYS:
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
            return None
        if isinstance(value, Decimal):
            if not value.is_finite() or value != value.to_integral_value():
                return None
            value = int(value)
        if value < 0 or value > MAX_DRIFT_COUNT:
            return None
        counts[key] = value
    if any(counts[k] > counts["clusters"] for k in DRIFT_COUNT_KEYS if k != "clusters"):
        return None
    return counts


def _ddb_safe(value):
    """A DynamoDB-serializable copy: floats -> Decimal(str(round(x, 4)))
    (nan/inf -> None); bool/int/str/None/Decimal pass; any other type is a
    code bug and raises TypeError."""
    import math
    if isinstance(value, dict):
        return {k: _ddb_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_ddb_safe(v) for v in value]
    if isinstance(value, float):
        return Decimal(str(round(value, 4))) if math.isfinite(value) else None
    if value is None or isinstance(value, (bool, int, str, Decimal)):
        return value
    raise TypeError(f"not DynamoDB-safe: {type(value).__name__}")


def _ratio(numerator, denominator) -> Decimal:
    return (Decimal(numerator) / Decimal(denominator)).quantize(Decimal("0.0001"))


def corroborate(alarm_name: str, now: datetime = None, deadline: float = None) -> dict:
    """Recompute the alarm's condition from durable, VERIFIED compliance
    records.

    corroborated: True / False from the records; None only for a botocore
    read error or the deadline (any other exception is a code bug and
    propagates). Malformed items are skipped and counted, never raised.
    One Query per day partition, newest first, so the item cap truncates the
    baseline, never the recent window.
    """
    from boto3.dynamodb.conditions import Key

    rule = CORROBORATION_RULES[alarm_name]
    now = now or datetime.now(timezone.utc)
    recent_minutes = rule.window_minutes + CORROBORATION_SLACK_MINUTES
    recent_start = now - timedelta(minutes=recent_minutes)
    baseline_start = recent_start - timedelta(minutes=CORROBORATION_BASELINE_MINUTES)
    bucket_start = now - timedelta(minutes=ALARM_EVALUATION_PERIODS + CORROBORATION_SLACK_MINUTES)
    unavailable = {"window_minutes": rule.window_minutes, "slack_minutes": CORROBORATION_SLACK_MINUTES,
                   "corroborated": None}

    items, truncated = [], False
    try:
        table = boto3.resource("dynamodb", region_name=REGION,
                               config=_corroboration_client_config()).Table(COMPLIANCE_TABLE)
        days = sorted({baseline_start.date().isoformat(), now.date().isoformat()}, reverse=True)
        for index, day in enumerate(days):
            kwargs = {
                "IndexName": "by_day_ts",
                "KeyConditionExpression": (Key("record_day").eq(day)
                                           & Key("timestamp").gte(baseline_start.isoformat())),
                "ProjectionExpression": "compliance_id, record_day, #ts, drift_counts, provenance_status",
                "ExpressionAttributeNames": {"#ts": "timestamp"},
                "Select": "SPECIFIC_ATTRIBUTES",
                "ScanIndexForward": False,
            }
            while True:
                if len(items) >= CORROBORATION_MAX_ITEMS:
                    truncated = True
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    logger.warning("Corroboration deadline passed for %s", alarm_name)
                    return {**unavailable, "error_class": "DeadlineExceeded"}
                page = table.query(**kwargs)
                items.extend(page.get("Items", []))
                if "LastEvaluatedKey" not in page:
                    break
                kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
            if truncated:
                break
    except (ClientError, BotoCoreError) as e:
        logger.warning("Corroboration query failed for %s (%s)", alarm_name, type(e).__name__)
        return {**unavailable, "error_class": type(e).__name__}
    if len(items) > CORROBORATION_MAX_ITEMS:
        items, truncated = items[:CORROBORATION_MAX_ITEMS], True

    recent = {"records": 0, "clusters": 0, "disputes": 0, "guardrail_hits": 0}
    baseline_records = baseline_clusters = invalid = 0
    buckets = {}
    for item in items:
        if item.get("provenance_status") != "VERIFIED":
            continue
        counts = validate_drift_counts(item.get("drift_counts"))
        if counts is None:
            invalid += 1
            continue
        ts = _parse_iso(item.get("timestamp"))
        if ts is None or ts < recent_start:
            baseline_records += 1
            baseline_clusters += counts["clusters"]
            continue
        recent["records"] += 1
        for key in ("clusters", "disputes", "guardrail_hits"):
            recent[key] += counts[key]
        if ts >= bucket_start:
            bucket = buckets.setdefault(ts.replace(second=0, microsecond=0),
                                        {"clusters": 0, "disputes": 0, "guardrail_hits": 0})
            for key in bucket:
                bucket[key] += counts[key]
    if invalid:
        logger.warning("Corroboration for %s skipped %d malformed VERIFIED record(s)", alarm_name, invalid)

    clusters = recent["clusters"]
    floor = MIN_CLUSTERS_FOR_CORROBORATION
    breaching_minutes = 0
    recomputed_rate = None
    if rule.numerator is None:
        # Volume: clusters per minute vs max(baseline per minute, floor/60).
        per_minute = Decimal(clusters) / Decimal(recent_minutes)
        base = max(Decimal(baseline_clusters) / CORROBORATION_BASELINE_MINUTES,
                   Decimal(floor) / CORROBORATION_BASELINE_MINUTES)
        recomputed_rate = (per_minute / base).quantize(Decimal("0.0001"))
        corroborated = clusters >= floor and per_minute > rule.threshold * base
    else:
        if clusters:
            recomputed_rate = _ratio(recent[rule.numerator], clusters)
        aggregate = clusters >= floor and Decimal(recent[rule.numerator]) / Decimal(clusters) > rule.threshold
        corroborated = aggregate
        if alarm_name in PER_MINUTE_ALARMS:
            numerator, threshold = PER_MINUTE_ALARMS[alarm_name]
            breaching_minutes = sum(
                1 for b in buckets.values()
                if b["clusters"] >= floor and Decimal(b[numerator]) / Decimal(b["clusters"]) > threshold)
            corroborated = breaching_minutes >= ALARM_DATAPOINTS_TO_ALARM or aggregate

    invocation_ratio = ((Decimal(recent["records"]) / Decimal(recent_minutes))
                        / max(Decimal(baseline_records) / CORROBORATION_BASELINE_MINUTES,
                              Decimal(1) / CORROBORATION_BASELINE_MINUTES)).quantize(Decimal("0.0001"))
    result = {
        "window_minutes": rule.window_minutes,
        "slack_minutes": CORROBORATION_SLACK_MINUTES,
        **recent,
        "baseline_records": baseline_records,
        "baseline_clusters": baseline_clusters,
        "invalid_records": invalid,
        "truncated": truncated,
        "breaching_minutes": breaching_minutes,
        "recomputed_rate": recomputed_rate,
        "invocation_ratio": invocation_ratio,
        "shaping_suspected": (recent["records"] >= SHAPING_MIN_RECORDS
                              and invocation_ratio > SHAPING_INVOCATION_RATIO),
        "corroborated": bool(corroborated),
    }
    return _ddb_safe(result)


def _emit_integrity_metric(name: str, value, config=None) -> None:
    """Best-effort FSI/GovernanceIntegrity datapoint (the audit record
    carries the same fact). The recheck path passes the single-attempt
    _corroboration_client_config() so it stays inside its deadline."""
    try:
        boto3.client("cloudwatch", region_name=REGION,
                     config=config or _bounded_client_config()).put_metric_data(
            Namespace=GOVERNANCE_INTEGRITY_NAMESPACE,
            MetricData=[{"MetricName": name, "Value": value, "Unit": "Count"}],
        )
    except Exception as e:  # noqa: BLE001 - best effort
        logger.error("%s metric publish failed (%s)", name, type(e).__name__)


def invoke_circuit_breaker(reason: str, mode: str = "local", triggered_by: str = None,
                           trigger_source: str = None, corroboration: dict = None) -> dict:
    """
    Execute circuit breaker — revoke roles, log event, set hold state.

    triggered_by is the STS-verified principal ARN for a manual trip.
    trigger_source is ALARM:<name> / AUTO_TRIP:<code> / MANUAL:<code>
    (derived from the enum-resolved reason when not given). An alarm trip
    reaches this function only after the caller corroborated it against
    VERIFIED compliance records (True, or None when the read failed), and
    all three are written onto the GOVERNANCE_HOLD event.

    Live mode writes GOVERNANCE_HOLD_INTENT before attaching. If that write
    fails the trip STILL proceeds, and GovernanceAuditWriteError is raised
    after the hold is verified, so the async invocation is retried or lands
    in the DLQ.

    After the intent, the trip claims the governance-state item
    (governance_state.claim_trip: a new generation, status HELD), which is
    what serializes it against a release. A failed claim never blocks
    containment: it is retried once after the attach loop, and if both
    attempts fail GovernanceStateWriteError is raised after the hold is
    verified (the sweep enforces the unclaimed trip meanwhile). Each
    attempt is one single-attempt call (<= 3 s), so the claims add at most
    3 + 0.2 + 3 = 6.2 s; the whole trip path is budgeted at
    TRIP_PATH_BUDGET_MS (21.5 s).

    The GOVERNANCE_HOLD record's timestamp is its write time;
    trip_started_at (and the returned timestamp) is the start time.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    event_id = str(uuid.uuid4())

    print(f"\n{'='*60}")
    print(f"  CIRCUIT BREAKER INVOKED")
    print(f"  Reason: {reason}")
    print(f"  Time: {timestamp}")
    print(f"{'='*60}")

    if mode == "local":
        # Defense in depth: a simulated trip must never run
        # inside the deployed Lambda.
        assert not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), (
            "invoke_circuit_breaker(mode='local') must never run inside the deployed Lambda"
        )
        # Simulate by writing to local state file
        state = {
            "status": "GOVERNANCE_HOLD",
            "event_id": event_id,
            "timestamp": timestamp,
            "trigger_reason": reason,
            "roles_revoked": AGENT_ROLES,
        }
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        logger.info("State written to %s", STATE_FILE)
        logger.info("Simulated revocation of %d roles", len(AGENT_ROLES))
        for role in AGENT_ROLES:
            print(f"  REVOKED: {role}")

        result = {
            "status": "GOVERNANCE_HOLD",
            "event_id": event_id,
            "timestamp": timestamp,
            "trigger_reason": reason,
            "roles_revoked": AGENT_ROLES,
            "http_status": 503,
            "message": "All agents disabled. Manual re-enable required.",
        }
        logger.info("Result: 503 Governance Hold")
        return result

    # Live mode: attach deny policy to all agent roles, then VERIFY the hold
    # is actually in place before claiming success. The old code swallowed
    # each attach error and returned GOVERNANCE_HOLD/503 unconditionally, so
    # a throttle, a policy-quota breach or a wrong ARN left the agents fully
    # live while the API response and the audit record both asserted they
    # were disabled. The trip now fails closed: an unverified
    # hold is an error, not a success.
    if trigger_source is None:
        trigger_source = _derive_trigger_source(reason)
    # Alarm trips arrive here already corroborated (handle_alarm_event /
    # recheck_alarms); an uncorroborated alarm never reaches this function.

    # Write-ahead intent. Containment never waits on
    # it: a failed intent write is reported after the hold is verified.
    intent_error = None
    try:
        write_governance_hold_event(
            f"intent-{event_id}", timestamp, reason,
            triggered_by=triggered_by, trigger_source=trigger_source, intent=True,
        )
    except GovernanceAuditWriteError as e:
        intent_error = e
        logger.error("GOVERNANCE_HOLD_INTENT write failed; tripping anyway (containment first)")

    # Claim the governance-state item (one attempt now, one retry after the
    # attach loop). Containment never waits on more than one attempt.
    state_table = _state_table()
    failed_claims = []
    hold_generation, state_error = _claim_trip_attempt(state_table, event_id, timestamp, failed_claims)

    iam = boto3.client("iam", region_name=REGION)
    deny_policy_arn = resolve_deny_policy_arn()

    attach_failures = {}
    for role in AGENT_ROLES:
        try:
            iam.attach_role_policy(RoleName=role, PolicyArn=deny_policy_arn)
            logger.info("Attached deny policy to %s", role)
        except Exception as e:
            # Log server-side with a generated error_id; never record
            # str(e) in the audit trail or API response — a
            # raw IAM exception can carry role/policy ARNs or other
            # account-specific detail.
            error_id = str(uuid.uuid4())
            logger.error(
                "Failed to revoke %s [%s]: %s", role, error_id, e, exc_info=True,
            )
            attach_failures[role] = {"error_id": error_id, "error_class": _classify_aws_error(e)}

    # Re-read the attached policies and confirm the deny policy is actually
    # present on every role — do not trust the attach call's return.
    status = get_status("live")
    confirmed_roles = status.get("revoked_roles", []) if status.get("status") == "GOVERNANCE_HOLD" else []
    unconfirmed = [r for r in AGENT_ROLES if r not in confirmed_roles]

    # Post-trip reconcile: retry the attach for any role still
    # unconfirmed, before the hold record is written. Attach-only; any
    # failure here is logged and the hold verdict uses the re-read below.
    reconciled_roles = []
    if unconfirmed:
        try:
            reconcile = hold_sweep.reconcile_hold(
                iam, _governance_table(), roles=AGENT_ROLES, deny_policy_arn=deny_policy_arn,
                trigger="post_trip", emit_metric=_emit_integrity_metric, hold_event_id=event_id,
                assume_active=True)
            reconciled_roles = list(reconcile.get("roles_reattached", []))
        except Exception as e:  # noqa: BLE001 - never blocks the trip's own verdict
            logger.error("Post-trip reconcile failed (%s)", type(e).__name__)
        status = get_status("live")
        confirmed_roles = status.get("revoked_roles", []) if status.get("status") == "GOVERNANCE_HOLD" else []
        unconfirmed = [r for r in AGENT_ROLES if r not in confirmed_roles]

    if hold_generation is None:
        time.sleep(CLAIM_RETRY_SLEEP_SECONDS)  # nosemgrep: arbitrary-sleep -- one bounded 0.2 s pause before the single governance-state claim retry
        hold_generation, state_error = _claim_trip_attempt(state_table, event_id, timestamp, failed_claims)

    # The audit record reflects what actually happened, per role. Its
    # timestamp is the write time; trip_started_at is the start.
    held_at = datetime.now(timezone.utc).isoformat()
    try:
        write_governance_hold_event(
            event_id, held_at, reason,
            roles_revoked=confirmed_roles,
            attach_failures=attach_failures,
            triggered_by=triggered_by,
            trigger_source=trigger_source,
            corroboration=corroboration,
            reconciled_roles=reconciled_roles,
            started_at=timestamp,
            hold_generation=hold_generation,
        )
    finally:
        # After the hold record, so a slow metric call never delays it; one
        # datapoint per failed claim attempt.
        if failed_claims:
            _emit_integrity_metric("HoldStateWriteFailed", len(failed_claims),
                                   config=_corroboration_client_config())

    if unconfirmed:
        # Enforcement is NOT in place for at least one role — do not report a
        # hold. Raise so the Lambda invocation is marked failed (and can be
        # retried / alarmed) rather than silently reporting a false 503.
        message = (
            "Circuit breaker FAILED to enforce governance hold on: "
            + ", ".join(unconfirmed)
        )
        logger.error(message)  # nosemgrep: logging-error-without-handling -- hold not enforced on a role: ERROR is deliberate, raised as GovernanceHoldEnforcementError so the invocation fails
        raise GovernanceHoldEnforcementError(message, confirmed_roles=confirmed_roles,
                                              unconfirmed_roles=unconfirmed,
                                              attach_failures=attach_failures)

    if intent_error is not None:
        if state_error is not None:
            logger.error("Both the GOVERNANCE_HOLD_INTENT write and the governance-state claim "
                         "failed (%s, %s); the hold is enforced", type(intent_error).__name__,
                         type(state_error).__name__)
        raise GovernanceAuditWriteError(
            "governance hold is in place, but its GOVERNANCE_HOLD_INTENT record "
            "could not be written") from (state_error or intent_error)
    if state_error is not None:
        raise GovernanceStateWriteError(
            "governance hold is in place, but the governance-state item could not be "
            "claimed") from state_error

    for role in confirmed_roles:
        print(f"  REVOKED: {role}")

    result = {
        "status": "GOVERNANCE_HOLD",
        "event_id": event_id,
        "timestamp": timestamp,
        "trigger_reason": reason,
        "roles_revoked": confirmed_roles,
        "held_at": held_at,
        "hold_generation": hold_generation,
        "http_status": 503,
        "message": "All agents disabled. Two-person release required.",
    }
    if triggered_by:
        result["triggered_by"] = triggered_by
    if trigger_source:
        result["trigger_source"] = trigger_source
    if corroboration is not None:
        result["corroborated"] = corroboration.get("corroborated")
    logger.info("Result: 503 Governance Hold (verified on %d role(s))", len(confirmed_roles))
    return result


def _claim_trip_attempt(table, event_id: str, started_at: str, failed_claims: list):
    """One governance_state.claim_trip attempt: (generation, None), or
    (None, error) with the failure appended to failed_claims. held_at is
    taken immediately before the call (the unclaimed-hold rule relies on
    it being the claim write time)."""
    try:
        generation = governance_state.claim_trip(table, event_id, started_at,
                                                 datetime.now(timezone.utc).isoformat())
        return generation, None
    except Exception as e:  # noqa: BLE001 - containment first; reported after the hold
        logger.error("governance-state claim failed for hold %s (%s)", event_id, type(e).__name__)
        failed_claims.append(type(e).__name__)
        return None, e


def get_status(mode: str) -> dict:
    """Check current circuit breaker status."""
    if mode == "local":
        # Defense in depth: even if something upstream still
        # passed mode="local" into this deployed function, never return a
        # simulated reading of the containment control from a Lambda
        # process — STATE_FILE is under the read-only /var/task there and
        # can never reflect reality.
        assert not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), (
            "get_status(mode='local') must never run inside the deployed Lambda"
        )
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)
            return state
        else:
            return {"status": "ACTIVE", "message": "Circuit breaker not engaged"}
    else:
        # Check if deny policy is attached to any role
        iam = boto3.client("iam", region_name=REGION)
        deny_policy_arn = resolve_deny_policy_arn()
        revoked_roles = []
        for role in AGENT_ROLES:
            try:
                policies = iam.list_attached_role_policies(RoleName=role)
                for policy in policies.get("AttachedPolicies", []):
                    if policy["PolicyArn"] == deny_policy_arn:
                        revoked_roles.append(role)
            except Exception as e:
                # Same outcome as before: an unverifiable role is not counted
                # as revoked. Log the error class only, never the message.
                logger.warning(
                    "Could not list attached policies for %s (%s); treating as not revoked",
                    role, _classify_aws_error(e),
                )

        if revoked_roles:
            return {
                "status": "GOVERNANCE_HOLD",
                "revoked_roles": revoked_roles,
            }
        else:
            return {"status": "ACTIVE", "message": "Circuit breaker not engaged"}


def write_governance_hold_event(event_id: str, timestamp: str, reason: str,
                                roles_revoked=None, attach_failures=None, triggered_by=None,
                                trigger_source=None, corroboration=None, intent=False,
                                reconciled_roles=None, started_at=None, hold_generation=None):
    """Write a GOVERNANCE_HOLD (or, with intent=True, GOVERNANCE_HOLD_INTENT)
    event to the audit trail.

    For the hold record, ``timestamp`` is its write time, ``started_at`` the
    trip start (stored as trip_started_at) and ``hold_generation`` the
    governance-state generation the trip claimed; a trip whose claims all
    failed is recorded with state_claimed: false instead.

    The hold record says exactly which roles were confirmed revoked and any
    per-role attach failures, so it reflects what actually happened rather
    than an unverified claim. The intent record is written
    before any attach and names the roles targeted. A write failure is
    fatal: a hold must not occur without a durable audit record,
    so this re-raises instead of swallowing the error.
    """
    try:
        table = _governance_table()
        item = {
            "event_id": event_id,
            "event_type": "GOVERNANCE_HOLD_INTENT" if intent else "GOVERNANCE_HOLD",
            "timestamp": timestamp,
            "trigger_reason": reason,
            "retention_expires": RETENTION_EXPIRES,
        }
        if intent:
            item["roles_targeted"] = list(AGENT_ROLES)
        else:
            item["roles_revoked"] = roles_revoked if roles_revoked is not None else AGENT_ROLES
        if attach_failures:
            item["attach_failures"] = attach_failures
        if triggered_by:
            item["triggered_by"] = triggered_by
        if trigger_source:
            item["trigger_source"] = trigger_source
        if corroboration is not None:
            item["corroboration"] = corroboration
        if reconciled_roles:
            item["reconciled_roles"] = list(reconciled_roles)
        if started_at:
            item["trip_started_at"] = started_at
        if not intent:
            if hold_generation is not None:
                item["hold_generation"] = hold_generation
            else:
                item["state_claimed"] = False
        table.put_item(Item=item)
    except Exception as e:
        # WARNING: GovernanceAuditWriteError propagates (fail-closed) and the
        # Lambda runtime records it as an unhandled ERROR.
        logger.warning("Audit write failed: %s", e)
        raise GovernanceAuditWriteError(f"governance-audit write failed: {e}") from e


def write_governance_release_event(event_id: str, timestamp: str, releasing_principal: str,
                                   prior_event_id: str, *, requested_by: str = None,
                                   approved_by: str = None, release_request_id: str = None,
                                   hold_generation: int = None) -> bool:
    """
    Write GOVERNANCE_HOLD_RELEASED to the audit trail BEFORE any detach. The
    caller treats a failure here as fatal to the release (_perform_release):
    a hold must never be lifted with no record of who lifted it or when.

    Returns:
        True if the audit write succeeded, False otherwise.
    """
    try:
        item = {
            "event_id": event_id,
            "event_type": "GOVERNANCE_HOLD_RELEASED",
            "timestamp": timestamp,
            "released_by": releasing_principal,
            "prior_hold_event_id": prior_event_id,
            "roles_restored": AGENT_ROLES,
            "retention_expires": RETENTION_EXPIRES,
        }
        for key, value in (("requested_by", requested_by), ("approved_by", approved_by),
                           ("release_request_id", release_request_id)):
            if value:
                item[key] = value
        if hold_generation is not None:
            item["hold_generation"] = hold_generation
        _governance_table().put_item(Item=item)
        return True
    except Exception as e:
        logger.error("Governance release audit write failed: %s", e)
        return False


def write_release_completed_event(event_id: str, timestamp: str, release_event_id: str,
                                  release_request_id: str, detached_roles, detach_failures,
                                  final_status: str, hold_event_id_after=None,
                                  hold_generation_after=None, roles_reattached=(),
                                  reattach_failures=None, state_unverified=False) -> bool:
    """GOVERNANCE_HOLD_RELEASE_COMPLETED after the detaches: per-role results,
    the re-read IAM state (final_status, or SUPERSEDED / ABORTED), the
    governance-state hold seen afterwards and any re-attach. Failure ->
    False (the caller reports audit_incomplete; the release already happened
    and its pre-record exists)."""
    try:
        item = {
            "event_id": event_id,
            "event_type": "GOVERNANCE_HOLD_RELEASE_COMPLETED",
            "timestamp": timestamp,
            "release_event_id": release_event_id,
            "release_request_id": release_request_id,
            "roles_detached": list(detached_roles),
            "detach_failures": detach_failures,
            "final_status": final_status,
            "hold_event_id_after": hold_event_id_after or "UNKNOWN",
            "roles_reattached": list(roles_reattached),
            "reattach_failures": reattach_failures or {},
            "state_unverified": bool(state_unverified),
            "retention_expires": RETENTION_EXPIRES,
        }
        if hold_generation_after is not None:
            item["hold_generation_after"] = hold_generation_after
        _governance_table().put_item(Item=item)
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("Governance release completion audit write failed (%s)", type(e).__name__)
        return False


def _newest_event(table, event_type: str):
    """The newest indexed event of ``event_type``, or None. Raises on a
    lookup error (callers fail closed)."""
    from boto3.dynamodb.conditions import Key
    page = table.query(
        IndexName="by_event_type",
        KeyConditionExpression=Key("event_type").eq(event_type),
        ScanIndexForward=False,
        Limit=1,
    )
    items = page.get("Items", [])
    return items[0] if items else None


def _valid_generation(value):
    """A governance-state generation as int (>= 1), or None. DynamoDB
    returns numbers as Decimal; bools, fractions and strings are refused."""
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        return None
    if isinstance(value, Decimal) and not value.is_finite():
        return None
    if value != int(value) or int(value) < 1:
        return None
    return int(value)


def _parse_iso(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _is_conditional_failure(e: Exception) -> bool:
    response = getattr(e, "response", None)
    return isinstance(response, dict) and \
        response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


RELEASE_ALLOWED_AFTER = frozenset({"ABORTED", "SUPERSEDED"})


def _hold_lookup_unavailable(e: Exception) -> dict:
    error_id = str(uuid.uuid4())
    logger.error("Release check: hold lookup failed [%s] (%s)", error_id, type(e).__name__)
    return _rejected(503, f"hold event lookup unavailable (ref {error_id})", "HOLD_LOOKUP_UNAVAILABLE")


def _trip_in_progress(table, state: dict):
    """409 TRIP_IN_PROGRESS when a trip recorded in the index never claimed
    the state item (it is still the active hold; wait for the claim, or
    re-trip), else None. A lookup error: 503 HOLD_LOOKUP_UNAVAILABLE."""
    try:
        unclaimed = hold_sweep.unclaimed_hold(table, state)
    except Exception as e:  # noqa: BLE001
        return _hold_lookup_unavailable(e)
    if unclaimed is None:
        return None
    logger.warning("Release refused: a trip has not claimed the governance-state item yet")
    return _rejected(409, "a trip is still being recorded; wait, or re-trip, then release",
                     "TRIP_IN_PROGRESS")


def _release_blockers(table, state: dict):
    """Refusal shared by request and approval, or None.

    TRIP_IN_PROGRESS: see _trip_in_progress.
    HOLD_ALREADY_RELEASED: the newest release names this hold and its
    COMPLETED record is missing (a crash mid-release) or not ABORTED /
    SUPERSEDED. Any lookup error: 503 HOLD_LOOKUP_UNAVAILABLE."""
    blocked = _trip_in_progress(table, state)
    if blocked:
        return blocked
    try:
        released = _newest_event(table, "GOVERNANCE_HOLD_RELEASED")
        if released and released.get("prior_hold_event_id") == state.get("hold_event_id"):
            completed = table.get_item(Key={"event_id": f"completed-{released.get('event_id')}"},
                                       ConsistentRead=True).get("Item")
            if not completed or completed.get("final_status") not in RELEASE_ALLOWED_AFTER:
                logger.warning("Release refused: this hold was already released")
                return _rejected(409, "this hold was already released; re-trip to start a new hold",
                                 "HOLD_ALREADY_RELEASED")
    except Exception as e:  # noqa: BLE001
        return _hold_lookup_unavailable(e)
    return None


def _read_state_or_rejection(context: str):
    """(state item or None, None) or (None, 503 rejection)."""
    try:
        return governance_state.read(_state_table()), None
    except Exception as e:  # noqa: BLE001
        error_id = str(uuid.uuid4())
        logger.error("%s: governance-state read failed [%s] (%s)", context, error_id, type(e).__name__)
        return None, _rejected(503, f"hold event lookup unavailable (ref {error_id})",
                               "HOLD_LOOKUP_UNAVAILABLE")


def _handle_request_release(event: dict) -> dict:
    """First step of the two-person release (live; fsi-circuit-breaker-human).
    Binds the request to the governance-state hold (hold_event_id and
    generation, consistent read)."""
    principal, authorization, rejection = _verify_caller(
        event, "request_release", "active-hold", authz.REQUEST_RELEASE)
    if rejection:
        return rejection

    if get_status("live").get("status") != "GOVERNANCE_HOLD":
        logger.info("Release request refused: no active hold")
        return _rejected(409, "no active governance hold", "NO_ACTIVE_HOLD")
    state, rejection = _read_state_or_rejection("Release request")
    if rejection:
        return rejection
    if not state:
        logger.warning("Release request refused: no governance-state hold recorded")
        return _rejected(409, "no recorded hold state; re-trip, then release", "HOLD_EVENT_UNKNOWN")
    table = _governance_table()
    hold_generation = _valid_generation(state.get("generation"))
    hold_event_id = state.get("hold_event_id")
    if state.get("status") != governance_state.HELD or hold_generation is None or not hold_event_id:
        # An unclaimed trip is the real reason the item is not HELD.
        blocked = _trip_in_progress(table, state)
        if blocked:
            return blocked
        logger.warning("Release request refused: the governance-state item is not HELD")
        return _rejected(409, "the recorded hold state is not HELD; re-trip, then release",
                         "HOLD_STATE_MISMATCH")
    blocked = _release_blockers(table, state)
    if blocked:
        return blocked

    now = datetime.now(timezone.utc)
    request_id = str(uuid.uuid4())
    expires_at = (now + timedelta(seconds=RELEASE_REQUEST_TTL_SECONDS)).isoformat()
    try:
        table.put_item(
            Item={
                "event_id": f"release-request#{request_id}",
                "event_type": "RELEASE_REQUESTED",
                "timestamp": now.isoformat(),
                "requested_by": principal.arn,
                "requested_by_individual": authorization.individual,
                "requested_by_channel": authorization.channel,
                "hold_event_id": hold_event_id,
                "hold_generation": hold_generation,
                "expires_at": expires_at,
                "status": "PENDING",
                "retention_expires": RETENTION_EXPIRES,
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except Exception as e:  # noqa: BLE001
        error_id = str(uuid.uuid4())
        logger.error("Release request write failed [%s] (%s)", error_id, type(e).__name__)
        return _rejected(500, f"release request could not be recorded (ref {error_id})",
                         "AUDIT_WRITE_FAILED")
    logger.info("Release requested by %s (request %s, hold %s, generation %d)",
                principal.arn, request_id, hold_event_id, hold_generation)
    return {"status": "RELEASE_PENDING", "release_request_id": request_id,
            "expires_at": expires_at, "http_status": 202}


def _handle_approve_release(event: dict) -> dict:
    """Second step: a distinct verified individual on the same channel
    approves a pending, unexpired request whose hold and generation are
    still the governance-state item's (consistent read)."""
    request_id = event.get("release_request_id")
    if not isinstance(request_id, str) or not RELEASE_REQUEST_ID_RE.fullmatch(request_id):
        return _rejected(400, "release_request_id is missing or malformed", "INVALID_REQUEST_ID")
    principal, authorization, rejection = _verify_caller(
        event, "approve_release", request_id, authz.APPROVE_RELEASE)
    if rejection:
        return rejection

    table = _governance_table()
    try:
        request = table.get_item(Key={"event_id": f"release-request#{request_id}"},
                                 ConsistentRead=True).get("Item")
    except Exception as e:  # noqa: BLE001
        error_id = str(uuid.uuid4())
        logger.error("Release approval: request lookup failed [%s] (%s)", error_id, type(e).__name__)
        return _rejected(503, f"release request lookup unavailable (ref {error_id})",
                         "REQUEST_LOOKUP_UNAVAILABLE")
    if not request or request.get("event_type") != "RELEASE_REQUESTED":
        logger.warning("Release approval refused: unknown request")
        return _rejected(404, "unknown release request", "UNKNOWN_REQUEST")
    expires_at = _parse_iso(request.get("expires_at"))
    if expires_at is None or datetime.now(timezone.utc) > expires_at:
        logger.warning("Release approval refused: request %s expired", request_id)
        return _rejected(403, "release request has expired", "REQUEST_EXPIRED")

    channel = request.get("requested_by_channel")
    if (not channel or authorization.channel != channel
            or authorization.individual == request.get("requested_by_individual")
            or principal.arn == request.get("requested_by")):
        logger.warning("Release approval refused: approver %s is not a distinct individual "
                       "on the request's channel", principal.arn)
        return _rejected(403, "a second, distinct approver on the same identity channel is required",
                         "SECOND_APPROVER_REQUIRED")

    hold_event_id = request.get("hold_event_id")
    if get_status("live").get("status") != "GOVERNANCE_HOLD":
        logger.warning("Release approval refused: no active hold")
        return _rejected(409, "no active governance hold", "NO_ACTIVE_HOLD")
    state, rejection = _read_state_or_rejection("Release approval")
    if rejection:
        return rejection
    hold_generation = _valid_generation(request.get("hold_generation"))
    if (not state or state.get("status") != governance_state.HELD or hold_generation is None
            or _valid_generation(state.get("generation")) != hold_generation
            or not hold_event_id or state.get("hold_event_id") != hold_event_id):
        logger.warning("Release approval refused: request %s is for a hold that is no longer current",
                       request_id)
        return _rejected(409, "the request's hold is no longer the current hold; request again",
                         "STALE_REQUEST")
    blocked = _release_blockers(table, state)
    if blocked:
        return blocked

    try:
        table.put_item(
            Item={
                "event_id": f"release-approval#{request_id}",
                "event_type": "RELEASE_APPROVED",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "approved_by": principal.arn,
                "approved_by_individual": authorization.individual,
                "approved_by_channel": authorization.channel,
                "requested_by": request.get("requested_by"),
                "release_request_id": request_id,
                "hold_event_id": hold_event_id,
                "hold_generation": hold_generation,
                "retention_expires": RETENTION_EXPIRES,
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except Exception as e:  # noqa: BLE001
        if _is_conditional_failure(e):
            logger.warning("Release approval refused: request %s already approved", request_id)
            return _rejected(409, "release request already approved", "ALREADY_APPROVED")
        error_id = str(uuid.uuid4())
        logger.error("Release approval write failed [%s] (%s)", error_id, type(e).__name__)
        return _rejected(500, f"release approval could not be recorded (ref {error_id})",
                         "AUDIT_WRITE_FAILED")

    return _perform_release({
        "release_request_id": request_id,
        "requested_by": request.get("requested_by"),
        "approved_by": principal.arn,
        "hold_event_id": hold_event_id,
        "hold_generation": hold_generation,
    })


def _reattach_all(iam, deny_policy_arn):
    """Re-attach the deny-all to every agent role: (reattached, failures)."""
    reattached, failures = [], {}
    for role in AGENT_ROLES:
        try:
            iam.attach_role_policy(RoleName=role, PolicyArn=deny_policy_arn)
            reattached.append(role)
        except Exception as e:  # noqa: BLE001
            error_id = str(uuid.uuid4())
            logger.error("Re-attach of the deny policy to %s failed [%s] (%s)",
                         role, error_id, type(e).__name__)
            failures[role] = {"error_id": error_id, "error_class": _classify_aws_error(e)}
    return reattached, failures


def _perform_release(approval: dict) -> dict:
    """Detach the deny-all policy after an approved two-person release.

    1. GOVERNANCE_HOLD_RELEASED (with requested_by, approved_by,
       release_request_id, the prior hold and its generation) is written
       BEFORE any detach; the release aborts if it fails.
    2. governance_state.claim_release for exactly the approved generation
       and hold. A newer trip (SUPERSEDED), an already released generation
       or a missing item stops the release with nothing detached; an
       ambiguous error is resolved by one consistent re-read.
    3. Detach from every agent role.
    4. Consistent re-read of the state item plus the unclaimed-trip check.
    5. If a newer hold appeared, re-attach the deny-all to every role.
    6. Re-read the IAM state.
    7. GOVERNANCE_HOLD_RELEASE_COMPLETED records the per-role results, the
       final status, the hold seen afterwards and any re-attach.
    """
    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    approved_by = approval["approved_by"]
    hold_event_id = approval["hold_event_id"]
    generation = approval["hold_generation"]
    request_id = approval.get("release_request_id")
    if not write_governance_release_event(
            event_id, timestamp, approved_by, hold_event_id,
            requested_by=approval.get("requested_by"), approved_by=approved_by,
            release_request_id=request_id, hold_generation=generation):
        logger.error("Aborting release: governance audit write failed")
        return {
            "status": "GOVERNANCE_HOLD",
            "message": "Release aborted: could not write governance audit record.",
            "http_status": 500,
        }
    base = {
        "released_by": approved_by,
        "requested_by": approval.get("requested_by"),
        "approved_by": approved_by,
        "release_request_id": request_id,
        "release_event_id": event_id,
    }

    def complete(final_status, detached=(), failures=None, **extra):
        return write_release_completed_event(
            f"completed-{event_id}", datetime.now(timezone.utc).isoformat(), event_id, request_id,
            detached, failures or {}, final_status, **extra)

    def refused(code, http_status, message, completed, **extra):
        result = {"status": "GOVERNANCE_HOLD", "code": code, "http_status": http_status,
                  "message": message, **base, **extra}
        if not completed:
            result["audit_incomplete"] = True
        return result

    # 2. Claim exactly the approved generation.
    state_table = _state_table()
    try:
        claim = governance_state.claim_release(state_table, generation, hold_event_id, request_id,
                                               approved_by, datetime.now(timezone.utc).isoformat())
    except Exception as e:  # noqa: BLE001 - ambiguous: re-read once
        error_id = str(uuid.uuid4())
        logger.error("Release %s: governance-state claim failed [%s] (%s); re-reading",
                     request_id, error_id, type(e).__name__)
        try:
            state = governance_state.read(state_table)
        except Exception as read_error:  # noqa: BLE001
            logger.error("Release %s: governance-state re-read failed [%s] (%s); nothing detached",
                         request_id, error_id, type(read_error).__name__)
            return refused("STATE_UNAVAILABLE", 503,
                           f"governance state unavailable (ref {error_id}); nothing was detached",
                           complete("ABORTED", state_unverified=True))
        landed = (bool(state) and state.get("status") == governance_state.RELEASED
                  and _valid_generation(state.get("generation")) == generation
                  and state.get("release_request_id") == request_id)
        if not landed:
            logger.error("Release %s: governance-state claim did not land [%s]; nothing detached",
                         request_id, error_id)
            return refused("STATE_UNAVAILABLE", 503,
                           f"governance state unavailable (ref {error_id}); nothing was detached",
                           complete("ABORTED"))
        claim = governance_state.CLAIMED
    if claim == governance_state.SUPERSEDED:
        logger.warning("Release %s superseded before detach: a newer hold claimed the state",
                       request_id)
        completed = complete("SUPERSEDED")
        _emit_integrity_metric("ReleaseSuperseded", 1)
        return refused("RELEASE_SUPERSEDED", 409,
                       "A newer hold superseded this release; nothing was detached.", completed)
    if claim == governance_state.ALREADY_RELEASED:
        logger.warning("Release %s refused: this hold generation was already released", request_id)
        return refused("ALREADY_RELEASED", 409, "this hold was already released",
                       complete("ABORTED"))
    if claim == governance_state.ABSENT:
        logger.warning("Release %s refused: no governance-state item", request_id)
        return refused("HOLD_EVENT_UNKNOWN", 409, "no recorded hold state; re-trip, then release",
                       complete("ABORTED"))

    # 3. Detach.
    logger.info("Restoring agent roles (requested by %s, approved by %s)...",
                approval.get("requested_by"), approved_by)
    iam = boto3.client("iam", region_name=REGION)
    deny_policy_arn = resolve_deny_policy_arn()
    detached_roles = []
    detach_failures = {}
    for role in AGENT_ROLES:
        try:
            iam.detach_role_policy(RoleName=role, PolicyArn=deny_policy_arn)
            logger.info("Detached deny policy from %s", role)
            detached_roles.append(role)
        except Exception as e:
            # Log server-side with a generated error_id; never record
            # str(e) in the API response — same control as
            # the attach_failures map in invoke_circuit_breaker above, this
            # is the identical failure map shape on the detach side.
            error_id = str(uuid.uuid4())
            logger.error(
                "Failed to re-enable %s [%s]: %s", role, error_id, e, exc_info=True,
            )
            detach_failures[role] = {"error_id": error_id, "error_class": _classify_aws_error(e)}

    # 4. Did a newer hold appear? The state read decides; the index check
    # for an unclaimed trip only ever adds a re-attach (the sweep is its
    # backstop).
    state_after, read_failed = None, False
    try:
        state_after = governance_state.read(state_table)
    except Exception as e:  # noqa: BLE001
        read_failed = True
        logger.error("Release %s: post-detach governance-state read failed (%s)",
                     request_id, type(e).__name__)
    superseded = False
    if not read_failed:
        unclaimed = None
        if state_after:
            try:
                unclaimed = hold_sweep.unclaimed_hold(_governance_table(), state_after)
            except Exception as e:  # noqa: BLE001
                logger.error("Release %s: post-detach unclaimed-trip check failed (%s)",
                             request_id, type(e).__name__)
        superseded = (not state_after
                      or _valid_generation(state_after.get("generation")) != generation
                      or state_after.get("status") == governance_state.HELD
                      or unclaimed is not None)

    # 5. Restore the newer hold.
    roles_reattached, reattach_failures = [], {}
    if superseded:
        roles_reattached, reattach_failures = _reattach_all(iam, deny_policy_arn)
        logger.error(  # nosemgrep: logging-error-without-handling -- a detach raced a newer hold: ERROR is deliberate and alarmed via NewerHoldDetected
            "A newer hold superseded release %s during the detach; re-attached the deny policy "
            "to %d role(s)", request_id, len(roles_reattached))
        _emit_integrity_metric("NewerHoldDetected", 1)
        _emit_integrity_metric("ReleaseSuperseded", 1)

    # 6-7. Re-read IAM, record the outcome.
    final_status = "SUPERSEDED" if superseded else get_status("live").get("status", "UNKNOWN")
    if read_failed:
        _emit_integrity_metric("HoldStateReadFailed", 1)
    completed = complete(
        final_status, detached_roles, detach_failures,
        hold_event_id_after=(state_after or {}).get("hold_event_id"),
        hold_generation_after=_valid_generation((state_after or {}).get("generation")),
        roles_reattached=roles_reattached, reattach_failures=reattach_failures,
        state_unverified=read_failed)

    if superseded:
        message = "A newer hold superseded this release; the hold was restored."
        if reattach_failures:
            message = ("A newer hold superseded this release; re-attach failed on "
                       + ", ".join(reattach_failures) + "; the sweep will finish the re-attach. "
                       "Re-trip now.")
        return refused("RELEASE_SUPERSEDED", 409, message, completed,
                       newer_hold_detected=True, roles_reattached=roles_reattached,
                       reattach_failures=reattach_failures, roles_detached=detached_roles)

    # Report what actually happened, not a fixed success message
    # — a partial detach must be visible as such.
    if detach_failures:
        result = {
            "status": "GOVERNANCE_HOLD",
            "message": "Release incomplete: failed to detach deny policy from "
                        + ", ".join(detach_failures.keys()),
            "roles_restored": detached_roles,
            "detach_failures": detach_failures,
        }
    else:
        result = {
            "status": "ACTIVE",
            "message": "All agents re-enabled",
            "roles_restored": detached_roles,
        }
    result.update({**base, "http_status": 200})
    if read_failed:
        result["state_unverified"] = True
    if not completed:
        result["audit_incomplete"] = True
    return result


# === Local simulation (never reachable in Lambda; see _resolve_mode) ========

def _local_principal_ok(principal_id) -> bool:
    return isinstance(principal_id, str) and 0 < len(principal_id) <= 128


def request_release_local(principal_id) -> dict:
    """Local two-person release, step 1 (channel "local", individual =
    principal_id). Records the local hold's event_id on the request."""
    assert not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), (
        "request_release_local must never run inside the deployed Lambda"
    )
    if not _local_principal_ok(principal_id):
        return _rejected(403, "caller identity could not be verified")
    state = get_status("local")
    if state.get("status") != "GOVERNANCE_HOLD":
        return _rejected(409, "no active governance hold", "NO_ACTIVE_HOLD")
    if not state.get("event_id"):
        return _rejected(409, "no recorded hold event", "HOLD_EVENT_UNKNOWN")
    now = datetime.now(timezone.utc)
    request = {
        "release_request_id": str(uuid.uuid4()),
        "requested_by_individual": principal_id,
        "requested_by_channel": "local",
        "hold_event_id": state["event_id"],
        "timestamp": now.isoformat(),
        "expires_at": (now + timedelta(seconds=RELEASE_REQUEST_TTL_SECONDS)).isoformat(),
    }
    with open(RELEASE_REQUEST_FILE, "w", encoding="utf-8") as f:
        json.dump(request, f, indent=2)
    return {"status": "RELEASE_PENDING", "release_request_id": request["release_request_id"],
            "expires_at": request["expires_at"], "http_status": 202}


def approve_release_local(request_id, principal_id, now: datetime = None) -> dict:
    """Local two-person release, step 2: distinct individual, unexpired,
    and the request's hold is still the current local hold."""
    assert not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), (
        "approve_release_local must never run inside the deployed Lambda"
    )
    if not isinstance(request_id, str) or not RELEASE_REQUEST_ID_RE.fullmatch(request_id):
        return _rejected(400, "release_request_id is missing or malformed", "INVALID_REQUEST_ID")
    if not _local_principal_ok(principal_id):
        return _rejected(403, "caller identity could not be verified")
    try:
        with open(RELEASE_REQUEST_FILE, encoding="utf-8") as f:
            request = json.load(f)
    except (OSError, ValueError):
        request = None
    if not request or request.get("release_request_id") != request_id:
        return _rejected(404, "unknown release request", "UNKNOWN_REQUEST")
    expires_at = _parse_iso(request.get("expires_at"))
    if expires_at is None or (now or datetime.now(timezone.utc)) > expires_at:
        return _rejected(403, "release request has expired", "REQUEST_EXPIRED")
    if principal_id == request.get("requested_by_individual"):
        return _rejected(403, "a second, distinct approver is required", "SECOND_APPROVER_REQUIRED")
    state = get_status("local")
    if state.get("status") != "GOVERNANCE_HOLD":
        return _rejected(409, "no active governance hold", "NO_ACTIVE_HOLD")
    if state.get("event_id") != request.get("hold_event_id"):
        return _rejected(409, "the request's hold is no longer the current hold; request again",
                         "STALE_REQUEST")
    os.remove(RELEASE_REQUEST_FILE)
    result = re_enable(mode="local", releasing_principal=principal_id)
    result.update({"requested_by": request.get("requested_by_individual"),
                   "approved_by": principal_id, "release_request_id": request_id})
    return result


def re_enable(mode: str = "local", releasing_principal: str = "UNKNOWN"):
    """
    Local simulation only: clear the simulated hold (demos/demo_circuit_breaker.py
    and the local tests). It never touches IAM. A live release goes through
    request_release + approve_release on fsi-circuit-breaker-human.
    """
    if mode != "local":
        raise ValueError("live release requires approve_release")

    logger.info("Restoring agent roles (releasing principal: %s)...", releasing_principal)
    # Defense in depth: a simulated release must never run
    # inside the deployed Lambda — it would report "All agents
    # re-enabled" without ever calling detach_role_policy.
    assert not os.environ.get("AWS_LAMBDA_FUNCTION_NAME"), (
        "re_enable(mode='local') must never run inside the deployed Lambda"
    )
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)
        logger.info("State file removed — agents re-enabled")
    else:
        logger.info("No circuit breaker state found — already active")
    return {"status": "ACTIVE", "message": "All agents re-enabled (simulated)",
            "released_by": releasing_principal}


# === CLI Entry Point ===
def main():
    parser = argparse.ArgumentParser(description="Circuit Breaker — Automated Agent Disable")
    parser.add_argument("--local", action="store_true", help="Local mode (simulate)")
    parser.add_argument("--invoke", action="store_true", help="Invoke circuit breaker now")
    parser.add_argument("--status", action="store_true", help="Check current status")
    parser.add_argument("--re-enable", action="store_true",
                        help="Clear the simulated hold (local mode only)")
    parser.add_argument("--reason", type=str, default="Manual CLI invocation",
                        help="Trigger reason")
    args = parser.parse_args()

    mode = "local" if args.local else "live"

    if args.re_enable:
        if mode != "local":
            print("A live hold is released with make release-request / make release-approve "
                  "(two people), or the out-of-band runbook (docs/RUNBOOK_GOVERNANCE_HOLD.md).")
            return
        result = re_enable(mode, releasing_principal="local-cli")
    elif args.status:
        result = get_status(mode)
    elif args.invoke:
        result = invoke_circuit_breaker(reason=args.reason, mode=mode)
    else:
        # Default: check thresholds with sample metrics (dispute_rate breaches 0.51)
        sample_metrics = {
            "dispute_rate": 0.55,
            "guardrail_intervention_rate": 0.05,
            "detection_volume_multiplier": 1.2,
        }
        result = check_thresholds(sample_metrics, mode)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
