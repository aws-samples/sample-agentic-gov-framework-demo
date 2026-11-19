"""
Executor Agent — Routes compliance decisions to actions.

Reads compliance decisions and routes actions. Enforces separation of duties —
cannot re-open or modify decisions.

Routing:
- FILE_SAR → write SAR to filing output (S3 or local file)
- NEEDS_REVIEW → write to human analyst queue (SQS or local log)
- CIRCUIT_BREAKER → invoke circuit breaker handler

SOX Enforcement: Handler MUST NOT accept input that modifies detection or compliance
decisions. Override/approve/change signals are rejected and logged.

IAM Identity (NHI #3: executor-agent-role):
- CAN: Write to SAR filing (S3), write to analyst queue (SQS), write audit trail
- CANNOT: Read raw transactions, invoke Bedrock, modify detection or compliance records
  (the only compliance-decisions write is dynamodb:UpdateItem for the
  one-time-use replay lease attributes executor_processed / lease_expires_at
  and the per-cluster completion string set completed_clusters — IAM limits
  the writable attributes to COMPLIANCE_TABLE_WRITE_ATTRIBUTES)

Partial-failure retry: after each successful FILE_SAR / NEEDS_REVIEW
side effect the stored cluster_id's completion key (_completion_key —
the id itself, or a sha256 of its canonical form for any id that is not a
plain bounded string) is ADDed to completed_clusters under a
condition that this run still holds the lease. A retry after lease expiry
reads that set right after its claim and skips those clusters, so only the
failed actions are re-run. CIRCUIT_BREAKER is never skipped or recorded (a
re-trip is idempotent, so always re-running it never weakens containment).
A completion write that fails after a successful side effect fails closed:
the run is not finalized.
"""
import json
import logging
import os
import re
import sys
import uuid
import hashlib
import hmac
import argparse
import tempfile
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from decimal import Decimal

# governance_common ships at the zip root in a deployed runtime (already on
# sys.path via the shim); for local CLI runs it lives at the repo root.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.isdir(os.path.join(_PROJECT_ROOT, "governance_common")) and _PROJECT_ROOT not in sys.path:
    sys.path.append(_PROJECT_ROOT)
from governance_common.deployed_runtime import refuse_local_mode_in_deployed_runtime  # noqa: E402
from governance_common.pan_filter import contains_full_pan  # noqa: E402
from governance_common.payload_limits import request_ref_ok  # noqa: E402

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
REGION = os.environ.get("AWS_REGION", "us-east-1")
AUDIT_TABLE = os.environ.get("AUDIT_TABLE", "executor-audit")
# SAR filings are encrypted with the dedicated SAR CMK; set by
# the deploy script from the FsiComplianceData SarFilingsKeyArn output.
SAR_KMS_KEY_ARN = os.environ.get("SAR_KMS_KEY_ARN", "")

# Upper bound on clusters per request; the shim maps the
# PAYLOAD_TOO_LARGE refusal to 413. Checked before any AWS call.
MAX_CLUSTERS_PER_REQUEST = 100

_resolved_account_id = None  # lazily resolved — see _account_id() below


def _account_id() -> str:
    """Resolve and cache the current AWS account id (lazy — never called in
    local mode), used to pin ExpectedBucketOwner on the SAR filing write."""
    global _resolved_account_id
    if _resolved_account_id is None:
        _resolved_account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    return _resolved_account_id
COMPLIANCE_TABLE = os.environ.get("COMPLIANCE_TABLE", "compliance-decisions")
SAR_BUCKET = os.environ.get("SAR_BUCKET", "fsi-sar-filings")
ANALYST_QUEUE_URL = os.environ.get("ANALYST_QUEUE_URL", "")
def _resolve_local_output_dir() -> str:
    """LOCAL_OUTPUT_DIR env value if set; otherwise the repo cached_output dir,
    unless running in AgentCore/Lambda (/var/task present and the repo dir is
    read-only), where the platform temp dir is used. TMPDIR is unset there, so
    tempfile.gettempdir() resolves to /tmp — the only writable location."""
    configured = os.environ.get("LOCAL_OUTPUT_DIR", "")
    if configured:
        return configured
    default_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "cached_output"
    )
    if os.path.isdir("/var/task") and not os.access(default_dir, os.W_OK):
        return os.path.join(tempfile.gettempdir(), "cached_output")
    return default_dir


LOCAL_OUTPUT_DIR = _resolve_local_output_dir()

# ═════════════════════════════════════════════════════════════════════════════
# BLUEPRINT 3 — DELIBERATIVE CHALLENGE (separation of duties)
# ═════════════════════════════════════════════════════════════════════════════
# The executor may only ROUTE a decision (file / escalate / circuit breaker); it can
# never re-open, override, or approve one. Any attempt to smuggle an override
# signal into the input is detected here, rejected, and logged as a SOX
# violation. This enforces that a disputed/escalated case actually reaches a
# human — the challenger's DISPUTE cannot be quietly overridden downstream.
# ═════════════════════════════════════════════════════════════════════════════
# SOX: Forbidden override KEYS. This is a structured key denylist, matched
# against KEY NAMES at known locations in the request — never as substrings
# over serialized free text. A SAR narrative or challenger
# rationale that happens to contain a word like "approved" or "modified" is
# ordinary model prose and must not suppress the batch.
FORBIDDEN_KEYS = {
    "override", "override_decision", "approve", "force_approve",
    "change_decision", "modify", "modify_compliance", "reopen",
    "skip_review", "bypass", "cancel_sar",
}

# Allow-listed keys for the request envelope and for each assessed cluster.
# Any key outside these sets at the respective location is treated as an
# attempt to smuggle in an override signal.
ALLOWED_ENVELOPE_KEYS = {"mode", "compliance_output"}
ALLOWED_PAYLOAD_KEYS = {
    "compliance_id", "detection_id", "clusters_assessed", "timestamp",
    "provenance_status", "dispatch_token", "request_ref",
}
ALLOWED_CLUSTER_KEYS = {
    "cluster_id", "decision", "sar_narrative", "challenger_rationale",
    "challenger_opinion", "challenger_failed", "guardrail_triggered",
    "model_metadata",
}


def _classify_aws_error(e: Exception) -> str:
    """
    Coarse, non-sensitive error class for a failed AWS call —
    one of "AccessDenied", "Throttling", "ResourceNotFound", or "Unknown".
    Used instead of returning str(e) to a caller: a raw exception message
    can carry resource ARNs, bucket names, queue URLs, or other
    account-specific detail that should only ever reach server-side logs,
    never a result dict a caller receives.
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


def _emit_delivery_failure_metric(metric_name: str):
    """Emit a CloudWatch metric when a SAR filing or escalation fails to
    reach its durable destination, so a fail-closed outcome is visible to
    operators / alarms rather than silently swallowed."""
    try:
        cw = boto3.client("cloudwatch", region_name=REGION)
        cw.put_metric_data(
            Namespace="FSI/AgenticCompliance",
            MetricData=[{"MetricName": metric_name, "Value": 1, "Unit": "Count"}],
        )
    except Exception as e:  # metric emission must never mask the real failure
        logger.error("Failed to emit %s metric: %s", metric_name, e)


def _event_digest(event: dict) -> str:
    """Stable, cryptographic digest of the event for the audit record.

    Replaces Python's built-in hash() (per-process randomized, so it was
    useless as an integrity field) with SHA-256 over the
    canonical JSON encoding.
    """
    canonical = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# Literal that replaces a dispatch token before an event is digested.
# app/invoke_live._executor_event_for_digest applies the same
# literal at the same position, so the console can still recompute event_hash.
REDACTED_DISPATCH_TOKEN = "<redacted>"  # nosec B105 -- literal placeholder that replaces the token in output, not a credential


def _redact_dispatch_token(event: dict) -> dict:
    """Copy of `event` whose compliance_output.dispatch_token (if present) is
    replaced with REDACTED_DISPATCH_TOKEN, so the capability token never
    reaches an audit record or its digest."""
    compliance_output = event.get("compliance_output") if isinstance(event, dict) else None
    if not isinstance(compliance_output, dict) or "dispatch_token" not in compliance_output:
        return event
    redacted = dict(event)
    redacted["compliance_output"] = dict(compliance_output, dispatch_token=REDACTED_DISPATCH_TOKEN)
    return redacted


def _utc_day(ts) -> str:
    """UTC calendar day (YYYY-MM-DD) of an ISO-8601 timestamp, for the
    by_day_ts index. Naive values are taken as UTC; anything
    unparsable falls back to today's UTC date."""
    try:
        parsed = datetime.fromisoformat(str(ts))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.date().isoformat()
    except (TypeError, ValueError, OverflowError):
        return datetime.now(timezone.utc).date().isoformat()


def _console_request_ref(compliance_output) -> "str | None":
    """The console correlation ref carried inside compliance_output, only if
    well-formed and not PAN-shaped. Never used for authorization."""
    if not isinstance(compliance_output, dict):
        return None
    ref = compliance_output.get("request_ref")
    if request_ref_ok(ref):
        return ref
    return None


def _write_audit(record: dict, mode: str, console_request_ref=None):
    """Write one executor audit record to the mode's sink; raises on failure.
    Every record of a console-initiated run carries console_request_ref."""
    if console_request_ref:
        record.setdefault("console_request_ref", console_request_ref)
    if mode == "local":
        write_audit_record_local(record)
    else:
        write_audit_record(record)


def _audit_write_failed(what: str, mode: str, exc: Exception) -> str:
    """Log a failed audit write at ERROR with an error_id (exception class
    only) and emit the AuditWriteFailure metric in live mode. Returns the
    error_id."""
    error_id = str(uuid.uuid4())
    logger.error("Audit write FAILED (%s) [%s]: %s", what, error_id, type(exc).__name__)
    if mode != "local":
        _emit_delivery_failure_metric("AuditWriteFailure")
    return error_id


# violation_type is projected onto the executor-audit by_day_ts index and
# shown to operators: it holds only fixed text, field names, locations and
# cluster indices, never a caller-supplied key or value or a stored narrative.
MAX_VIOLATION_TYPE_CHARS = 256
VIOLATION_WITHHELD = "violation detail withheld"


def _safe_violation(text) -> str:
    """Bound a violation description to MAX_VIOLATION_TYPE_CHARS and
    withhold it entirely if it contains a full card number."""
    text = str(text)[:MAX_VIOLATION_TYPE_CHARS]
    if contains_full_pan(text):
        return VIOLATION_WITHHELD
    return text


def _safe_record_id(value) -> str:
    """A compliance_id / detection_id fit for an audit record: the value if
    it is a well-formed record id and not PAN-shaped, else "invalid"."""
    if _is_str_matching(value, _RECORD_ID_RE) and not contains_full_pan(value):
        return value
    return "invalid"


def _record_rejection(record: dict, mode: str, response: dict, console_request_ref=None) -> dict:
    """Write a rejection audit record (SOX / provenance / replay). The
    request stays rejected either way; a failed write adds
    audit_recorded: false to the response."""
    try:
        _write_audit(record, mode, console_request_ref)
    except Exception as e:
        _audit_write_failed(record.get("action_taken", "rejection"), mode, e)
        response["audit_recorded"] = False
    return response


def handler(event: dict, context=None) -> dict:
    """
    Lambda handler for executor agent.

    Args:
        event: Lambda event with keys: mode (live|local), compliance_output (dict)
        context: Lambda context object (None in local mode)

    Returns:
        Executor output dict with action records and provenance chain.
    """
    mode = event.get("mode", "local")

    # Defense in depth: even if a caller somehow
    # reaches this handler with mode="local" in a DEPLOYED runtime
    # (AgentCore extracts the package to /var/task), refuse it — mirrors
    # the identical guard in lambdas/detection_agent/handler.py. mode="local"
    # skips provenance verification (verify_provenance_chain) and the
    # one-time-use replay marking further down, and write_audit_record_local
    # writes to a local file rather than the durable audit table. Not
    # currently reachable (the HTTP shim pins mode server-side), but this
    # closes the same backstop gap the detection/compliance handlers already
    # have rather than leaving the executor as the one handler without it.
    # There is no override (governance_common.deployed_runtime).
    refuse_local_mode_in_deployed_runtime(mode)

    # === SOX ENFORCEMENT (envelope): reject override KEYS at the top level ===
    # This is a structured key check over the request envelope, not a
    # substring scan over free text. It catches an override
    # signal smuggled in as a top-level key before we even resolve the
    # payload; the resolved compliance_output is checked per-cluster below,
    # after the by-reference load, so a path-string payload can no longer
    # hide its contents from the gate.
    # Console correlation ref (validated form only); stored as
    # console_request_ref on every executor audit record of this run.
    request_ref = _console_request_ref(event.get("compliance_output"))

    sox_violation = check_sox_violation(event)
    if sox_violation:
        sox_violation = _safe_violation(sox_violation)
        action_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        violation_record = {
            "action_id": action_id,
            "timestamp": timestamp,
            "action_taken": "SOX_VIOLATION_REJECTED",
            "violation_type": sox_violation,
            # The dispatch token never reaches the digest.
            "event_hash": _event_digest(_redact_dispatch_token(event)),
        }
        logger.warning("SOX VIOLATION REJECTED: %s", sox_violation)
        return _record_rejection(violation_record, mode, {
            "error": "SOX_VIOLATION",
            "message": f"Executor cannot modify decisions. Violation: {sox_violation}",
            "action_id": action_id,
        }, request_ref)

    # Get compliance output. Only an inline dict is accepted — a string value
    # used to be treated as a filesystem path and opened, giving a caller a
    # path/errno oracle and an unbounded read, AND letting a by-reference
    # payload bypass the SOX gate. The CLI loads the
    # file itself and passes a dict, so by-reference input is only ever a
    # request-surface construct and is rejected here.
    compliance_output = event.get("compliance_output", {})
    if isinstance(compliance_output, str):
        raise ValueError(
            "compliance_output must be an inline object, not a file path"
        )

    # === SOX ENFORCEMENT (resolved payload): reject override KEYS inside the
    # resolved compliance_output / its clusters. Structured — a disallowed
    # KEY at a known location, never a denylisted word inside a SAR narrative
    # or challenger rationale (which previously caused whole-batch false
    # suppression).
    # Cluster cap, before any AWS call (including the SOX
    # rejection audit write) — the shim maps it to 413.
    if isinstance(compliance_output, dict):
        requested = compliance_output.get("clusters_assessed")
        if isinstance(requested, list) and len(requested) > MAX_CLUSTERS_PER_REQUEST:
            logger.info("Rejected executor request: %d clusters exceeds cap", len(requested))
            return {"error": "PAYLOAD_TOO_LARGE", "max_clusters": MAX_CLUSTERS_PER_REQUEST}

    payload_violation = check_sox_violation_payload(compliance_output)
    if payload_violation:
        payload_violation = _safe_violation(payload_violation)
        action_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        violation_record = {
            "action_id": action_id,
            "timestamp": timestamp,
            "action_taken": "SOX_VIOLATION_REJECTED",
            "violation_type": payload_violation,
            "event_hash": _event_digest(_redact_dispatch_token(event)),
        }
        logger.warning("SOX VIOLATION REJECTED (resolved payload): %s", payload_violation)
        return _record_rejection(violation_record, mode, {
            "error": "SOX_VIOLATION",
            "message": f"Executor cannot modify decisions. Violation: {payload_violation}",
            "action_id": action_id,
        }, request_ref)

    # Fail fast in a deployed runtime if the durable destinations are not
    # configured. Running live with an empty ANALYST_QUEUE_URL
    # (or the stale "fsi-sar-filings" SAR_BUCKET default) guaranteed the old
    # silent local-file fallback for every case; now that the fallback is
    # gone, an unconfigured destination is a misconfiguration to surface, not
    # to paper over.
    if mode != "local" and os.path.isdir("/var/task"):
        missing = []
        if not SAR_BUCKET or SAR_BUCKET == "fsi-sar-filings":
            missing.append("SAR_BUCKET")
        if not ANALYST_QUEUE_URL:
            missing.append("ANALYST_QUEUE_URL")
        if not SAR_KMS_KEY_ARN:
            missing.append("SAR_KMS_KEY_ARN")
        if missing:
            raise RuntimeError(
                "Executor cannot run live without durable destinations: "
                + ", ".join(missing) + " is not configured."
            )

    compliance_id = compliance_output.get("compliance_id", "unknown")
    detection_id = compliance_output.get("detection_id", "unknown")
    clusters_assessed = compliance_output.get("clusters_assessed", [])

    # === PROVENANCE CHECK ===
    # The executor must route from a RECORDED compliance decision, not from
    # whatever the caller asserts in compliance_output. In live mode, look up
    # compliance_id in compliance-decisions (the executor role holds
    # dynamodb:GetItem only — cdk/agents_stack.py) and reject the whole request if the
    # record is missing, if detection_id doesn't match, if the asserted
    # cluster_id set diverges (missing OR extra) from the stored set, or if
    # any asserted cluster's fields diverge from the stored record. On
    # success, routing below uses the STORED cluster objects, not the
    # caller-supplied dicts.
    # Local mode has no DynamoDB table to check against — it is the existing
    # no-AWS demo path (write_audit_record_local, etc.) and is left as-is.
    # Rejections and audit failures surface in the response, never silently.
    audit_incomplete = False

    if mode != "local":
        # Only a VERIFIED record presented with its dispatch token routes;
        # checked before the lease claim so a
        # squatter cannot take the lease.
        provenance_error, verified_clusters = verify_compliance_provenance(
            compliance_id, detection_id, clusters_assessed,
            dispatch_token=compliance_output.get("dispatch_token"),
        )
        if provenance_error:
            provenance_error = _safe_violation(provenance_error)
            action_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            violation_record = {
                "action_id": action_id,
                "timestamp": timestamp,
                "action_taken": "PROVENANCE_CHECK_FAILED",
                "violation_type": provenance_error,
                "compliance_id": _safe_record_id(compliance_id),
                "detection_id": _safe_record_id(detection_id),
            }
            logger.warning("PROVENANCE CHECK FAILED: %s", provenance_error)
            return _record_rejection(violation_record, mode, {
                "error": "PROVENANCE_CHECK_FAILED",
                "message": f"Executor will not route an unverified decision. {provenance_error}",
                "action_id": action_id,
            }, request_ref)
        # Route from the STORED cluster objects, not the caller-supplied
        # dicts — verify_compliance_provenance already proved every field
        # the caller asserted matches the stored record, but driving
        # routing off the stored objects directly means a
        # forged field can never reach SAR content or the analyst
        # escalation even if a future field is added to ALLOWED_CLUSTER_KEYS
        # without also being added to the provenance field check.
        clusters_assessed = verified_clusters

        # One-time-use CLAIM (a reclaimable lease): claim
        # compliance_id for processing BEFORE the routing loop runs, so a
        # second handler() invocation for the SAME compliance_id — even one
        # that perfectly matches the stored record — is rejected as a
        # replay rather than re-filing a SAR or re-tripping a resolved
        # decision a second time. Unlike the old permanent mark, this is a
        # reclaimable lease: the finalizing "permanently processed" mark
        # only happens AFTER every routed action below succeeds (see
        # finalize_compliance_id_processed call at the end of this
        # function) — a mid-routing failure leaves the lease to expire on
        # its own rather than permanently blocking every future retry.
        replay_error, lease_expires_at = claim_compliance_id_lease(compliance_id)
        if replay_error:
            replay_error = _safe_violation(replay_error)
            action_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            violation_record = {
                "action_id": action_id,
                "timestamp": timestamp,
                "action_taken": "PROVENANCE_CHECK_FAILED",
                "violation_type": "REPLAY_REJECTED",
                "compliance_id": _safe_record_id(compliance_id),
                "detection_id": _safe_record_id(detection_id),
            }
            logger.warning("PROVENANCE CHECK FAILED (replay): %s", replay_error)
            return _record_rejection(violation_record, mode, {
                "error": "PROVENANCE_CHECK_FAILED",
                "message": f"Executor will not route an unverified decision. {replay_error}",
                "action_id": action_id,
            }, request_ref)

        # Per-cluster completion state. Read AFTER the claim
        # lands (strongly consistent), so a previous holder whose lease we
        # just took over can no longer add to the set behind our back (its
        # conditional completion writes now fail). If the state cannot be
        # read, skip nothing: re-running proven work is preferred over
        # skipping unproven work.
        completed, completion_state_ok = load_completed_clusters(compliance_id)
        if not completion_state_ok:
            logger.error(
                "Completion state unavailable for compliance_id %s — no cluster "
                "will be skipped on this attempt", compliance_id,
            )
            try:
                _write_audit({
                    "action_id": str(uuid.uuid4()),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "action_taken": "COMPLETION_STATE_UNAVAILABLE",
                    "compliance_id": compliance_id,
                    "detection_id": detection_id,
                }, mode, request_ref)
            except Exception as e:
                # Nothing is skipped on this attempt, so routing stays safe;
                # the gap is surfaced in the response.
                _audit_write_failed("COMPLETION_STATE_UNAVAILABLE", mode, e)
                audit_incomplete = True
    else:
        # Local mode: no lease, no completion tracking, nothing skipped.
        completed = frozenset()
        lease_expires_at = None

    def _record_outcome(action_record: dict):
        """Write the outcome record for an action. A failure marks it
        outcome_recorded: false, which blocks finalize."""
        try:
            _write_audit(action_record, mode, request_ref)
        except Exception as e:
            _audit_write_failed(action_record.get("action_taken", "outcome"), mode, e)
            action_record["outcome_recorded"] = False

    # Process each cluster decision
    actions = []
    for cluster in clusters_assessed:
        decision = cluster.get("decision", "NEEDS_REVIEW")
        cluster_id = cluster.get("cluster_id", "unknown")
        completion_key = _completion_key(cluster.get("cluster_id"))

        action_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Skip a FILE_SAR / NEEDS_REVIEW cluster whose side effect a previous
        # attempt already completed AND recorded. Only the
        # STORED cluster_id is consulted (routing uses verified stored
        # clusters). CIRCUIT_BREAKER is deliberately never skipped.
        if (
            mode != "local"
            and decision in ("FILE_SAR", "NEEDS_REVIEW")
            and completion_key in completed
        ):
            action_record = {
                "action_id": action_id,
                "compliance_id": compliance_id,
                "detection_id": detection_id,
                "cluster_id": cluster_id,
                "timestamp": timestamp,
                "action_taken": ALREADY_COMPLETED,
                "decision_input": decision,
                "provenance_chain": f"{detection_id} -> {compliance_id} -> {action_id}",
                "result": {"status": "skipped_already_completed"},
            }
            actions.append(action_record)
            _record_outcome(action_record)
            continue

        # WRITE-AHEAD INTENT: no side effect without a prior
        # durable intent record. A failed intent write blocks FILE_SAR /
        # NEEDS_REVIEW (AUDIT_UNAVAILABLE, not a success, so the run is not
        # finalized and the lease expires for retry). CIRCUIT_BREAKER is the
        # fail-safe exception: containment proceeds, recorded as
        # intent_recorded: false.
        intent_recorded = True
        if mode != "local" and decision in ("FILE_SAR", "NEEDS_REVIEW", "CIRCUIT_BREAKER"):
            try:
                _write_audit({
                    "action_id": f"intent-{action_id}",
                    "record_day": _utc_day(timestamp),
                    "timestamp": timestamp,
                    "action_taken": "ACTION_INTENT",
                    "intended_action": decision,
                    "compliance_id": compliance_id,
                    "detection_id": detection_id,
                    "cluster_id": cluster_id,
                }, mode, request_ref)
            except Exception as e:
                intent_recorded = False
                error_id = _audit_write_failed("ACTION_INTENT", mode, e)
                if decision != "CIRCUIT_BREAKER":
                    action_record = {
                        "action_id": action_id,
                        "compliance_id": compliance_id,
                        "detection_id": detection_id,
                        "cluster_id": cluster_id,
                        "timestamp": timestamp,
                        "action_taken": "AUDIT_UNAVAILABLE",
                        "decision_input": decision,
                        "provenance_chain": f"{detection_id} -> {compliance_id} -> {action_id}",
                        "result": {"status": "AUDIT_UNAVAILABLE", "error_id": error_id},
                        "intent_recorded": False,
                    }
                    actions.append(action_record)
                    _record_outcome(action_record)
                    continue

        if decision == "FILE_SAR":
            action_result = execute_file_sar(cluster, mode)
            # action_taken reflects the ACTUAL delivery outcome, not the
            # decision — a FILING_FAILED result must not be recorded as FILED
            # in the audit trail or counted in total_filed.
            action_taken = "FILED" if action_result.get("status") != "FILING_FAILED" else "FILING_FAILED"
        elif decision == "NEEDS_REVIEW":
            action_result = execute_escalate(cluster, mode)
            action_taken = "ESCALATED" if action_result.get("status") != "ESCALATION_FAILED" else "ESCALATION_FAILED"
        elif decision == "CIRCUIT_BREAKER":
            # The kill switch must not be invocable by payload shape alone —
            # only a decision that was actually present in the stored
            # compliance record (verified above in live mode) may reach it.
            # A failed containment attempt must never be a silent, unaudited
            # abort of the whole run — catch it here, record
            # the attempt and the failure, then re-raise so the invocation
            # is still marked failed.
            try:
                action_result = execute_circuit_breaker(mode)
                action_taken = "CIRCUIT_BREAKER_INVOKED"
            except Exception as e:
                # WARNING: the bare `raise` below re-surfaces this to the
                # AgentCore entrypoint, which logs it at ERROR with an error_id.
                logger.warning("Circuit breaker invocation FAILED: %s", e)
                failure_record = {
                    "action_id": action_id,
                    "compliance_id": compliance_id,
                    "detection_id": detection_id,
                    "cluster_id": cluster_id,
                    "timestamp": timestamp,
                    "action_taken": "CIRCUIT_BREAKER_INVOCATION_FAILED",
                    "decision_input": decision,
                    "provenance_chain": f"{detection_id} -> {compliance_id} -> {action_id}",
                    "error": str(e),
                }
                if not intent_recorded:
                    failure_record["intent_recorded"] = False
                try:
                    _write_audit(failure_record, mode, request_ref)
                except Exception as audit_e:
                    # The invocation fails either way (re-raised below).
                    _audit_write_failed("CIRCUIT_BREAKER_INVOCATION_FAILED", mode, audit_e)
                raise
        else:
            action_result = {"error": f"Unknown decision: {decision}"}
            action_taken = "ERROR"

        # BLUEPRINT 2 — DECISION EXPLAINABILITY (end-to-end provenance)
        # Each action record links the action back through the compliance
        # decision to the original detection (detection_id -> compliance_id ->
        # action_id), recording which decision drove which action. This closes
        # the provenance chain so any filed SAR or escalation is fully traceable.
        action_record = {
            "action_id": action_id,
            "compliance_id": compliance_id,
            "detection_id": detection_id,
            "cluster_id": cluster_id,
            "timestamp": timestamp,
            "action_taken": action_taken,
            "decision_input": decision,
            "provenance_chain": f"{detection_id} -> {compliance_id} -> {action_id}",
            "result": action_result,
        }
        if not intent_recorded:
            action_record["intent_recorded"] = False

        # Record per-cluster completion right after a
        # successful FILE_SAR / NEEDS_REVIEW side effect, before the audit
        # write so completion_recorded is audited. Every stored cluster_id
        # has a recordable completion key, so only a failed
        # WRITE leaves a side effect unrecorded — and that fails closed:
        # the action stays truthfully FILED/ESCALATED but the run is not
        # finalized. CIRCUIT_BREAKER is never recorded.
        if mode != "local" and action_taken in ("FILED", "ESCALATED"):
            action_record["completion_recorded"] = record_cluster_completed(
                compliance_id, completion_key, lease_expires_at
            )

        actions.append(action_record)
        # Outcome record. Completion (above) is recorded before it, so a
        # retry after a failed outcome write skips this cluster and writes
        # ALREADY_COMPLETED: the trail converges.
        _record_outcome(action_record)

    # Finalize the processing claim — only reached once every
    # routed action above has completed without raising (the CIRCUIT_BREAKER
    # branch re-raises on a failed trip, which skips this call and leaves
    # the lease to expire so a genuine failure can be retried). This is what
    # makes the one-time-use guarantee permanent; a lease that never reaches
    # this point is reclaimable once it expires, not blocked forever.
    #
    # Execute_file_sar / execute_escalate report delivery failure
    # by RETURNING FILING_FAILED / ESCALATION_FAILED rather than raising, so
    # reaching this point does not by itself mean every action succeeded.
    # Finalize ONLY if every action record is a true success; otherwise leave
    # the lease to expire so an unfiled SAR / failed escalation can be retried.
    #
    # ALREADY_COMPLETED counts as success (proven and recorded by
    # an earlier attempt), but a side effect whose completion write failed
    # (completion_recorded is False) blocks finalize, so finalize means "all
    # actions succeeded and are recorded across attempts".
    #
    # An action whose outcome record could not be written
    # (outcome_recorded False) also blocks finalize.
    outcomes_missing = [a for a in actions if not a.get("outcome_recorded", True)]
    if outcomes_missing:
        audit_incomplete = True
    if mode != "local":
        unrecorded = [a for a in actions if a.get("completion_recorded") is False]
        if (
            all(a["action_taken"] in SUCCESS_ACTIONS for a in actions)
            and not unrecorded
            and not outcomes_missing
        ):
            finalize_compliance_id_processed(compliance_id)
        else:
            failed = sorted({
                a["action_taken"] for a in actions
                if a["action_taken"] not in SUCCESS_ACTIONS
            })
            logger.error(
                "Not finalizing compliance_id %s — action(s) did not succeed %s; "
                "%d completion write(s) failed; %d outcome record(s) missing; "
                "lease left to expire so the request can be retried",
                compliance_id, failed, len(unrecorded), len(outcomes_missing),
            )

    output = {
        "executor_run_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "compliance_id": compliance_id,
        "detection_id": detection_id,
        "actions": actions,
        "total_filed": sum(1 for a in actions if a["action_taken"] == "FILED"),
        "total_escalated": sum(1 for a in actions if a["action_taken"] == "ESCALATED"),
        "total_circuit_breaker": sum(1 for a in actions if a["action_taken"] == "CIRCUIT_BREAKER_INVOKED"),
        "total_already_completed": sum(1 for a in actions if a["action_taken"] == ALREADY_COMPLETED),
    }
    if audit_incomplete:
        output["audit_incomplete"] = True

    return output


def check_sox_violation(event: dict) -> str | None:
    """
    SOX enforcement (envelope): reject any forbidden override KEY at the top
    level of the request, or any top-level key outside the allow-list.

    Structured key matching only — never a substring scan over serialized
    free text, so model-authored prose inside compliance_output
    cannot trip this. The resolved compliance_output is checked separately by
    check_sox_violation_payload after the by-reference load.

    Args:
        event: The incoming request envelope to inspect.

    Returns:
        Violation description if found, None if clean.
    """
    for key in event.keys():
        lowered = str(key).lower()
        if lowered in FORBIDDEN_KEYS:
            return f"Forbidden override key '{lowered}' present in request envelope"
        if lowered not in ALLOWED_ENVELOPE_KEYS:
            return "Unexpected key in request envelope (not on allow-list)"

    return None


def check_sox_violation_payload(compliance_output) -> str | None:
    """
    SOX enforcement (resolved payload): inspect the RESOLVED compliance_output
    — the same document that drives routing — for forbidden override keys.

    Rejection is made on KEY NAMES at known locations, never on free-text
    values, so a SAR narrative or challenger rationale containing an ordinary
    word is never treated as an override. An unexpected key at
    the payload or cluster level is rejected as a smuggled override signal.

    Args:
        compliance_output: The resolved (dict) compliance output.

    Returns:
        Violation description if found, None if clean.
    """
    if not isinstance(compliance_output, dict):
        return None

    for key in compliance_output.keys():
        lowered = str(key).lower()
        if lowered in FORBIDDEN_KEYS:
            return f"Forbidden override key '{lowered}' present in compliance_output"
        if lowered not in ALLOWED_PAYLOAD_KEYS:
            return "Unexpected key in compliance_output (not on allow-list)"

    clusters = compliance_output.get("clusters_assessed", [])
    if isinstance(clusters, list):
        for index, cluster in enumerate(clusters):
            if not isinstance(cluster, dict):
                continue  # reported by the value rules below
            for key in cluster.keys():
                lowered = str(key).lower()
                if lowered in FORBIDDEN_KEYS:
                    return f"Forbidden override key '{lowered}' present in cluster index {index}"
                if lowered not in ALLOWED_CLUSTER_KEYS:
                    return f"Unexpected key in cluster index {index} (not on allow-list)"

    return _check_payload_values(compliance_output)


# SOX value rules. Violation messages name the field and
# the cluster index, never the offending value.
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9._#-]{1,128}")
_CLUSTER_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")  # as the compliance agent
DISPATCH_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_PROVENANCE_STATUSES = frozenset({"VERIFIED", "UNVERIFIED", "NOT_CHECKED"})
_DECISIONS = frozenset({"FILE_SAR", "NEEDS_REVIEW", "CIRCUIT_BREAKER"})
_CHALLENGER_OPINIONS = frozenset({"AGREE", "DISPUTE"})
MAX_TIMESTAMP_CHARS = 40
MAX_SAR_NARRATIVE_CHARS = 8000
MAX_CHALLENGER_RATIONALE_CHARS = 4000
MAX_MODEL_METADATA_DEPTH = 4


def _is_str_matching(value, pattern) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _model_metadata_violation(metadata) -> "str | None":
    """model_metadata must be a dict, nested at most MAX_MODEL_METADATA_DEPTH
    containers deep (itself = 1), with no FORBIDDEN_KEYS member as a key at
    any depth. Iterative, so hostile nesting cannot recurse."""
    if not isinstance(metadata, dict):
        return "must be an object"
    stack = [(metadata, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_MODEL_METADATA_DEPTH:
            return f"exceeds nesting depth {MAX_MODEL_METADATA_DEPTH}"
        if isinstance(node, dict):
            for key, child in node.items():
                if str(key).lower() in FORBIDDEN_KEYS:
                    return "contains a forbidden override key"
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
        else:
            for child in node:
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
    return None


def _check_payload_values(compliance_output: dict) -> "str | None":
    """Type/value rules for the allow-listed payload and cluster keys. Any
    violation is a SOX_VIOLATION; optional keys are checked only if present
    (dispatch_token presence is enforced by verify_compliance_provenance)."""
    def bad(field, where="compliance_output"):
        return f"Invalid value for field '{field}' in {where}"

    for field in ("compliance_id", "detection_id"):
        if field in compliance_output and not _is_str_matching(compliance_output[field], _RECORD_ID_RE):
            return bad(field)
    if "timestamp" in compliance_output:
        ts = compliance_output["timestamp"]
        if not isinstance(ts, str) or len(ts) > MAX_TIMESTAMP_CHARS:
            return bad("timestamp")
    if "provenance_status" in compliance_output and \
            compliance_output["provenance_status"] not in _PROVENANCE_STATUSES:
        return bad("provenance_status")
    if "dispatch_token" in compliance_output and \
            not _is_str_matching(compliance_output["dispatch_token"], DISPATCH_TOKEN_RE):
        return bad("dispatch_token")
    if "request_ref" in compliance_output and \
            not request_ref_ok(compliance_output["request_ref"]):
        return bad("request_ref")

    clusters = compliance_output.get("clusters_assessed", [])
    if not isinstance(clusters, list) or len(clusters) > MAX_CLUSTERS_PER_REQUEST:
        return bad("clusters_assessed")
    for index, cluster in enumerate(clusters):
        where = f"cluster index {index}"
        if not isinstance(cluster, dict):
            return f"clusters_assessed element at index {index} is not an object"
        if "cluster_id" in cluster and not _is_str_matching(cluster["cluster_id"], _CLUSTER_ID_RE):
            return bad("cluster_id", where)
        if "decision" in cluster and cluster["decision"] not in _DECISIONS:
            return bad("decision", where)
        if "challenger_opinion" in cluster and cluster["challenger_opinion"] not in _CHALLENGER_OPINIONS:
            return bad("challenger_opinion", where)
        for field in ("challenger_failed", "guardrail_triggered"):
            if field in cluster and not isinstance(cluster[field], bool):
                return bad(field, where)
        for field, limit in (("sar_narrative", MAX_SAR_NARRATIVE_CHARS),
                             ("challenger_rationale", MAX_CHALLENGER_RATIONALE_CHARS)):
            if field in cluster and (not isinstance(cluster[field], str) or len(cluster[field]) > limit):
                return bad(field, where)
        if "model_metadata" in cluster:
            problem = _model_metadata_violation(cluster["model_metadata"])
            if problem:
                return f"{bad('model_metadata', where)}: {problem}"
    return None


def verify_compliance_provenance(
    compliance_id: str, detection_id: str, clusters_assessed: list, *, dispatch_token
) -> "tuple[str | None, list | None]":
    """
    Look up compliance_id in the compliance-decisions table and verify the
    caller-asserted compliance_output actually matches the recorded run,
    instead of trusting the request body.

    Verification is COMPLETE, not partial:
      - The asserted cluster_id set must exactly equal the stored set — a
        caller can no longer omit a stored cluster (e.g. to suppress a
        CIRCUIT_BREAKER or NEEDS_REVIEW routing) and have the rest of the
        batch pass as "verified". Both missing AND extra cluster_ids fail
        the batch.
      - Every field on ALLOWED_CLUSTER_KEYS that the executor or its
        downstream sinks (SAR filing, analyst escalation) actually consumes
        is compared against the stored record, not just decision and
        sar_narrative — a caller can no longer forge challenger_rationale,
        challenger_opinion, guardrail_triggered, or model_metadata.

    Returns:
        (violation, verified_clusters) — violation is a description string
        if the record is missing, if detection_id doesn't match, if the
        asserted cluster_id set diverges from the stored set, or if any
        asserted cluster's fields diverge from the stored record; None if
        verified. verified_clusters is the list of STORED cluster objects
        (not the caller-supplied dicts) in the caller's original order, to
        be used by the routing loop — it is only meaningful when violation
        is None.

    Fixed check order: (1) lookup; (2) the stored
    record is provenance_status VERIFIED; (3) dispatch_token is well-formed
    and its sha256 matches the stored dispatch_token_sha256 (constant-time);
    (4) the detection_id and complete cluster checks below. dispatch_token
    is keyword-only with no default, so a caller that forgets it gets a
    TypeError rather than a skipped check. Error strings never contain the
    token or the stored hash.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(COMPLIANCE_TABLE)
        response = table.get_item(Key={"compliance_id": compliance_id}, ConsistentRead=True)
    except Exception as e:
        logger.error("Provenance lookup failed: %s", type(e).__name__)
        return "Could not verify compliance_id: lookup error", None

    record = response.get("Item")
    if not record:
        return "No stored compliance record for compliance_id", None

    if record.get("provenance_status") != "VERIFIED":
        return "compliance record is not provenance-verified", None

    stored_hash = record.get("dispatch_token_sha256")
    if not (
        _is_str_matching(dispatch_token, DISPATCH_TOKEN_RE)
        and _is_str_matching(stored_hash, _SHA256_HEX_RE)
        and hmac.compare_digest(
            hashlib.sha256(dispatch_token.encode("ascii")).hexdigest(), stored_hash
        )
    ):
        return "dispatch token invalid", None

    if record.get("detection_id") != detection_id:
        return "detection_id mismatch", None

    # Cluster ids are compared by their canonical completion key,
    # not raw value: a stored or asserted cluster_id may be
    # unhashable (dict/list) or of a type that would compare equal to a
    # different-typed id (True == 1). Keying by _completion_key keeps
    # duplicate / missing / extra detection exact for every value, and it is
    # the same key the completion set uses. Messages report asserted
    # indices or counts, never the ids themselves.
    stored_clusters = {
        _completion_key(c.get("cluster_id")): c
        for c in record.get("clusters_assessed", [])
    }
    stored_ids = set(stored_clusters.keys())
    asserted_ids = [_completion_key(c.get("cluster_id")) for c in clusters_assessed]
    asserted_id_set = set(asserted_ids)

    def _indexes(keys):
        return [i for i, cid in enumerate(asserted_ids) if cid in keys]

    # Reject a batch asserting the same cluster_id more than once
    # BEFORE the missing/extra-ids checks below — a caller
    # repeating one cluster_id could otherwise make len(asserted_ids) equal
    # len(stored_ids) while actually omitting a different stored cluster
    # (e.g. padding out a CIRCUIT_BREAKER omission with a duplicate of
    # another cluster_id), which the set-based missing/extra checks alone
    # would not catch since they only compare sets, not multiplicities.
    if len(asserted_ids) != len(asserted_id_set):
        duplicates = {cid for cid in asserted_ids if asserted_ids.count(cid) > 1}
        return (
            f"Batch contains duplicate cluster_id(s) at index(es) {_indexes(duplicates)} — the executor "
            "will not route a batch that asserts the same cluster_id more than once",
            None,
        )

    missing_ids = stored_ids - asserted_id_set
    if missing_ids:
        return (
            f"Batch omits {len(missing_ids)} stored cluster_id(s) — the executor "
            "will not route a partial batch that silently drops recorded clusters "
            "(e.g. to suppress CIRCUIT_BREAKER/NEEDS_REVIEW routing)",
            None,
        )

    extra_ids = asserted_id_set - stored_ids
    if extra_ids:
        return (
            f"Batch asserts cluster_id(s) at index(es) {_indexes(extra_ids)} not present in the "
            "stored compliance record",
            None,
        )

    # Fields that flow into routing, SAR content, or the analyst escalation
    # and must match the stored record exactly — not just decision and
    # sar_narrative.
    verified_fields = (
        "decision", "sar_narrative", "challenger_rationale",
        "challenger_opinion", "challenger_failed", "guardrail_triggered",
        "model_metadata",
    )

    for index, cluster in enumerate(clusters_assessed):
        stored = stored_clusters[asserted_ids[index]]
        for field in verified_fields:
            if stored.get(field) != cluster.get(field):
                return f"field mismatch for cluster index {index}: {field}", None

    # Drive routing from the STORED cluster objects, keyed off the
    # deduplicated stored id set — not the caller's raw
    # asserted_ids list — in the caller's first-occurrence order. Duplicates
    # are already rejected outright above, so this is defensive: it keeps
    # routing from the stored/deduplicated id set even if a future change
    # relaxes the hard duplicate rejection. The field-level check above
    # already proved every asserted cluster equals the stored record, but
    # routing off the stored object closes the class of gap entirely rather
    # than relying on every field staying on verified_fields forever.
    verified_clusters = [stored_clusters[cid] for cid in dict.fromkeys(asserted_ids)]

    return None, verified_clusters


EXECUTOR_LEASE_SECONDS = int(os.environ.get("EXECUTOR_LEASE_SECONDS", "300"))

# The only compliance-decisions attributes any executor UpdateItem touches
# (written OR evaluated in a condition), including the partition key. The
# CDK grant restricts dynamodb:Attributes to exactly this list;
# tests assert the synthesized policy matches it.
COMPLIANCE_TABLE_WRITE_ATTRIBUTES = (
    "compliance_id", "completed_clusters", "executor_processed", "lease_expires_at",
)

# action_taken for a cluster skipped because an earlier attempt already
# completed and recorded its side effect.
ALREADY_COMPLETED = "ALREADY_COMPLETED"

# A stored cluster_id is used verbatim as its completed_clusters member only
# if it is a plain, bounded, colon-free string (the shape every pipeline-
# generated id has: detection-agent uuid4s, "cluster-1", "c1"). Any other
# stored value — empty, non-string, over-long, unusual characters — maps to
# "sha256:" + a digest of a type-tagged canonical encoding, so
# every stored cluster_id is recordable. The two namespaces cannot collide:
# a verbatim key never contains ':', a hashed key always does.
_VERBATIM_COMPLETION_KEY_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
_HASHED_COMPLETION_KEY_PREFIX = "sha256:"

# action_taken values that count as a true success for finalizing the
# one-time-use claim. Anything else (FILING_FAILED,
# ESCALATION_FAILED, ERROR) leaves the lease to expire for retry.
# ALREADY_COMPLETED is a success proven by an earlier attempt.
SUCCESS_ACTIONS = frozenset({
    "FILED", "ESCALATED", "CIRCUIT_BREAKER_INVOKED", ALREADY_COMPLETED,
})


def _canonical_id_form(value):
    """Deterministic, type-tagged JSON-able form of a stored cluster_id.
    Tags keep distinct types distinct (int 1 vs str "1" vs
    True); numbers are tagged alike whether they arrive as int (request
    JSON) or Decimal (DynamoDB), matching how they compare equal. Sets and
    maps are sorted so the form never depends on iteration order (Python
    set order varies across processes)."""
    if value is None:
        return ["none"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, (int, float, Decimal)):
        # Normalized so 1, 1.0, Decimal("1") and Decimal("1.00") agree.
        number = Decimal(repr(value)) if isinstance(value, float) else Decimal(value)
        return ["num", str(number.normalize()) if number.is_finite() else str(number)]
    if isinstance(value, (bytes, bytearray)):
        return ["bytes", bytes(value).hex()]
    if isinstance(value, (list, tuple)):
        return ["list", [_canonical_id_form(v) for v in value]]
    if isinstance(value, (set, frozenset)):
        members = [_canonical_id_form(v) for v in value]
        return ["set", sorted(members, key=lambda m: json.dumps(m, sort_keys=True))]
    if isinstance(value, dict):
        pairs = [[_canonical_id_form(k), _canonical_id_form(v)] for k, v in value.items()]
        return ["map", sorted(pairs, key=lambda p: json.dumps(p, sort_keys=True))]
    return ["other", type(value).__name__, repr(value)]


def _completion_key(cluster_id) -> str:
    """The completed_clusters member for a stored cluster_id.
    Always a non-empty bounded string, so every stored value —
    including empty, non-string, or over-long ids — is recordable and a
    successful side effect can always be marked complete. Distinct ids map
    to distinct keys (see _VERBATIM_COMPLETION_KEY_RE). Also used to key
    cluster ids in verify_compliance_provenance, so duplicate / missing /
    extra detection works for unhashable stored ids too."""
    if isinstance(cluster_id, str) and _VERBATIM_COMPLETION_KEY_RE.fullmatch(cluster_id):
        return cluster_id
    canonical = json.dumps(
        _canonical_id_form(cluster_id), sort_keys=True, separators=(",", ":")
    )
    return _HASHED_COMPLETION_KEY_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_completed_clusters(compliance_id: str) -> "tuple[frozenset, bool]":
    """
    Read the per-cluster completion set for compliance_id.
    Strongly consistent, projected to completed_clusters only. Called right
    after a successful lease claim.

    Returns (ids, True) on success (an absent attribute is an empty set) and
    (frozenset(), False) on any read error or malformed value — the caller
    then skips nothing.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(COMPLIANCE_TABLE)
        response = table.get_item(
            Key={"compliance_id": compliance_id},
            ConsistentRead=True,
            ProjectionExpression="completed_clusters",
        )
    except Exception as e:
        logger.error(
            "Completion state read failed for compliance_id %s (%s)",
            compliance_id, type(e).__name__,
        )
        return frozenset(), False

    item = response.get("Item") if isinstance(response, dict) else None
    if not item or "completed_clusters" not in item:
        return frozenset(), True
    value = item["completed_clusters"]
    if isinstance(value, (set, frozenset, list)) and all(isinstance(v, str) for v in value):
        return frozenset(value), True
    logger.error(
        "Malformed completed_clusters for compliance_id %s (type %s)",
        compliance_id, type(value).__name__,
    )
    return frozenset(), False


def record_cluster_completed(compliance_id: str, cluster_key: str, lease_expires_at) -> bool:
    """
    ADD cluster_key to completed_clusters, conditional on this
    run still holding the lease (executor_processed IN_PROGRESS with the
    exact lease_expires_at value this run's claim wrote). Lease values are
    strictly increasing across claims, so a run whose lease was taken over
    cannot record completion, and the condition can never create a new item.

    Returns True if recorded, False on any failure (never raises, never
    returns exception text).
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(COMPLIANCE_TABLE)
        table.update_item(
            Key={"compliance_id": compliance_id},
            UpdateExpression="ADD completed_clusters :cid",
            ConditionExpression=(
                "executor_processed = :in_progress AND lease_expires_at = :lease"
            ),
            ExpressionAttributeValues={
                ":cid": {cluster_key},
                ":in_progress": "IN_PROGRESS",
                ":lease": lease_expires_at,
            },
        )
    except Exception as e:
        code = ""
        response = getattr(e, "response", None)
        if isinstance(response, dict):
            code = response.get("Error", {}).get("Code", "")
        logger.error(
            "Completion write FAILED for compliance_id %s cluster %s (%s%s) — "
            "side effect already executed; run will not be finalized",
            compliance_id, cluster_key, type(e).__name__,
            f"/{code}" if code else "",
        )
        return False
    return True


def claim_compliance_id_for_processing(compliance_id: str) -> "str | None":
    """Backward-compatible wrapper around claim_compliance_id_lease() that
    returns only the error (None on success)."""
    error, _ = claim_compliance_id_lease(compliance_id)
    return error


def claim_compliance_id_lease(compliance_id: str) -> "tuple[str | None, int | None]":
    """
    One-time-use CLAIM for compliance_id (a reclaimable lease):
    a conditional DynamoDB update that sets executor_processed="IN_PROGRESS"
    with a lease_expires_at timestamp, and FAILS
    (ConditionalCheckFailedException) if the compliance_id is already
    permanently processed ("DONE") or already has an UNEXPIRED in-progress
    lease from another run. This closes a replay gap that
    verify_compliance_provenance alone does not: a compliance record that
    matches the stored record perfectly is still a replay if the SAME
    compliance_id has already been executed (e.g. re-filing the same SAR,
    or re-tripping a resolved CIRCUIT_BREAKER decision a second time).

    This is a CLAIM, not a completion. The original version of this
    function set a permanent "already processed" flag BEFORE the routing
    loop ran at all (see handler() below); if routing then failed partway
    through (a transient SQS/S3 error, a mid-batch exception), the
    compliance_id was left permanently marked processed with no reset
    path — containment/SAR filing never actually happened, and every
    retry (including Lambda's own automatic retries) was rejected as a
    replay forever. The lease here is reclaimable: once
    EXECUTOR_LEASE_SECONDS elapses with the run never having called
    finalize_compliance_id_processed(), a fresh invocation's claim
    attempt is allowed to proceed again, because the condition expression
    below treats an expired lease the same as "never claimed."

    Must be called BEFORE the routing loop runs, and only in live mode —
    there is no DynamoDB table in local mode, consistent with how
    verify_compliance_provenance itself is skipped there.

    Returns:
        (None, lease_expires_at) on success — the compliance_id now holds
        this run's lease, and lease_expires_at (int epoch seconds, strictly
        increasing across successful claims) is this run's lease token for
        record_cluster_completed; (violation, None) if it is
        already permanently processed or another run's lease has not yet
        expired.
    """
    # Integer epoch seconds, never float: the boto3 DynamoDB
    # RESOURCE API rejects Python floats in ExpressionAttributeValues with a
    # TypeError ("Float types are not supported"), which previously crashed
    # every live invocation before routing (including CIRCUIT_BREAKER).
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    lease_expires_at = now_epoch + EXECUTOR_LEASE_SECONDS
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(COMPLIANCE_TABLE)
        table.update_item(
            Key={"compliance_id": compliance_id},
            UpdateExpression=(
                "SET executor_processed = :in_progress, lease_expires_at = :lease_expires_at"
            ),
            ConditionExpression=(
                "attribute_not_exists(executor_processed) "
                "OR executor_processed = :false "
                "OR (executor_processed = :in_progress AND lease_expires_at < :now) "
            ),
            ExpressionAttributeValues={
                ":in_progress": "IN_PROGRESS",
                ":false": False,
                ":now": now_epoch,
                ":lease_expires_at": lease_expires_at,
            },
        )
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return (
                "compliance_id has already been processed (or is currently being "
                "processed by another run) by the executor — replay rejected"
            ), None
        logger.error(
            "Processing claim failed: %s (%s)",
            type(e).__name__, e.response.get("Error", {}).get("Code", "unknown"),
        )
        return "Could not claim compliance_id for processing: lookup error", None
    except Exception as e:
        # Any non-ClientError (e.g. a serialization TypeError)
        # becomes an audited PROVENANCE_CHECK_FAILED, not an unhandled crash.
        # Still fails closed: no lease is held, so nothing is routed.
        logger.error("Processing claim failed: %s", type(e).__name__)
        return "Could not claim compliance_id for processing: lookup error", None
    return None, lease_expires_at


def finalize_compliance_id_processed(compliance_id: str) -> None:
    """
    Finalize the claim taken by claim_compliance_id_for_processing() as
    permanently processed — called ONLY after every routed
    action in the batch has completed without raising. This is what
    actually makes the one-time-use guarantee permanent; until this call
    succeeds, a claimed-but-unfinished run is still reclaimable once its
    lease expires, so a genuinely failed run (not just a replay of an
    already-completed one) can be retried.

    A failure to write this finalization is logged but not raised: the
    routed actions have already executed and been audited at this point,
    so this call failing only means the lease will eventually expire and
    a subsequent identical request could be re-routed — a reclaimed lease
    after a successful run is a lesser risk than raising here and
    potentially masking the fact that the actions already ran. Such a
    retry still skips every cluster recorded in completed_clusters,
    which is left on the item after finalize as an audit trail.
    """
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(COMPLIANCE_TABLE)
        table.update_item(
            Key={"compliance_id": compliance_id},
            UpdateExpression="SET executor_processed = :done REMOVE lease_expires_at",
            ExpressionAttributeValues={":done": True},
        )
    except Exception as e:
        logger.error(
            "Could not finalize compliance_id %s as processed (actions already "
            "executed) — the lease will expire and a retry could be re-routed: %s",
            compliance_id, e,
        )


def execute_file_sar(cluster: dict, mode: str) -> dict:
    """Route FILE_SAR decision to SAR filing system."""
    sar_content = {
        "cluster_id": cluster.get("cluster_id"),
        "sar_narrative": cluster.get("sar_narrative", ""),
        "filed_at": datetime.now(timezone.utc).isoformat(),
        "filing_type": "BSA/FinCEN_SAR",
    }

    if mode == "local":
        # Write to local file
        filepath = os.path.join(LOCAL_OUTPUT_DIR, f"sar_filed_{cluster.get('cluster_id', 'unknown')[:8]}.json")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(sar_content, f, indent=2)
        logger.info("SAR filed to %s", filepath)
        return {"destination": filepath, "status": "filed_locally"}
    else:
        # Write to S3. A failure must FAIL CLOSED — the old code silently
        # wrote the SAR to a plaintext local file and still reported it as
        # FILED, so the audit trail and API response both claimed a filing
        # that never reached the durable, encrypted store. A
        # BSA/FinCEN SAR that could not be filed is a FILING_FAILED outcome,
        # not a success.
        try:
            s3 = boto3.client("s3", region_name=REGION)
            key = f"filings/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{cluster.get('cluster_id')}.json"
            # ExpectedBucketOwner: fail the write rather than
            # silently filing a confidential SAR narrative to a
            # same-account bucket that happens to share the configured name
            # but isn't the one this account's deploy actually owns.
            # SSE-KMS with the dedicated SAR filings CMK: only
            # fsi-compliance-reader can decrypt a filing.
            put_kwargs = {"ServerSideEncryption": "aws:kms"}
            if SAR_KMS_KEY_ARN:
                put_kwargs["SSEKMSKeyId"] = SAR_KMS_KEY_ARN
            s3.put_object(
                Bucket=SAR_BUCKET,
                Key=key,
                Body=json.dumps(sar_content),
                ContentType="application/json",
                ExpectedBucketOwner=_account_id(),
                **put_kwargs,
            )
            return {"destination": f"s3://{SAR_BUCKET}/{key}", "status": "filed"}
        except Exception as e:
            # Log server-side with a generated error_id; never return
            # str(e) to the caller — a raw S3 exception can
            # carry the bucket name/ARN or other account-specific detail.
            # Reuses the error_id + exc_info=True logging shape already
            # established in agentcore/executor_agent/main.py for this same "never return raw exception text"
            # control.
            error_id = str(uuid.uuid4())
            logger.error(
                "S3 SAR write FAILED for cluster %s [%s]: %s",
                cluster.get("cluster_id"), error_id, e, exc_info=True,
            )
            _emit_delivery_failure_metric("SarFilingFailure")
            return {
                "destination": None,
                "status": "FILING_FAILED",
                "error_id": error_id,
                "error_class": _classify_aws_error(e),
            }


def execute_escalate(cluster: dict, mode: str) -> dict:
    """Route NEEDS_REVIEW decision to human analyst queue."""
    escalation = {
        "cluster_id": cluster.get("cluster_id"),
        "reason": cluster.get("challenger_rationale", "Requires human review"),
        "decision": cluster.get("decision"),
        "guardrail_triggered": cluster.get("guardrail_triggered", False),
        "escalated_at": datetime.now(timezone.utc).isoformat(),
    }

    if mode == "local":
        filepath = os.path.join(LOCAL_OUTPUT_DIR, f"escalation_{cluster.get('cluster_id', 'unknown')[:8]}.json")
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(escalation, f, indent=2)
        logger.info("Escalation written to %s", filepath)
        return {"destination": filepath, "status": "escalated_locally"}
    else:
        # Write to SQS. Fail CLOSED on error rather than silently spilling AML
        # case detail to a plaintext local file and reporting it as ESCALATED
        # — an escalation that never reached the analyst queue
        # has not been escalated.
        try:
            sqs = boto3.client("sqs", region_name=REGION)
            sqs.send_message(
                QueueUrl=ANALYST_QUEUE_URL,
                MessageBody=json.dumps(escalation),
            )
            return {"destination": ANALYST_QUEUE_URL, "status": "escalated"}
        except Exception as e:
            # Log server-side with a generated error_id; never return
            # str(e) to the caller — a raw SQS exception can
            # carry the queue URL/ARN or other account-specific detail.
            error_id = str(uuid.uuid4())
            logger.error(
                "SQS escalation FAILED for cluster %s [%s]: %s",
                cluster.get("cluster_id"), error_id, e, exc_info=True,
            )
            _emit_delivery_failure_metric("EscalationFailure")
            return {
                "destination": None,
                "status": "ESCALATION_FAILED",
                "error_id": error_id,
                "error_class": _classify_aws_error(e),
            }


def execute_circuit_breaker(mode: str) -> dict:
    """Invoke circuit breaker handler.

    Live mode invokes the deployed circuit-breaker Lambda via boto3 rather
    than importing its module by path. The old path-arithmetic
    import (`sys.path.insert` + `from handler import ...`) could never
    resolve in a deployed AgentCore package — circuit_breaker/ is not
    bundled into the executor's zip — and even if it were, the name
    collides with sys.modules['handler'], which the AgentCore wrapper has
    already registered as the executor's OWN handler module, so the import
    silently returned the wrong module. Either way the call raised and
    aborted the whole run with no audit record of the attempted trip.
    """
    if mode == "local":
        logger.info("CIRCUIT BREAKER invoked (simulated)")
        return {"status": "circuit_breaker_simulated"}
    else:
        function_name = os.environ.get("CIRCUIT_BREAKER_FUNCTION", "")
        if not function_name:
            raise RuntimeError(
                "Cannot invoke circuit breaker: CIRCUIT_BREAKER_FUNCTION is not configured."
            )
        lambda_client = boto3.client("lambda", region_name=REGION)
        # action=="auto_trip": a SEPARATE, IAM-principal-based
        # authorization path from the human break-glass action=="invoke"
        # dispatch — the executor is a known automated SERVICE caller
        # (already scoped to invoke exactly this function via IAM, see
        # cdk/agents_stack.py), never a human break-glass operator, so its
        # trip goes to the automated entry point (BREAKER_ENTRY=automated),
        # never through the human identity-proof channel.
        # trip_source is a fixed code the breaker resolves against its own
        # KNOWN_AUTOMATED_TRIP_SOURCES enum, never free caller text.
        payload = json.dumps({
            "action": "auto_trip",
            "mode": "live",
            "trip_source": "EXECUTOR_CONTAINMENT",
        }).encode("utf-8")
        response = lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=payload,
        )
        result_payload = response["Payload"].read()
        result = json.loads(result_payload) if result_payload else {}
        # A REJECTED/non-2xx-equivalent breaker response must never be
        # treated as a successful trip — the old code only
        # checked response["FunctionError"] (never set here, since the
        # breaker returns a normal body, not a Lambda function error) and
        # let any REJECTED body fall through as if the trip had succeeded,
        # which the caller then recorded as CIRCUIT_BREAKER_INVOKED.
        if response.get("FunctionError"):
            raise RuntimeError(
                f"Circuit breaker invocation failed: {result.get('errorMessage', result)}"
            )
        # A successful trip always reports status=="GOVERNANCE_HOLD" (with
        # http_status 503 by design — see invoke_circuit_breaker). Anything
        # else — REJECTED (403/400 from the auto_trip authorization checks),
        # or any other unexpected shape — must never be treated as success.
        if result.get("status") != "GOVERNANCE_HOLD":
            raise RuntimeError(
                f"Circuit breaker invocation was not authorized/successful: {result}"
            )
        return result


def write_audit_record(record: dict):
    """Write action record to DynamoDB audit trail. Every record carries
    record_day (UTC day of its timestamp) so it lands in by_day_ts."""
    record.setdefault("record_day", _utc_day(record.get("timestamp")))
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(AUDIT_TABLE)
        from decimal import Decimal
        item = json.loads(json.dumps(record), parse_float=Decimal)
        table.put_item(Item=item)
    except Exception as e:
        # WARNING: re-raised (fail-closed); the caller logs it at ERROR.
        logger.warning("Failed to write to DynamoDB: %s", e)
        raise


# Local audit sink — mirrors the executor-audit DynamoDB table for local mode.
LOCAL_AUDIT_FILE = os.path.join(LOCAL_OUTPUT_DIR, "executor_audit.jsonl")


def write_audit_record_local(record: dict):
    """Append the full audit record to a local JSONL sink (local-mode equivalent
    of the executor-audit DynamoDB table).

    Writes the exact same record dict that live mode persists to DynamoDB, so
    the local audit trail carries identical detail (action_id, compliance_id,
    detection_id, cluster_id, timestamp, action_taken, decision_input,
    provenance_chain, result). One JSON object per line, newest appended last.
    Same record_day default as write_audit_record, so both sinks share one
    record shape.
    """
    record.setdefault("record_day", _utc_day(record.get("timestamp")))
    try:
        os.makedirs(os.path.dirname(LOCAL_AUDIT_FILE), exist_ok=True)
        with open(LOCAL_AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")
        logger.info("Audit record %s written to %s", record.get("action_id"), LOCAL_AUDIT_FILE)
    except Exception as e:
        # WARNING: re-raised (fail-closed); the caller logs it at ERROR.
        logger.warning("Failed to write local audit record: %s", e)
        raise


# === CLI Entry Point ===
def main():
    parser = argparse.ArgumentParser(description="Executor Agent — Route compliance decisions")
    parser.add_argument("--local", action="store_true", help="Local mode (write to files, not AWS)")
    parser.add_argument("--compliance-file", type=str, default=None,
                        help="Path to compliance agent output JSON")
    parser.add_argument("--output", type=str, default=None,
                        help="Write output to file (default: stdout)")
    args = parser.parse_args()

    mode = "local" if args.local else "live"

    if args.compliance_file:
        with open(args.compliance_file, "r", encoding="utf-8") as f:
            compliance_output = json.load(f)
    else:
        # Use cached compliance result
        cached_path = os.path.join(LOCAL_OUTPUT_DIR, "compliance_result.json")
        if os.path.exists(cached_path):
            with open(cached_path, "r", encoding="utf-8") as f:
                compliance_output = json.load(f)
        else:
            compliance_output = {"compliance_id": "demo", "detection_id": "demo", "clusters_assessed": []}

    event = {"mode": mode, "compliance_output": compliance_output}
    result = handler(event)

    output_json = json.dumps(result, indent=2, default=str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        logger.info("Written to %s", args.output)
    else:
        print(output_json)

    return result


if __name__ == "__main__":
    main()
