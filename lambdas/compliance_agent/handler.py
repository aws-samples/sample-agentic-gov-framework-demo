"""
Compliance Reasoner Agent — SAR Generation + Independent Challenger.

Takes detection output, generates SAR narrative via Bedrock, independently
challenges the detection, and decides whether to auto-file or escalate.

Pipeline:
1. Read flagged clusters from detection agent output
2. Enrich each cluster
3. SAR Generation (Bedrock call #1) — guardrail-enforced
4. Independent Challenger (Bedrock call #2) — genuinely different methodology
5. Divergence logic → FILE_SAR or NEEDS_REVIEW
6. Full audit record to DynamoDB

IAM Identity (NHI #2: compliance-agent-role):
- CAN: Invoke Bedrock (with guardrail), read detection-results table, write compliance-decisions table
- CANNOT: Write to SAR filing system, modify detection results, disable agents
"""
import json
import logging
import os
import re
import sys
import time
import uuid
import hashlib
import secrets
import argparse
import boto3
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sar_prompts import (
    enrich_cluster, build_sar_prompt_segments, build_challenger_prompt_segments,
    join_prompt_segments, get_prompt_fingerprint, SAR_SYSTEM_PROMPT,
    CHALLENGER_SYSTEM_PROMPT, TRUSTED, UNTRUSTED
)
from output_schema import validate_model_output
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import model_assurance
from model_assurance import validate_model
from governance_common import signing
from governance_common.deployed_runtime import refuse_local_mode_in_deployed_runtime
from governance_common.payload_limits import request_ref_ok


class ComplianceAuditWriteError(RuntimeError):
    """The durable compliance-decisions write failed. The
    handler lets it propagate, so no un-audited decision is ever returned."""


class DuplicateDecisionError(RuntimeError):
    """A decision already exists for this detection: the
    single-decision marker's condition failed inside the transaction."""


class UnapprovedModelError(RuntimeError):
    """Raised when a model_id is not on the approved-models registry
    (data/approved_models.json). No SAR or challenger call may reach
    Bedrock with a model that has not been through model-risk review."""


# Configuration
REGION = os.environ.get("AWS_REGION", "us-east-1")
# No insecure literal default: an unset BEDROCK_MODEL_ID/CHALLENGER_MODEL_ID
# must fail fast rather than silently falling back to an unapproved model
# (the previous default, us.meta.llama3-3-70b-instruct-v1:0, is not on
# data/approved_models.json). validate_model() below is the actual
# enforcement point; this just removes the unapproved fallback literal.
MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "")
# Independent challenger runs on a DIFFERENT model family from the champion so
# effective challenge is at the model level, not just the prompt (SR 11-7).
CHALLENGER_MODEL_ID = os.environ.get("CHALLENGER_MODEL_ID", "")
GUARDRAIL_ID = os.environ.get("GUARDRAIL_ID", "")
# No "DRAFT" default: DRAFT is the mutable, unpublished
# guardrail version — defaulting to it meant an unset GUARDRAIL_VERSION
# silently deployed against a guardrail configuration that can change out
# from under a live deploy with no version pin at all. An unset value must
# fail closed through invoke_bedrock's own GuardrailNotConfiguredError
# check below, the same way an unset GUARDRAIL_ID already does.
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "")
COMPLIANCE_TABLE = os.environ.get("COMPLIANCE_TABLE", "compliance-decisions")
# Detection provenance root: compliance assesses the STORED
# detection clusters, never the caller's copy.
DETECTION_TABLE = os.environ.get("DETECTION_TABLE", "detection-results")
# Each cluster costs two Bedrock calls; bound the per-request work.
# Checked before any AWS client is built.
MAX_CLUSTERS_PER_REQUEST = 25
DETECTION_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
# Provenance status of a run:
#   VERIFIED    durable run, caller clusters match the stored detection
#   UNVERIFIED  durable run, no stored detection, ALLOW_UNVERIFIED_EVALUATION
#               on: evaluation only (all NEEDS_REVIEW, no drift, no token)
#   NOT_CHECKED non-durable run (local dev, tests, in-process console)
VERIFIED, UNVERIFIED, NOT_CHECKED = "VERIFIED", "UNVERIFIED", "NOT_CHECKED"
ALLOWED_DECISIONS = frozenset({"FILE_SAR", "NEEDS_REVIEW"})
# Fields of a caller cluster that reach enrichment / the prompt and must
# equal the stored detection values.
PROVENANCE_FIELDS = (
    "accounts", "account_count", "typology", "total_amount_usd",
    "time_span_seconds", "merchant_categories", "confidence_factors",
)
# input_quality gate: above this schema-rejection share the
# whole run is forced to NEEDS_REVIEW.
MAX_SCHEMA_REJECTED_SHARE = 0.10

CACHED_OUTPUT_PATH = os.environ.get(
    "CACHED_OUTPUT_PATH",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "cached_output", "compliance_result.json"
    )
)


def handler(event: dict, context=None, *, bedrock_client=None) -> dict:
    """
    Lambda handler for compliance reasoner agent.

    Args:
        event: Lambda event with keys: mode (live|local), detection_output
               (inline dict), optional request_ref (lowercase uuid4).
        context: Lambda context object (None in local mode)
        bedrock_client: keyword-only pre-built bedrock-runtime client (the
               console's in-process path passes one built from the
               operator's own session; tests pass fakes). When None the
               client is built from the runtime's role, exactly as before,
               only once assessment starts (Lambda/AgentCore path).

    Returns:
        Compliance output dict with cluster assessments and decisions, or an
        error dict ({"error": PAYLOAD_TOO_LARGE | PROVENANCE_CHECK_FAILED |
        PROVENANCE_UNAVAILABLE | DUPLICATE_DECISION, ...}) that the shim maps
        to 413 / 409 / 503 / 409. Raises ComplianceAuditWriteError when the
        durable write fails, so no un-audited decision is returned.
    """
    mode = event.get("mode", "local")
    compliance_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Defense in depth: refuse local mode in a DEPLOYED
    # runtime. Local mode returns a shipped FILE_SAR fixture without invoking
    # Bedrock, the guardrail, the drift metric or the audit write, so it must
    # never be reachable in production. There is no override
    # (governance_common.deployed_runtime).
    refuse_local_mode_in_deployed_runtime(mode)

    if mode == "local":
        return run_local_mode(compliance_id, timestamp)

    # Durable = the run is audited (and therefore provenance-checked). Computed
    # once, up front, so provenance, the write and drift all agree.
    # Auto-enabled in AgentCore Runtime (detected by /var/task).
    write_audit = os.environ.get("WRITE_AUDIT", "false").lower() == "true"
    if not write_audit and os.path.isdir("/var/task"):
        write_audit = True

    # Get detection output. Only an inline dict is accepted — a string value
    # used to be treated as a filesystem path and opened, giving a caller a
    # path/errno oracle and an unbounded read. The CLI loads the
    # file itself and passes a dict, so by-reference input is only ever a
    # request-surface construct and is rejected here.
    detection_output = event.get("detection_output", {})
    if isinstance(detection_output, str):
        raise ValueError(
            "detection_output must be an inline object, not a file path"
        )
    if not isinstance(detection_output, dict):
        raise ValueError("detection_output must be an object")

    # Correlation reference to the console's operator-audit record;
    # never used for authorization. Re-validated for non-shim callers.
    # A PAN-shaped uuid is refused too: request_ref is stored and archived.
    request_ref = event.get("request_ref")
    if request_ref is not None and not request_ref_ok(request_ref):
        raise ValueError("invalid request_ref")

    detection_id = detection_output.get("detection_id", "unknown")
    flagged_clusters = detection_output.get("flagged_clusters", [])

    # Validate every caller-supplied cluster_id BEFORE any Bedrock call or
    # compliance-decisions write: the stored cluster_id becomes
    # the executor's routing / completion identity, so an empty, non-string,
    # over-long or odd-charset id must never be persisted. An absent
    # cluster_id is still allowed (assess_cluster assigns a uuid4). The
    # error names only the cluster index, never the offending value.
    validate_cluster_ids(flagged_clusters)

    # Cluster cap, before any AWS client is built.
    if isinstance(flagged_clusters, list) and len(flagged_clusters) > MAX_CLUSTERS_PER_REQUEST:
        logger.info("Rejected compliance request: %d clusters > cap %d",
                    len(flagged_clusters), MAX_CLUSTERS_PER_REQUEST)
        return {"error": "PAYLOAD_TOO_LARGE", "max_clusters": MAX_CLUSTERS_PER_REQUEST}

    # Detection provenance: a durable run assesses only the
    # recorded detection, never the caller's copy.
    stored_item = None
    if write_audit:
        provenance_status, stored_item, error = verify_detection_provenance(detection_output)
        if error is not None:
            return error
        if provenance_status == VERIFIED:
            clusters_to_assess = _stored_clusters_in_caller_order(flagged_clusters, stored_item)
            # Single decision per detection: the cheap pre-check
            # stops a replay before any Bedrock call; the transaction's
            # marker condition is the race-safe enforcement.
            if decision_exists(detection_id):
                logger.warning("Duplicate decision request for detection %s", detection_id)
                return _duplicate_decision_error()
        else:
            clusters_to_assess = flagged_clusters
    else:
        provenance_status = NOT_CHECKED
        clusters_to_assess = flagged_clusters

    if not clusters_to_assess:
        return build_output(
            compliance_id=compliance_id,
            detection_id=detection_id,
            timestamp=timestamp,
            clusters_assessed=[],
            provenance_status=provenance_status,
            request_ref=request_ref,
        )

    # Process each cluster
    if bedrock_client is None:
        bedrock_client = boto3.client("bedrock-runtime", region_name=REGION)
    clusters_assessed = []

    for cluster in clusters_to_assess:
        result = assess_cluster(cluster, bedrock_client)
        clusters_assessed.append(result)

    _apply_provenance_gates(clusters_assessed, clusters_to_assess, provenance_status, stored_item)

    # Decision invariant: the compliance agent only ever emits
    # FILE_SAR or NEEDS_REVIEW; re-checked before anything is written.
    for result in clusters_assessed:
        if result.get("decision") not in ALLOWED_DECISIONS:
            raise ValueError("invalid decision")

    # Decision time: the stored timestamp (the by_day_ts sort
    # key the breaker corroborates against) is set immediately before the
    # write, not at run start. The run start goes on the stored item only.
    run_started = timestamp
    timestamp = datetime.now(timezone.utc).isoformat()
    output = build_output(
        compliance_id=compliance_id,
        detection_id=detection_id,
        timestamp=timestamp,
        clusters_assessed=clusters_assessed,
        provenance_status=provenance_status,
        request_ref=request_ref,
    )

    if write_audit:
        # Dispatch capability token: VERIFIED only. Only its
        # sha256 is stored; the token itself exists only in this response
        # and is never logged.
        dispatch_token = secrets.token_urlsafe(32) if provenance_status == VERIFIED else None
        token_sha256 = (hashlib.sha256(dispatch_token.encode("ascii")).hexdigest()
                        if dispatch_token else None)
        try:
            # Fail closed: ComplianceAuditWriteError propagates.
            write_to_dynamodb(
                output,
                dispatch_token_sha256=token_sha256,
                console_request_ref=request_ref,
                started_at=run_started,
            )
        except DuplicateDecisionError:
            # Lost the race on the marker: the assessment is unaudited and
            # is discarded, never returned.
            logger.warning("Duplicate decision for detection %s (transaction)", detection_id)
            return _duplicate_decision_error()
        if dispatch_token:
            output["dispatch_token"] = dispatch_token

    # Drift metrics are no longer published from this role:
    # fsi-drift-metric-publisher derives them from the stored VERIFIED
    # record (compliance-decisions stream), so a datapoint exists only when
    # a durable decision does.
    return output


def _duplicate_decision_error() -> dict:
    return {"error": "DUPLICATE_DECISION",
            "message": "a decision already exists for this detection"}


def _provenance_mismatch() -> dict:
    return {"error": "PROVENANCE_CHECK_FAILED",
            "message": "detection_output does not match the recorded detection"}


def _norm(value):
    """Canonical form for provenance comparison: numbers (int / float /
    Decimal) compare numerically as Decimal, containers recursively."""
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, Decimal)):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(repr(value))
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_norm(v) for v in value]
    return value


def _from_ddb(value):
    """DynamoDB Decimal -> int / float, recursively (stored clusters are
    assessed and returned as plain JSON numbers)."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: _from_ddb(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_from_ddb(v) for v in value]
    return value


def verify_detection_provenance(detection_output: dict):
    """Bind the run to the recorded detection. Durable runs only.

    Returns (status, stored_item, error):
      (VERIFIED, item, None)    the caller's cluster_id multiset and every
                                enrichment field match the stored item
      (UNVERIFIED, None, None)  no stored item and ALLOW_UNVERIFIED_EVALUATION
      (None, None, error_dict)  PROVENANCE_CHECK_FAILED (mismatch / absent)
                                or PROVENANCE_UNAVAILABLE (lookup error)
    Raises ValueError for a malformed detection_id.
    """
    detection_id = detection_output.get("detection_id")
    if not (isinstance(detection_id, str) and DETECTION_ID_RE.fullmatch(detection_id)):
        raise ValueError("detection_output.detection_id is invalid")
    try:
        table = boto3.resource("dynamodb", region_name=REGION).Table(DETECTION_TABLE)
        response = table.get_item(Key={"detection_id": detection_id}, ConsistentRead=True)
    except Exception as e:
        error_id = str(uuid.uuid4())
        logger.error("Detection provenance lookup failed [%s] (%s)", error_id, type(e).__name__)
        return None, None, {"error": "PROVENANCE_UNAVAILABLE", "error_id": error_id}

    item = response.get("Item")
    if not item:
        if os.environ.get("ALLOW_UNVERIFIED_EVALUATION", "false").lower() == "true":
            logger.warning("No recorded detection %s; UNVERIFIED evaluation only", detection_id)
            return UNVERIFIED, None, None
        logger.warning("Provenance check failed: no recorded detection %s", detection_id)
        return None, None, _provenance_mismatch()

    caller = detection_output.get("flagged_clusters", [])
    stored = item.get("flagged_clusters") or []
    if not (_clusters_match(caller, stored)):
        logger.warning("Provenance check failed: detection %s does not match the record", detection_id)
        return None, None, _provenance_mismatch()
    return VERIFIED, item, None


def _clusters_match(caller, stored) -> bool:
    if not (isinstance(caller, list) and isinstance(stored, list)):
        return False
    if not all(isinstance(c, dict) for c in caller) or not all(isinstance(s, dict) for s in stored):
        return False
    if Counter(c.get("cluster_id") for c in caller) != Counter(s.get("cluster_id") for s in stored):
        return False
    by_id = {}
    for s in stored:
        by_id.setdefault(s.get("cluster_id"), []).append(s)
    for c in caller:
        s = by_id[c.get("cluster_id")].pop(0)
        for field in PROVENANCE_FIELDS:
            if _norm(c.get(field)) != _norm(s.get(field)):
                return False
    return True


def _stored_clusters_in_caller_order(caller: list, stored_item: dict) -> list:
    """The STORED clusters (Decimal -> number), in the caller's order.
    Only called after _clusters_match succeeded."""
    by_id = {}
    for s in stored_item.get("flagged_clusters") or []:
        by_id.setdefault(s.get("cluster_id"), []).append(_from_ddb(s))
    return [by_id[c.get("cluster_id")].pop(0) for c in caller]


def _degraded_input(stored_item) -> bool:
    quality = stored_item.get("input_quality") if isinstance(stored_item, dict) else None
    if not isinstance(quality, dict):
        return False
    try:
        rejected = float(quality.get("schema_rejected", 0) or 0)
        total = float(quality.get("transactions_in", 0) or 0)
    except (TypeError, ValueError):
        return True
    return rejected / max(total, 1) > MAX_SCHEMA_REJECTED_SHARE


def _apply_provenance_gates(clusters_assessed, assessed_inputs, provenance_status, stored_item):
    """Fail-safe decision overrides that depend on provenance. Gate markers stay inside model_metadata."""
    if provenance_status == UNVERIFIED:
        for result in clusters_assessed:
            result["decision"] = "NEEDS_REVIEW"
            result.setdefault("model_metadata", {})["provenance_gate"] = UNVERIFIED
        return
    if provenance_status != VERIFIED:
        return
    # input_quality / evidence_flags are read from the STORED item, never
    # from the caller.
    degraded = _degraded_input(stored_item)
    for result, source in zip(clusters_assessed, assessed_inputs):
        if degraded:
            result["decision"] = "NEEDS_REVIEW"
            result.setdefault("model_metadata", {})["input_quality_gate"] = "DEGRADED_INPUT"
        if source.get("evidence_flags"):
            result["decision"] = "NEEDS_REVIEW"
            result.setdefault("model_metadata", {})["evidence_gate"] = "EVIDENCE_FLAGGED"


def decision_exists(detection_id: str) -> bool:
    """Pre-check for the single-decision marker. A lookup error
    fails closed (ComplianceAuditWriteError, no Bedrock call)."""
    try:
        table = boto3.resource("dynamodb", region_name=REGION).Table(COMPLIANCE_TABLE)
        response = table.get_item(Key={"compliance_id": f"detection#{detection_id}"},
                                  ConsistentRead=True)
    except Exception as e:
        logger.error("Decision marker lookup failed (%s)", type(e).__name__)  # nosemgrep: logging-error-without-handling -- fail-closed: logged at ERROR so the failed decision lookup is visible, then re-raised as ComplianceAuditWriteError; class name only
        raise ComplianceAuditWriteError("decision marker lookup failed") from e
    return bool(response.get("Item"))


# Accepted cluster_id shape: every pipeline-generated id fits
# (detection-agent uuid4s, "cluster-1", "c1").
CLUSTER_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")


def validate_cluster_ids(flagged_clusters) -> None:
    """Raise ValueError if any flagged cluster carries a cluster_id that is
    not a non-empty string of at most 128 characters from [A-Za-z0-9._-].
    A cluster without a cluster_id key is accepted (a uuid4 is assigned)."""
    if not isinstance(flagged_clusters, list):
        return  # shape handling of flagged_clusters itself is unchanged
    for index, cluster in enumerate(flagged_clusters):
        if not isinstance(cluster, dict) or "cluster_id" not in cluster:
            continue
        cluster_id = cluster["cluster_id"]
        if not (isinstance(cluster_id, str) and CLUSTER_ID_RE.fullmatch(cluster_id)):
            raise ValueError(
                f"flagged_clusters[{index}].cluster_id is invalid: must be 1-128 "
                "characters from [A-Za-z0-9._-]"
            )


def assess_cluster(cluster: dict, bedrock_client) -> dict:
    """
    Assess a single flagged cluster through SAR generation + challenger.

    Returns cluster assessment dict per the interface contract.
    """
    cluster_id = cluster.get("cluster_id", str(uuid.uuid4()))
    enriched = enrich_cluster(cluster)

    # Every cluster field is caller-supplied and reaches both the SAR and
    # challenger prompts (see sar_prompts.py), so the guardrail is applied
    # to BOTH calls unconditionally. The old gate keyed this on
    # `cluster.get("analyst_notes")`, a field enrich_cluster never passes
    # through to the prompt — so it guardrailed nothing that actually
    # reached the model while leaving the fields that do reach it
    # unguarded.

    # === SAR GENERATION (Bedrock call #1) ===
    sar_narrative = ""
    sar_metadata = {}
    guardrail_triggered = False
    # SAR output failed schema validation or the SAR call failed: the cluster
    # can never auto-file a placeholder narrative.
    sar_rejected = False

    try:
        sar_segments = build_sar_prompt_segments(enriched)
        # Fingerprint over the full joined prompt text (unchanged audit
        # semantics), not over the guardContent-tagged request shape.
        sar_fingerprint = get_prompt_fingerprint(join_prompt_segments(sar_segments))

        start_time = time.time()
        sar_response = invoke_bedrock(
            bedrock_client, sar_segments, SAR_SYSTEM_PROMPT, "sar",
            use_guardrail=True
        )
        sar_latency = int((time.time() - start_time) * 1000)

        if sar_response.get("guardrail_intervened"):
            guardrail_triggered = True
            sar_narrative = "[GUARDRAIL BLOCKED SAR OUTPUT]"
            sar_metadata = {
                "model_id": MODEL_ID,
                "latency_ms": sar_latency,
                "guardrail_action": "INTERVENED",
                "prompt_fingerprint": sar_fingerprint,
            }
        else:
            # Strict schema: the raw model text never becomes
            # the filed narrative.
            sar_data, sar_error = validate_model_output("sar", sar_response["text"])
            sar_metadata = {
                "model_id": MODEL_ID,
                "latency_ms": sar_latency,
                "guardrail_action": "NONE",
                "prompt_fingerprint": sar_fingerprint,
            }
            if sar_error is not None:
                logger.warning("SAR output rejected: %s (cluster %s)", sar_error, cluster_id)
                sar_rejected = True
                sar_narrative = "[SAR OUTPUT REJECTED — failed schema validation]"
                sar_metadata["output_validation"] = sar_error
            else:
                sar_narrative = sar_data["sar_narrative"]
    except Exception as e:
        # Log the full exception server-side only. Raw Bedrock/botocore
        # exception text (AccessDeniedException/ValidationException
        # messages embed the assumed-role ARN, account id and model id) must
        # not become the SAR narrative or compliance-record metadata, which
        # is returned to the /invocations caller and written to
        # compliance-decisions. A stable error code plus a
        # correlation id is enough for an operator to find the detail in
        # CloudWatch Logs without exposing it to the caller or the record.
        error_id = str(uuid.uuid4())
        logger.error("SAR generation failed [%s]: %s", error_id, e, exc_info=True)
        sar_rejected = True
        sar_narrative = f"[SAR GENERATION FAILED — error_id {error_id}]"
        sar_metadata = {
            "model_id": MODEL_ID,
            "latency_ms": 0,
            "guardrail_action": "ERROR",
            "error_id": error_id,
        }

    # ═════════════════════════════════════════════════════════════════════════
    # BLUEPRINT 3 — DELIBERATIVE CHALLENGE (real LLM challenger)
    # ═════════════════════════════════════════════════════════════════════════
    # A second, independent Bedrock call acts as the SR 11-7 challenger. It runs
    # the methodologically-different challenger prompt, is guardrail-protected on
    # untrusted input, and records a full audit trail (prompt fingerprint,
    # latency, model ID). The prompt-fingerprint assert enforces that the
    # challenger is genuinely different from the champion — if they ever matched,
    # the challenge would be a rubber stamp and the run fails loudly.
    # ═════════════════════════════════════════════════════════════════════════
    # === INDEPENDENT CHALLENGER (Bedrock call #2) ===
    challenger_opinion = "AGREE"
    challenger_rationale = ""
    challenger_metadata = {}
    challenger_failed = False
    challenger_confidence = None

    try:
        challenger_segments = build_challenger_prompt_segments(enriched)
        challenger_fingerprint = get_prompt_fingerprint(join_prompt_segments(challenger_segments))

        # Verify methodological independence (hash comparison)
        assert sar_fingerprint != challenger_fingerprint, "Prompts must be methodologically different"

        start_time = time.time()
        challenger_response = invoke_bedrock(
            bedrock_client, challenger_segments, CHALLENGER_SYSTEM_PROMPT, "challenger",
            use_guardrail=True, model_id=CHALLENGER_MODEL_ID
        )
        challenger_latency = int((time.time() - start_time) * 1000)

        if challenger_response.get("guardrail_intervened"):
            guardrail_triggered = True
            challenger_opinion = "DISPUTE"
            challenger_rationale = "[GUARDRAIL BLOCKED CHALLENGER OUTPUT — defaulting to DISPUTE]"
            challenger_metadata = {
                "model_id": CHALLENGER_MODEL_ID,
                "latency_ms": challenger_latency,
                "guardrail_action": "INTERVENED",
                "prompt_fingerprint": challenger_fingerprint,
            }
        else:
            challenger_metadata = {
                "model_id": CHALLENGER_MODEL_ID,
                "latency_ms": challenger_latency,
                "guardrail_action": "NONE",
                "prompt_fingerprint": challenger_fingerprint,
            }
            # Strict schema: only an exact "AGREE"/"DISPUTE" in a
            # schema-valid reply counts (never default to AGREE).
            # A rejected reply routes as DISPUTE (fail safe) but is recorded
            # as an output rejection, not a dispute, so formatting breakage
            # can't drive the dispute-rate breaker.
            challenger_data, challenger_error = validate_model_output(
                "challenger", challenger_response["text"])
            if challenger_error is not None:
                logger.warning("Challenger output rejected: %s (cluster %s)",
                               challenger_error, cluster_id)
                challenger_opinion = "DISPUTE"
                challenger_rationale = (
                    f"[CHALLENGER OUTPUT REJECTED — {challenger_error} — defaulting to DISPUTE]"
                )
                challenger_metadata["output_validation"] = challenger_error
            else:
                challenger_opinion = challenger_data["verdict"]
                challenger_rationale = challenger_data["rationale"]
                challenger_confidence = challenger_data["confidence"]
                challenger_metadata["confidence"] = challenger_confidence
    except Exception as e:
        # Operational failure (transport/validation error from the Bedrock
        # call itself) is distinct from a genuine model DISPUTE verdict.
        # Still fail safe to NEEDS_REVIEW — an unreviewable challenger must
        # not let a SAR auto-file — but record it as challenger_failed so
        # publish_drift_metrics counts it separately from real disagreement.
        # Otherwise a caller-triggerable error (e.g. an oversized cluster
        # field tripping a Bedrock ValidationException) drives the exact
        # same drift metric as a genuine model dispute.
        # Same redaction as the SAR except block above: log the
        # raw exception server-side, never return it in the rationale or
        # metadata that reach the caller and compliance-decisions.
        error_id = str(uuid.uuid4())
        logger.error("Challenger call failed [%s]: %s", error_id, e, exc_info=True)
        challenger_opinion = "DISPUTE"
        challenger_failed = True
        challenger_rationale = f"[CHALLENGER FAILED — error_id {error_id} — defaulting to DISPUTE for safety]"
        challenger_metadata = {
            "model_id": CHALLENGER_MODEL_ID,
            "latency_ms": 0,
            "guardrail_action": "ERROR",
            "error_id": error_id,
        }

    # === DIVERGENCE LOGIC ===
    # BLUEPRINT 4 — DRIFT CONTROL (fail-safe escalation)
    # The system fails safe to a human: if the independent challenger DISPUTEs,
    # or the guardrail intervened, the decision is downgraded to NEEDS_REVIEW
    # instead of auto-filing. Only a clean, unchallenged, guardrail-passing
    # assessment is allowed to auto-file a SAR. (Challenger failure also defaults
    # to DISPUTE upstream — see the challenger except block.)
    if challenger_opinion == "DISPUTE":
        decision = "NEEDS_REVIEW"
    elif guardrail_triggered:
        decision = "NEEDS_REVIEW"
    elif sar_rejected:
        decision = "NEEDS_REVIEW"
    elif challenger_confidence not in ("HIGH", "MEDIUM"):
        # An auto-file needs at least MEDIUM-confidence agreement.
        decision = "NEEDS_REVIEW"
    else:
        decision = "FILE_SAR"
    # Decision invariant: never derived from model text, never CIRCUIT_BREAKER.
    if decision not in ALLOWED_DECISIONS:
        raise ValueError("invalid decision")

    return {
        "cluster_id": cluster_id,
        "sar_narrative": sar_narrative,
        "challenger_opinion": challenger_opinion,
        "challenger_rationale": challenger_rationale,
        "challenger_failed": challenger_failed,
        "decision": decision,
        "guardrail_triggered": guardrail_triggered,
        "model_metadata": {
            "sar_call": sar_metadata,
            "challenger_call": challenger_metadata,
        }
    }


class GuardrailNotConfiguredError(RuntimeError):
    """Raised when a call that must be guardrailed has no GUARDRAIL_ID set.
    Every SAR/challenger call now requires use_guardrail=True (see
    assess_cluster) since cluster fields are caller-controlled, so a missing
    guardrail must fail the call rather than silently proceed unguarded.
    Also raised when the prompt carries no UNTRUSTED segment to tag as
    guardContent (see build_guarded_content)."""


def build_guarded_content(prompt_segments) -> list:
    """
    Convert (kind, text) prompt segments into Converse user content blocks.

    TRUSTED segments (our fixed instruction text) become plain
    {"text": ...} blocks; UNTRUSTED segments (the only place caller-
    controlled cluster data appears) become
    {"guardContent": {"text": {"text": ...}}} blocks. Once any guardContent
    block is present, the guardrail's input evaluation is scoped to the
    guardContent blocks — every configured filter (prompt attack,
    misconduct, PII, regex, denied words) still runs on the caller data —
    and the model's output is still evaluated in full. Without this
    scoping the guardrail evaluated our own instruction text and blocked
    every SAR/challenger call as a prompt attack.

    Fails closed: a plain string, an unknown segment kind, or a prompt with
    no non-empty UNTRUSTED segment raises GuardrailNotConfiguredError rather
    than sending untagged text (which would silently either un-scope or
    — if a guardContent block were missing — skip guarding the data).
    """
    if not isinstance(prompt_segments, (list, tuple)):
        raise GuardrailNotConfiguredError(
            "prompt must be a list of (kind, text) segments with an untrusted "
            "segment — refusing to send an untagged prompt."
        )
    content = []
    has_untrusted = False
    for segment in prompt_segments:
        if not (isinstance(segment, (list, tuple)) and len(segment) == 2):
            raise GuardrailNotConfiguredError("malformed prompt segment")
        kind, text = segment
        if not isinstance(text, str):
            raise GuardrailNotConfiguredError("prompt segment text must be a string")
        if kind == UNTRUSTED:
            if text:
                content.append({"guardContent": {"text": {"text": text}}})
                has_untrusted = True
        elif kind == TRUSTED:
            if text:
                content.append({"text": text})
        else:
            raise GuardrailNotConfiguredError(f"unknown prompt segment kind: {kind!r}")
    if not has_untrusted:
        raise GuardrailNotConfiguredError(
            "prompt has no untrusted segment to guard — refusing to send it "
            "without a guardContent block."
        )
    return content


# Per-process cache of the last SUCCESSFUL registry verification, keyed by
# (path, mtime_ns, size, sha256). Failures are never cached: a
# definitive SignatureInvalidError and a transient Unavailable error both
# refuse this call only, and the next call re-verifies.
_VERIFIED_REGISTRY_CACHE = {}


def _verified_registry(now: datetime = None) -> dict:
    """The approved-models registry, only if its signature verifies.

    A cached registry is valid only until signed_at + the registry's maximum
    signature age: after that it is re-verified, and a stale
    KMS signature refuses every decision (UnapprovedModelError). KMS
    envelopes verify only inside a deployed runtime, so outside one (local
    dev) the cache never expires."""
    path = model_assurance.DEFAULT_REGISTRY_PATH
    now = now or datetime.now(timezone.utc)
    try:
        stat = os.stat(path)
        with open(path, "rb") as f:
            current_sha = hashlib.sha256(f.read()).hexdigest()
        key = (path, stat.st_mtime_ns, stat.st_size, current_sha)
    except OSError:
        key = None
    cached = _VERIFIED_REGISTRY_CACHE.get(key) if key is not None else None
    if cached is not None and (cached[1] is None or now < cached[1]):
        return cached[0]
    try:
        registry, verified, signed_at = model_assurance.verified_registry_bytes(path, now=now)
        valid_until = None
        if signing.in_deployed_runtime():
            max_age = signing.load_key_pins().max_signature_age(signing.PURPOSE_REGISTRY)
            valid_until = signed_at + timedelta(seconds=max_age)
    except signing.SignatureInvalidError as exc:
        raise UnapprovedModelError("approved-models registry signature invalid") from exc
    except signing.SignatureVerificationUnavailableError as exc:
        raise UnapprovedModelError("approved-models registry signature could not be verified") from exc
    if key is not None and hashlib.sha256(verified).hexdigest() == key[3]:
        _VERIFIED_REGISTRY_CACHE.clear()
        _VERIFIED_REGISTRY_CACHE[key] = (registry, valid_until)
    return registry


def invoke_bedrock(client, prompt_segments: list, system_prompt: str, call_type: str,
                   use_guardrail: bool = False, model_id: str = None) -> dict:
    """
    Invoke Bedrock Converse API with a guardrail.

    Args:
        prompt_segments: (kind, text) segments from
                       sar_prompts.build_*_prompt_segments(). UNTRUSTED
                       segments are sent as guardContent (see
                       build_guarded_content); there must be at least one.
        use_guardrail: Every caller in this module passes True — cluster
                       fields are caller-controlled and reach the prompt, so
                       the guardrail is the second CHD/injection boundary
                       (after the PAN ingress filter). If no
                       GUARDRAIL_ID/GUARDRAIL_VERSION is configured, or
                       use_guardrail is False, this fails closed
                       (GuardrailNotConfiguredError) rather than calling the
                       model unguarded.
        model_id: Model to invoke. Defaults to the champion MODEL_ID; the
                  challenger call passes CHALLENGER_MODEL_ID so the two run on
                  independent model families (SR 11-7 model-level challenge).

    Returns:
        dict: {"text": str, "guardrail_intervened": bool, "stop_reason": str}
    """
    if use_guardrail and not GUARDRAIL_ID:
        raise GuardrailNotConfiguredError(
            "GUARDRAIL_ID is not configured — refusing to send caller-controlled "
            "cluster data to the model unguarded."
        )
    if use_guardrail and not GUARDRAIL_VERSION:
        # GUARDRAIL_ID alone is not enough — without a
        # published numbered version, the Converse call would pin to the
        # mutable DRAFT guardrail, which can change out from under a live
        # deploy with no version pin.
        raise GuardrailNotConfiguredError(
            "GUARDRAIL_VERSION is not configured — refusing to send caller-controlled "
            "cluster data against the mutable DRAFT guardrail."
        )
    if not use_guardrail:
        # Every prompt now carries caller-controlled guardContent; there is
        # no legitimate unguarded call path in this module.
        raise GuardrailNotConfiguredError(
            "use_guardrail=False is not supported — SAR/challenger prompts carry "
            "caller-controlled data and must always be guardrailed."
        )

    resolved_model_id = model_id or MODEL_ID
    # Enforce the approved-models registry at the point of invocation, not
    # just at deploy-time gate/dashboard checks — those never ran against
    # this runtime path. An unapproved or unset model_id must
    # never generate a SAR narrative or a challenger verdict.
    approved, reason = validate_model(resolved_model_id, _verified_registry())
    if not approved:
        raise UnapprovedModelError(
            f"Refusing to invoke Bedrock with an unapproved model: {reason}"
        )

    converse_params = {
        "modelId": resolved_model_id,
        "messages": [
            {"role": "user", "content": build_guarded_content(prompt_segments)}
        ],
        "inferenceConfig": {
            "maxTokens": 800 if call_type == "sar" else 500,
            "temperature": 0.1,
        },
        "system": [{"text": system_prompt}],
        "guardrailConfig": {
            "guardrailIdentifier": GUARDRAIL_ID,
            "guardrailVersion": GUARDRAIL_VERSION,
        },
    }

    response = client.converse(**converse_params)

    stop_reason = response.get("stopReason", "")
    if stop_reason == "guardrail_intervened":
        return {"text": "", "guardrail_intervened": True, "stop_reason": stop_reason}

    # Extract response text
    output = response.get("output", {})
    message = output.get("message", {})
    content_blocks = message.get("content", [])
    raw_text = ""
    for block in content_blocks:
        if "text" in block:
            raw_text += block["text"]

    return {"text": raw_text, "guardrail_intervened": False, "stop_reason": stop_reason}


def parse_json_response(raw_text: str, call_type: str = "sar") -> dict:
    """Compatibility wrapper over output_schema.validate_model_output:
    the schema-valid object, or {"_rejected": error_code}.
    There is no substring search or raw-text fallback any more."""
    data, error = validate_model_output(call_type, raw_text)
    return data if error is None else {"_rejected": error}


def run_local_mode(compliance_id: str, timestamp: str) -> dict:
    """--local mode: use pre-cached compliance results."""
    if os.path.exists(CACHED_OUTPUT_PATH):
        with open(CACHED_OUTPUT_PATH, "r", encoding="utf-8") as f:
            cached = json.load(f)
        cached["compliance_id"] = compliance_id
        cached["timestamp"] = timestamp
        logger.info("Loaded cached compliance result (%d clusters)", len(cached.get('clusters_assessed', [])))
        return cached
    else:
        logger.info("No cached output at %s, returning empty result", CACHED_OUTPUT_PATH)
        return build_output(
            compliance_id=compliance_id,
            detection_id="unknown",
            timestamp=timestamp,
            clusters_assessed=[],
        )


def build_output(compliance_id: str, detection_id: str, timestamp: str,
                 clusters_assessed: list, provenance_status: str | None = None,
                 request_ref: str | None = None) -> dict:
    """Build structured compliance output per interface contract.
    provenance_status / request_ref are added when given."""
    output = {
        "compliance_id": compliance_id,
        "detection_id": detection_id,
        "timestamp": timestamp,
        "clusters_assessed": clusters_assessed,
    }
    if provenance_status is not None:
        output["provenance_status"] = provenance_status
    if request_ref is not None:
        output["request_ref"] = request_ref
    return output


# ═════════════════════════════════════════════════════════════════════════════
# BLUEPRINT 4 — DRIFT CONTROL (drift counts on the decision record)
# ═════════════════════════════════════════════════════════════════════════════
# Every VERIFIED decision stores its drift numerators (drift_counts). The
# drift metrics the alarms watch are published from those stored records by
# fsi-drift-metric-publisher (lambdas/drift_metric_publisher/handler.py), the
# only drift-metric publisher; this agent's role has no
# cloudwatch:PutMetricData grant.
# ═════════════════════════════════════════════════════════════════════════════


def _output_rejected(cluster: dict) -> bool:
    metadata = cluster.get("model_metadata")
    call = metadata.get("challenger_call") if isinstance(metadata, dict) else None
    return isinstance(call, dict) and bool(call.get("output_validation"))


def compute_drift_counts(clusters_assessed: list) -> dict:
    """Drift numerators stored on the decision record.
    An operational challenger failure is recorded with
    challenger_opinion="DISPUTE" (so routing never treats it as AGREE), but
    it is NOT a model disagreement, and neither is a schema-rejected
    challenger reply: neither counts as a dispute, so forced
    Bedrock failures or JSON-breaking text cannot manufacture a dispute rate
    and trip the fleet-wide kill switch."""
    clusters = [c for c in clusters_assessed if isinstance(c, dict)]
    return {
        "clusters": len(clusters_assessed),
        "disputes": sum(
            1 for c in clusters
            if c.get("challenger_opinion") == "DISPUTE" and not c.get("challenger_failed")
            and not _output_rejected(c)
        ),
        "guardrail_hits": sum(1 for c in clusters if c.get("guardrail_triggered")),
        "challenger_failures": sum(1 for c in clusters if c.get("challenger_failed")),
        "output_rejections": sum(1 for c in clusters if _output_rejected(c)),
    }


def write_to_dynamodb(output: dict, dispatch_token_sha256: str | None = None,
                      console_request_ref: str | None = None, started_at: str | None = None):
    """Write the compliance decision to the DynamoDB audit trail, fail closed.
    Raises ComplianceAuditWriteError on any failure and
    DuplicateDecisionError when the single-decision marker already exists.

    VERIFIED runs write the decision and the ``detection#<id>`` marker in one
    transaction, both conditioned on attribute_not_exists, so
    only one decision per detection can ever be recorded. Other runs
    (UNVERIFIED) are a plain conditional put with no marker.

    The record carries record_day (by_day_ts), drift_counts, the
    provenance_status, the dispatch token's sha256 (never the token) and the
    console_request_ref; the response-only keys dispatch_token / request_ref
    are never stored.
    """
    record = {k: v for k, v in output.items() if k not in ("dispatch_token", "request_ref")}
    record["record_day"] = str(output.get("timestamp", ""))[:10] or \
        datetime.now(timezone.utc).date().isoformat()
    record["drift_counts"] = compute_drift_counts(output.get("clusters_assessed", []))
    if dispatch_token_sha256 is not None:
        record["dispatch_token_sha256"] = dispatch_token_sha256
    if console_request_ref is not None:
        record["console_request_ref"] = console_request_ref
    if started_at is not None:
        # Run start; "timestamp" is the decision time.
        record["started_at"] = started_at
    # DynamoDB doesn't support float — convert to Decimal
    item = json.loads(json.dumps(record, default=str), parse_float=Decimal)
    condition = "attribute_not_exists(compliance_id)"
    try:
        if output.get("provenance_status") == VERIFIED:
            from boto3.dynamodb.types import TypeSerializer
            serializer = TypeSerializer()
            marker = {
                "compliance_id": f"detection#{output['detection_id']}",
                "decision_compliance_id": output["compliance_id"],
                "timestamp": output.get("timestamp", ""),
                "record_type": "DETECTION_DECISION_MARKER",
            }
            client = boto3.client("dynamodb", region_name=REGION)
            client.transact_write_items(TransactItems=[
                {"Put": {"TableName": COMPLIANCE_TABLE,
                         "Item": {k: serializer.serialize(v) for k, v in item.items()},
                         "ConditionExpression": condition}},
                {"Put": {"TableName": COMPLIANCE_TABLE,
                         "Item": {k: serializer.serialize(v) for k, v in marker.items()},
                         "ConditionExpression": condition}},
            ])
        else:
            table = boto3.resource("dynamodb", region_name=REGION).Table(COMPLIANCE_TABLE)
            table.put_item(Item=item, ConditionExpression=condition)
    except Exception as e:
        if _marker_condition_failed(e):
            raise DuplicateDecisionError("a decision already exists for this detection") from e
        error_id = str(uuid.uuid4())
        # Class name only: no item content (or token hash) reaches the logs.
        logger.error("Compliance audit write failed [%s] (%s)", error_id, type(e).__name__)  # nosemgrep: logging-error-without-handling -- fail-closed: audit write failure is ERROR by design (tests assert it), re-raised as ComplianceAuditWriteError; class name only
        raise ComplianceAuditWriteError(f"compliance audit write failed (error_id {error_id})") from e
    logger.info("Written compliance decision %s to %s", output["compliance_id"], COMPLIANCE_TABLE)


def _marker_condition_failed(error: Exception) -> bool:
    """True when a TransactWriteItems cancellation was caused by the marker
    (second item) failing its attribute_not_exists condition."""
    response = getattr(error, "response", None)
    if not isinstance(response, dict):
        return False
    if response.get("Error", {}).get("Code") != "TransactionCanceledException":
        return False
    reasons = response.get("CancellationReasons") or []
    return len(reasons) >= 2 and isinstance(reasons[1], dict) and \
        reasons[1].get("Code") == "ConditionalCheckFailed"


# === CLI Entry Point ===
def main():
    parser = argparse.ArgumentParser(description="Compliance Reasoner Agent — SAR + Challenger")
    parser.add_argument("--local", action="store_true", help="Use pre-cached output (no Bedrock required)")
    parser.add_argument("--detection-file", type=str, default=None,
                        help="Path to detection agent output JSON")
    parser.add_argument("--output", type=str, default=None,
                        help="Write output to file (default: stdout)")
    args = parser.parse_args()

    if args.local:
        event = {"mode": "local"}
    elif args.detection_file:
        with open(args.detection_file, "r", encoding="utf-8") as f:
            detection_output = json.load(f)
        event = {"mode": "live", "detection_output": detection_output}
    else:
        event = {"mode": "local"}

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
