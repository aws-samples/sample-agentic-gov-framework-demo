"""
Detection Agent — Lambda wrapper for cuGraph fraud ring detection.

Wraps GPU fraud detection logic into the governance envelope agent pattern.
- PAN/PII ingress filter runs BEFORE graph processing
- Schema canonicalization (txn_schema) runs on the PAN-clean transactions, so
  only allowlisted, normalized fields reach detection, the audit item and logs
- Structured detection output written to DynamoDB audit trail
- --local mode reads from pre-cached JSON instead of running GPU
- Exits with structured JSON output consumed by Agent 2 (Compliance Reasoner)

IAM Identity (NHI #1: detection-agent-role):
- CAN: Read from transaction source (S3/Kinesis), write to detection-results DynamoDB table
- CANNOT: Invoke Bedrock, write to SAR filing, read/write compliance decisions
"""
import json
import logging
import os
import sys
import time
import uuid
import argparse
import boto3
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pan_filter import contains_full_pan, filter_transactions
from fraud_detection import detect_fraud_gpu, detect_fraud_cpu, load_transactions
from txn_schema import canonicalize

# governance_common ships at the zip root in a deployed runtime (already on
# sys.path via the shim); for local CLI runs it lives at the repo root.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if os.path.isdir(os.path.join(_PROJECT_ROOT, "governance_common")) and _PROJECT_ROOT not in sys.path:
    sys.path.append(_PROJECT_ROOT)
from governance_common.deployed_runtime import refuse_local_mode_in_deployed_runtime  # noqa: E402
from governance_common.payload_limits import request_ref_ok  # noqa: E402

# AWS resources (conditional — not needed in --local mode)
REGION = os.environ.get("AWS_REGION", "us-east-1")
DETECTION_TABLE = os.environ.get("DETECTION_TABLE", "detection-results")
# Upper bound on caller-supplied transactions_inline.
MAX_TRANSACTIONS = int(os.environ.get("MAX_TRANSACTIONS", "50000"))
# Cap on invoker-facing pan_rejected_indices and on the refs stored inline in
# the main audit item. Refs beyond it go to chunk items, each of
# at most this many refs, keeping every item well under DynamoDB's 400 KB.
PAN_REJECTIONS_CAP = 500
# Cumulative character budget for transactions_inline: compact
# JSON length must not exceed 4x the pan_filter single-text cap (1,048,576),
# i.e. 4,194,304 chars — same value as pan_filter's MAX_BATCH_CHARS.
MAX_INLINE_BATCH_CHARS = 4 * 1_048_576
# Server-side dataset allowlist. A caller names a dataset by id;
# it can never name a file. Resolved under ALLOWED_TXN_DIR by load_transactions.
DATASETS = {"sample-small": "transactions_small.jsonl"}
DEFAULT_DATASET_ID = "sample-small"
# Sanity check (a) for flagged clusters.
MIN_CLUSTER_DISTINCT_TXNS = 3
CACHED_OUTPUT_PATH = os.environ.get(
    "CACHED_OUTPUT_PATH",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "cached_output", "detection_result.json"
    )
)


def _serialized_chars(transactions) -> "int | None":
    """Compact JSON length of the batch, or None if it cannot be serialized."""
    try:
        return len(json.dumps(transactions, ensure_ascii=False, separators=(",", ":")))
    except (TypeError, ValueError, RecursionError):
        return None


def _write_audit_enabled() -> bool:
    # Auto-enable in AgentCore Runtime (detected by /var/task).
    write_audit = os.environ.get("WRITE_AUDIT", "false").lower() == "true"
    if not write_audit and os.path.isdir("/var/task"):
        write_audit = True
    return write_audit


def handler(event: dict, context=None) -> dict:
    """
    Lambda handler for detection agent.

    Args:
        event: Lambda event with keys: mode (gpu|cpu|local), and either
            transactions_inline (list) or dataset_id (a key of DATASETS,
            default "sample-small"); optional request_ref (lowercase uuid4).
            transaction_file is refused: only the CLI can name a file.
        context: Lambda context object (None in local mode)

    Returns:
        Detection output dict matching the interface contract schema.
    """
    # Entry validation, matching the pan_filter handler: a str
    # event would make `"transactions_inline" in event` a substring test and
    # a list event would make .get raise AttributeError.
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    # A request can never select a file. The message is never
    # echoed to the caller (the shim returns a generic 500).
    if "transaction_file" in event:
        raise ValueError("transaction_file is not accepted")
    # A PAN-shaped uuid is refused too: request_ref is stored and archived.
    request_ref = event.get("request_ref")
    if request_ref is not None and not request_ref_ok(request_ref):
        raise ValueError("invalid request_ref")
    mode = event.get("mode", "local")

    # Defense in depth: even if a caller somehow reaches this
    # handler with mode=local in a DEPLOYED runtime, refuse it — local mode
    # returns a shipped fixture without running the PAN filter or writing an
    # audit record, so it must never be reachable in production. There is no
    # override (governance_common.deployed_runtime).
    refuse_local_mode_in_deployed_runtime(mode)

    if mode == "local":
        return run_local_mode(str(uuid.uuid4()), datetime.now(timezone.utc).isoformat())

    # Load transactions (inline payload or an allowlisted dataset)
    if "transactions_inline" in event:
        txns = event["transactions_inline"]
        # Same strictness as filter_transactions (type(...) is list), so a
        # non-list fails here with a clear error.
        if type(txns) is not list:
            raise ValueError("transactions_inline must be a JSON array")
        inline_source = True
    else:
        dataset_id = event.get("dataset_id", DEFAULT_DATASET_ID)
        if not isinstance(dataset_id, str) or dataset_id not in DATASETS:
            raise ValueError("unknown dataset_id")
        inline_source = False
        # Module-level name, so tests can monkeypatch h.load_transactions.
        txns = load_transactions(DATASETS[dataset_id])

    return _run_detection(txns, mode, inline_source=inline_source,
                          write_audit=_write_audit_enabled(), request_ref=request_ref)


def run_detection_from_file(path: str, mode: str = "cpu") -> dict:
    """CLI-only entry point: run detection over a path-confined file.

    The request-surface handler() never accepts a file name; scripts and the
    CLI call this instead. load_transactions keeps ALLOWED_TXN_DIR
    confinement, the suffix check and the size cap.
    """
    txns = load_transactions(path)
    return _run_detection(txns, mode, inline_source=False, write_audit=_write_audit_enabled())


def _run_detection(txns: list, mode: str, *, inline_source: bool, write_audit: bool,
                   request_ref: str | None = None) -> dict:
    detection_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    # Cap the workload from either source. Graph
    # PageRank and the per-component rescans are ~O(components × transactions);
    # an unbounded input lets one request dominate the single-worker CPU.
    if len(txns) > MAX_TRANSACTIONS:
        raise ValueError(
            f"transactions exceed the maximum of {MAX_TRANSACTIONS} transactions"
        )
    # Cumulative character budget for caller-supplied inline batches,
    # before any scanner work. The file source is server-side,
    # path-confined data and is not subject to it.
    if inline_source:
        inline_chars = _serialized_chars(txns)
        if inline_chars is None:
            raise ValueError("transactions_inline must be JSON-serializable")
        if inline_chars > MAX_INLINE_BATCH_CHARS:
            raise ValueError(
                f"transactions_inline exceeds the maximum serialized size of "
                f"{MAX_INLINE_BATCH_CHARS} characters"
            )

    # BLUEPRINT 1 — DATA & ACCESS CONTROLS: PAN ingress filter runs BEFORE any
    # graph processing, so no unmasked cardholder data ever enters detection.
    # === PAN INGRESS FILTER (BEFORE graph processing) ===
    clean_txns, rejected_count, rejection_details = filter_transactions(txns)
    pan_rejected_indices = sorted(d["index"] for d in rejection_details)
    pan_rejection_refs = None
    if rejected_count > 0:
        logger.warning("Rejected %d transactions containing PAN data", rejected_count)
        for detail in rejection_details[:PAN_REJECTIONS_CAP]:
            # Index only: not the rule that fired (an evasion oracle
            # for anyone reading the logs), the raw identifier (it may
            # carry the PAN) or the keyed txn_ref. Rule and txn_ref live
            # only in the audit item. Capped at PAN_REJECTIONS_CAP lines;
            # the remainder is one aggregate line below.
            logger.warning("  Rejected txn index=%d", detail["index"])
        if len(rejection_details) > PAN_REJECTIONS_CAP:
            logger.warning(
                "PAN filter: %d further rejection(s) not logged individually (cap %d)",
                len(rejection_details) - PAN_REJECTIONS_CAP, PAN_REJECTIONS_CAP,
            )
        # Server-side sink only: the audit item keeps the rule
        # and keyed txn_ref; the invoker sees indices only.
        pan_rejection_refs = [
            {"index": d["index"], "txn_ref": d["txn_ref"], "rule": d["rule"]}
            for d in rejection_details
        ]

    # === SCHEMA CANONICALIZATION ===
    # filter_transactions preserves order, so the k-th clean transaction maps
    # back to the k-th input index that was not PAN-rejected.
    rejected_set = set(pan_rejected_indices)
    clean_input_indices = [i for i in range(len(txns)) if i not in rejected_set]
    canonical, schema_rejections, schema_stats = canonicalize(clean_txns)
    schema_rejection_refs = [
        {"index": clean_input_indices[r["index"]], "reason_code": r["reason_code"]}
        for r in schema_rejections
    ]
    if schema_rejection_refs:
        logger.warning("Schema canonicalization rejected %d transactions", len(schema_rejection_refs))
    input_quality = {
        "transactions_in": len(txns),
        "transactions_used": len(canonical),
        "schema_rejected": schema_stats["schema_rejected"],
        "duplicates_rejected": schema_stats["duplicates_rejected"],
        "fields_dropped": schema_stats["fields_dropped"],
    }
    quality_fields = {
        "schema_rejected_count": len(clean_txns) - len(canonical),
        "fields_dropped": schema_stats["fields_dropped"],
        "input_quality": input_quality,
    }

    def _audit(output):
        if write_audit:
            write_to_dynamodb(output, pan_rejection_refs=pan_rejection_refs,
                              schema_rejection_refs=schema_rejection_refs,
                              console_request_ref=request_ref)

    if not canonical:
        error = ("All transactions rejected by PAN filter" if not clean_txns
                 else "All transactions rejected by schema validation")
        output = build_output(
            detection_id=detection_id,
            timestamp=timestamp,
            transaction_count=0,
            gpu_time_seconds=0.0,
            flagged_clusters=[],
            pagerank_top_10=[],
            pan_rejected_count=rejected_count,
            error=error,
            pan_rejected_indices=pan_rejected_indices,
            **quality_fields,
        )
        _audit(output)
        return output

    # === RUN DETECTION (canonical records only) ===
    if mode == "gpu":
        flagged_clusters, elapsed, pagerank_top_10 = detect_fraud_gpu(canonical)
    else:
        flagged_clusters, elapsed, pagerank_top_10 = detect_fraud_cpu(canonical)

    flagged_clusters = apply_cluster_sanity_checks(flagged_clusters, canonical)

    # Assign cluster IDs
    for cluster in flagged_clusters:
        cluster["cluster_id"] = str(uuid.uuid4())

    # Build output
    output = build_output(
        detection_id=detection_id,
        timestamp=timestamp,
        transaction_count=len(canonical),
        gpu_time_seconds=round(elapsed, 2),
        flagged_clusters=flagged_clusters,
        pagerank_top_10=pagerank_top_10,
        pan_rejected_count=rejected_count,
        pan_rejected_indices=pan_rejected_indices,
        **quality_fields,
    )
    _audit(output)
    return output


def apply_cluster_sanity_checks(flagged_clusters: list, canonical: list) -> list:
    """Sanity checks before persisting provenance-root evidence.

    (a) a cluster needs >= MIN_CLUSTER_DISTINCT_TXNS distinct intra-cluster
        txn_ids, else it is dropped;
    (b) total_amount_usd must equal the recomputed sum of distinct intra txns
        within 0.01, else evidence_flags gains AMOUNT_MISMATCH;
    (c) an account in two flagged clusters marks both OVERLAPPING_ACCOUNT.
    (b) and (c) are expected unreachable (defense in depth).
    """
    kept = []
    for cluster in flagged_clusters:
        members = set(cluster.get("accounts", []))
        distinct = {}
        for t in canonical:
            if t["sender_id"] in members and t["receiver_id"] in members:
                distinct.setdefault(t["txn_id"], t)
        if len(distinct) < MIN_CLUSTER_DISTINCT_TXNS:
            continue
        flags = []
        recomputed = sum(t["amount"] for t in distinct.values())
        if abs(float(cluster.get("total_amount_usd", 0)) - recomputed) > 0.01:
            flags.append("AMOUNT_MISMATCH")
        kept.append((cluster, members, flags))

    seen = {}
    for idx, (_, members, _) in enumerate(kept):
        for account in members:
            seen.setdefault(account, set()).add(idx)
    overlapping = {i for owners in seen.values() if len(owners) > 1 for i in owners}

    result = []
    for idx, (cluster, _, flags) in enumerate(kept):
        if idx in overlapping:
            flags.append("OVERLAPPING_ACCOUNT")
        if flags:
            cluster["evidence_flags"] = flags
        result.append(cluster)
    return result


def run_local_mode(detection_id: str, timestamp: str) -> dict:
    """
    --local mode: read from pre-cached output file.
    Stage-safe fallback that doesn't require GPU.
    """
    if os.path.exists(CACHED_OUTPUT_PATH):
        with open(CACHED_OUTPUT_PATH, "r", encoding="utf-8") as f:
            cached = json.load(f)
        # Override with fresh IDs
        cached["detection_id"] = detection_id
        cached["timestamp"] = timestamp
        logger.info("Loaded cached detection result (%d clusters)", len(cached.get('flagged_clusters', [])))
        return cached
    else:
        logger.info("No cached output at %s, returning empty result", CACHED_OUTPUT_PATH)
        return build_output(
            detection_id=detection_id,
            timestamp=timestamp,
            transaction_count=0,
            gpu_time_seconds=0.0,
            flagged_clusters=[],
            pagerank_top_10=[],
        )


# ═════════════════════════════════════════════════════════════════════════════
# BLUEPRINT 2 — DECISION EXPLAINABILITY (detection evidence)
# ═════════════════════════════════════════════════════════════════════════════
# Detection does not emit a bare "fraud/not-fraud" verdict. Every flagged
# cluster carries its supporting evidence: typology, the PageRank scores that
# surfaced it, and per-cluster confidence_factors (circular ratio, fan-in/out,
# avg amount). This structured, human-readable basis is written to the audit
# trail and handed to the compliance agent so every downstream decision is
# traceable back to the exact signals that produced it.
# ═════════════════════════════════════════════════════════════════════════════
def build_output(
    detection_id: str,
    timestamp: str,
    transaction_count: int,
    gpu_time_seconds: float,
    flagged_clusters: list,
    pagerank_top_10: list,
    pan_rejected_count: int = 0,
    error: str = None,
    pan_rejected_indices: list | None = None,
    schema_rejected_count: int | None = None,
    fields_dropped: int | None = None,
    input_quality: dict | None = None,
) -> dict:
    """Build the structured detection output per the interface contract.

    Invoker-facing PAN detail is indices only: no rule, no
    reason and no txn_ref, so the output is not a per-rule oracle.
    pan_rejected_indices is sorted and capped at PAN_REJECTIONS_CAP entries.
    """
    output = {
        "detection_id": detection_id,
        "timestamp": timestamp,
        "transaction_count": transaction_count,
        "gpu_time_seconds": gpu_time_seconds,
        "flagged_clusters": flagged_clusters,
        "pagerank_top_10": pagerank_top_10,
    }
    if pan_rejected_count > 0:
        output["pan_rejected_count"] = pan_rejected_count
        indices = sorted(int(i) for i in (pan_rejected_indices or []))
        output["pan_rejected_indices"] = indices[:PAN_REJECTIONS_CAP]
        output["pan_rejected_indices_truncated"] = len(indices) > PAN_REJECTIONS_CAP
    if schema_rejected_count is not None:
        output["schema_rejected_count"] = schema_rejected_count
    if fields_dropped is not None:
        output["fields_dropped"] = fields_dropped
    if input_quality is not None:
        output["input_quality"] = dict(input_quality)
    if error:
        output["error"] = error
    return output


def _utc_day(timestamp: str) -> str:
    try:
        dt = datetime.fromisoformat(timestamp)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.date().isoformat()
    except (TypeError, ValueError):
        return datetime.now(timezone.utc).date().isoformat()


def _chunks(refs: list) -> list:
    return [refs[i:i + PAN_REJECTIONS_CAP] for i in range(0, len(refs), PAN_REJECTIONS_CAP)]


def write_to_dynamodb(output: dict, pan_rejection_refs: list | None = None,
                      schema_rejection_refs: list | None = None,
                      console_request_ref: str | None = None):
    """Write detection result to DynamoDB audit trail (fail closed).

    The first PAN_REJECTIONS_CAP pan/schema rejection refs are stored inline
    on the main item; the rest go to chunk items
    ``<detection_id>#rejections#NNNN`` / ``<detection_id>#schema-rejections#NNNN``
    written BEFORE the main item so the main item never claims
    chunks that don't exist. Any write failure raises. ``output`` is never
    mutated, so the keyed txn_ref never reaches the invoker.
    """
    from decimal import Decimal
    try:
        dynamodb = boto3.resource("dynamodb", region_name=REGION)
        table = dynamodb.Table(DETECTION_TABLE)
        detection_id = output["detection_id"]
        extra = {}
        for refs, attr, suffix, record_type in (
            (pan_rejection_refs, "pan_rejection_refs", "rejections", "PAN_REJECTION_REFS"),
            (schema_rejection_refs, "schema_rejection_refs", "schema-rejections",
             "SCHEMA_REJECTION_REFS"),
        ):
            if refs is None:
                continue
            refs = list(refs)
            overflow = _chunks(refs[PAN_REJECTIONS_CAP:])
            for n, chunk in enumerate(overflow, 1):
                table.put_item(Item={
                    "detection_id": f"{detection_id}#{suffix}#{n:04d}",
                    "record_type": record_type,
                    "parent_detection_id": detection_id,
                    "refs": chunk,
                })
            extra[attr] = refs[:PAN_REJECTIONS_CAP]
            extra[f"{attr[:-1]}_chunks"] = len(overflow)
        # DynamoDB doesn't support float — convert to Decimal
        item = json.loads(json.dumps(output), parse_float=Decimal)
        item = {**item, **extra, "record_day": _utc_day(output.get("timestamp"))}
        if console_request_ref is not None:
            item["console_request_ref"] = console_request_ref
        table.put_item(Item=item)
        logger.info("Written detection result %s to %s", detection_id, DETECTION_TABLE)
    except Exception as e:
        # WARNING: re-raised (fail-closed); the AgentCore entrypoint logs it at
        # ERROR. Class name only, so no item content can reach the logs.
        logger.warning("Failed to write to DynamoDB (%s)", type(e).__name__)
        raise


# === CLI Entry Point ===
def main():
    parser = argparse.ArgumentParser(description="Detection Agent — Fraud Ring Detection")
    parser.add_argument("--local", action="store_true", help="Use pre-cached output (no GPU required)")
    parser.add_argument("--mode", choices=["gpu", "cpu", "local"], default="local",
                        help="Detection mode (default: local)")
    parser.add_argument("--file", type=str, default="data/transactions_small.jsonl",
                        help="Path to transactions JSONL file")
    parser.add_argument("--output", type=str, default=None,
                        help="Write output to file (default: stdout)")
    args = parser.parse_args()

    mode = "local" if args.local else args.mode
    if mode == "local":
        result = handler({"mode": "local"})
    else:
        result = run_detection_from_file(args.file, mode)

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
