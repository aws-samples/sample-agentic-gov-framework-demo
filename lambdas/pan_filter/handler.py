"""
PAN Ingress Filter — Lambda Handler.

Standalone Lambda with ZERO external dependencies (pure stdlib).
Runs at the API Gateway / ingress layer to reject PAN-laden payloads
before they reach the heavier detection agent.

IAM Identity (NHI #0: pan-filter-role):
- CAN: Be invoked by API Gateway or other Lambdas
- CANNOT: Read/write DynamoDB, invoke Bedrock, access S3
"""
import json
import logging
import os

from pan_filter import contains_full_pan, filter_transactions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Upper bound on the single-text payload, in characters.
# Not configurable by environment.
MAX_TEXT_CHARS = 1_048_576

# Cumulative character budget for batch mode: the compact JSON
# serialization of `transactions` must not exceed 4x the single-text cap
# (4,194,304 chars). Bounds scanner work (NFKC, per-character classes, Luhn
# windows) at four times the accepted single-text worst case, well below the
# 6 MB synchronous Lambda payload limit; the demo dataset (~104 KB) has ~40x
# headroom. Not configurable by environment.
MAX_BATCH_CHARS = 4 * MAX_TEXT_CHARS

# Cap on per-rejection WARNING log lines per invocation; same
# value as the detection handler's PAN_REJECTIONS_CAP. The
# remainder is reported as one aggregate line.
PAN_REJECTIONS_CAP = 500

USAGE = {
    "error": "No transactions or text provided",
    "usage": "Pass {\"transactions\": [...]} or {\"text\": \"...\"}",
}


def _max_transactions() -> int:
    """Current batch cap, read at call time so the environment is authoritative."""
    return int(os.environ.get("MAX_TRANSACTIONS", "50000"))


def _serialized_chars(transactions) -> "int | None":
    """Compact JSON length of the batch, or None if it cannot be serialized."""
    try:
        return len(json.dumps(transactions, ensure_ascii=False, separators=(",", ":")))
    except (TypeError, ValueError, RecursionError):
        return None


def handler(event: dict, context=None) -> dict:
    """
    Lambda handler for PAN ingress filtering.

    Accepts:
      - {"transactions": [...]}  — batch mode, returns counts + rejected_indices
      - {"text": "..."}          — single-text mode, returns {contains_pan: bool}

    Returns:
      Structured response with filtering results.
    """
    # Entry validation: a str event would make `"text" in event`
    # a substring test and a list event would make .get raise.
    if not isinstance(event, dict):
        return {"error": "event must be a JSON object"}

    # Single-text check mode
    if "text" in event:
        text = event["text"]
        if not isinstance(text, str):
            return {"error": "text must be a string"}
        if len(text) > MAX_TEXT_CHARS:
            return {"error": "text too long"}
        has_pan = contains_full_pan(text)
        return {
            "contains_pan": has_pan,
            "action": "BLOCKED" if has_pan else "ALLOWED",
        }

    # Batch transaction mode — normative check order.
    # None of these checks does any per-element work.
    transactions = event.get("transactions")
    if transactions is None:
        return USAGE
    if type(transactions) is not list:
        return {"error": "transactions must be a JSON array"}
    if not transactions:
        return USAGE
    max_transactions = _max_transactions()
    if len(transactions) > max_transactions:
        return {"error": f"transactions exceeds the maximum of {max_transactions}"}
    # Cumulative character budget — checked after the entry checks
    # above, still before any scanner work.
    batch_chars = _serialized_chars(transactions)
    if batch_chars is None:
        return {"error": "transactions must be JSON-serializable"}
    if batch_chars > MAX_BATCH_CHARS:
        return {
            "error": f"transactions exceeds the maximum serialized size of "
                     f"{MAX_BATCH_CHARS} characters"
        }

    clean, rejected_count, details = filter_transactions(transactions)

    # Return counts and rejected indices only — do not echo
    # clean_transactions back to the invoker. The invoker
    # already has its own input; echoing it back serves no purpose here and
    # widens what a caller who can only reach this standalone Lambda learns.
    # Neither the rule/reason (a per-rule oracle for iterating encodings)
    # nor the keyed txn_ref (an HMAC oracle) is
    # returned.
    response = {
        "total_input": len(transactions),
        "allowed_count": len(clean),
        "rejected_count": rejected_count,
        "rejected_indices": sorted(d["index"] for d in details),
    }

    # Per-rejection lines capped at PAN_REJECTIONS_CAP; the
    # remainder is one aggregate count line. Index only: neither the rule
    # that fired (an evasion oracle for anyone reading the logs) nor the
    # keyed txn_ref is logged.
    for d in details[:PAN_REJECTIONS_CAP]:
        logger.warning("PAN filter rejected index=%d", d["index"])
    if len(details) > PAN_REJECTIONS_CAP:
        logger.warning(
            "PAN filter: %d further rejection(s) not logged individually (cap %d)",
            len(details) - PAN_REJECTIONS_CAP, PAN_REJECTIONS_CAP,
        )
    if rejected_count > 0:
        logger.warning(
            "PAN filter rejected %d/%d transactions",
            rejected_count, len(transactions),
        )

    return response
