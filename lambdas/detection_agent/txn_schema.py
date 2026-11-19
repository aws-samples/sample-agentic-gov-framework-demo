"""
Transaction schema canonicalization.

Runs on the transactions the PAN ingress filter accepted, before graph
detection. Only allowlisted fields survive, every identifier is normalized
(NFKC + casefold + ASCII charset) and holds at most 12 digits, the amount is
quantized to cents and the timestamp is canonicalized to naive-UTC seconds.
So no single surviving field can carry a 13-19-digit PAN, and case /
confusable / whitespace variants of one counterparty become one graph node.

canonicalize() is total: it never raises on element shape. Each rejected
transaction gets one reason code; the function itself decides nothing else.
"""
import math
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from pan_filter import _scan_transaction  # noqa: E402  same top-level module as handler.py

ALLOWED_FIELDS = ("txn_id", "sender_id", "receiver_id", "amount", "timestamp", "merchant_category")
ID_RE = re.compile(r"[a-z0-9._-]{1,64}")      # after NFKC + casefold + strip; ASCII only
MAX_ID_DIGITS = 12                             # < 13 = shortest PAN
CATEGORY_RE = re.compile(r"[a-z_]{1,32}")
MAX_AMOUNT = 1_000_000_000.0
MAX_TIMESTAMP_CHARS = 40
MIN_YEAR = 2000
MAX_YEAR = 2100

_CENT = Decimal("0.01")
_PRECISION_LIMIT = Decimal("0.001")

# Reason codes (stored in the audit item's schema_rejection_refs only).
NOT_OBJECT = "NOT_OBJECT"
ID_TYPE = "ID_TYPE"
ID_CHARSET = "ID_CHARSET"
ID_DIGITS = "ID_DIGITS"
SELF_LOOP = "SELF_LOOP"
AMOUNT = "AMOUNT"
AMOUNT_PRECISION = "AMOUNT_PRECISION"
TIMESTAMP = "TIMESTAMP"
CATEGORY = "CATEGORY"
DUPLICATE_TXN_ID = "DUPLICATE_TXN_ID"
PAN_IN_PROJECTION = "PAN_IN_PROJECTION"


class _Reject(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _identifier(value) -> str:
    if not isinstance(value, str):
        raise _Reject(ID_TYPE)
    normalized = unicodedata.normalize("NFKC", value).casefold().strip()
    if ID_RE.fullmatch(normalized) is None:
        raise _Reject(ID_CHARSET)
    if sum(1 for ch in normalized if "0" <= ch <= "9") > MAX_ID_DIGITS:
        raise _Reject(ID_DIGITS)
    return normalized


def _amount(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Reject(AMOUNT)
    if isinstance(value, float) and not math.isfinite(value):
        raise _Reject(AMOUNT)
    if not 0 < value <= MAX_AMOUNT:
        raise _Reject(AMOUNT)
    try:
        exact = Decimal(str(value))
        quantized = exact.quantize(_CENT, rounding=ROUND_HALF_EVEN)
    except (InvalidOperation, ValueError):
        raise _Reject(AMOUNT)
    # A meaningful sub-cent value is rejected rather than silently changed;
    # float noise below 0.001 (e.g. 100.10000000000001) is quantized.
    if abs(exact - quantized) >= _PRECISION_LIMIT:
        raise _Reject(AMOUNT_PRECISION)
    if quantized <= 0:
        raise _Reject(AMOUNT)
    return float(quantized)


def _timestamp(value) -> str:
    if not isinstance(value, str) or len(value) > MAX_TIMESTAMP_CHARS:
        raise _Reject(TIMESTAMP)
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        raise _Reject(TIMESTAMP)
    if not MIN_YEAR <= dt.year <= MAX_YEAR:
        raise _Reject(TIMESTAMP)
    return dt.replace(microsecond=0).isoformat(timespec="seconds")


def _category(txn: dict) -> str:
    if "merchant_category" not in txn:
        return ""
    value = txn["merchant_category"]
    if not isinstance(value, str):
        raise _Reject(CATEGORY)
    folded = value.casefold()
    if CATEGORY_RE.fullmatch(folded) is None:
        raise _Reject(CATEGORY)
    return folded


def _project(txn, index: int) -> dict:
    if not isinstance(txn, dict):
        raise _Reject(NOT_OBJECT)
    sender = _identifier(txn.get("sender_id"))
    receiver = _identifier(txn.get("receiver_id"))
    txn_id = _identifier(txn["txn_id"]) if "txn_id" in txn else f"auto-{index}"
    if sender == receiver:
        raise _Reject(SELF_LOOP)
    return {
        "txn_id": txn_id,
        "sender_id": sender,
        "receiver_id": receiver,
        "amount": _amount(txn.get("amount")),
        "timestamp": _timestamp(txn.get("timestamp")),
        "merchant_category": _category(txn),
    }


def canonicalize(txns: list) -> tuple:
    """Project and normalize each transaction.

    Returns (canonical_txns, rejections, stats):
      - canonical_txns: dicts with exactly ALLOWED_FIELDS, normalized values,
        in input order;
      - rejections: [{"index", "reason_code"}], index into ``txns``;
      - stats: {"fields_dropped", "duplicates_rejected", "schema_rejected"};
        fields_dropped counts non-schema keys removed from accepted records.
    """
    canonical = []
    rejections = []
    stats = {"fields_dropped": 0, "duplicates_rejected": 0, "schema_rejected": 0}
    seen_ids = set()
    for index, txn in enumerate(txns if isinstance(txns, list) else []):
        try:
            projected = _project(txn, index)
            if projected["txn_id"] in seen_ids:
                raise _Reject(DUPLICATE_TXN_ID)
            # Defense in depth: X4 on the projected record (expected
            # unreachable given the per-identifier digit cap).
            if _scan_transaction(projected) is not None:
                raise _Reject(PAN_IN_PROJECTION)
        except _Reject as rej:
            rejections.append({"index": index, "reason_code": rej.code})
            if rej.code == DUPLICATE_TXN_ID:
                stats["duplicates_rejected"] += 1
            continue
        seen_ids.add(projected["txn_id"])
        stats["fields_dropped"] += sum(1 for key in txn if key not in ALLOWED_FIELDS)
        canonical.append(projected)
    stats["schema_rejected"] = len(rejections)
    return canonical, rejections, stats
