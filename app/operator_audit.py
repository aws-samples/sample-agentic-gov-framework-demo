"""
Operator audit.

record_console_action() stamps every console governance action with the
signed-in principal. Fail-closed contract for callers: write REQUESTED
before acting and do not act if that raises; COMPLETED/FAILED afterwards is
best effort.

Sinks:
- MODE=live: PutItem to the operator-audit table (attribute_not_exists on
  event_id) through the principal's own operator session; never ambient
  credentials.
- MODE=local: one JSON line appended (O_APPEND + fsync) to
  <LOCAL_OUTPUT_DIR or cached_output>/operator_audit.jsonl.

SIGN_IN_FAILED is never written to DynamoDB and never through any AWS
session: passing a session for it is a programming error (ValueError).
Records hold ids, enums and short scalars only: never passwords, tokens,
exception text or request payloads.
"""
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from app.console_identity import NoAwsAuthorityError, Principal, actor_fields
from governance_common.payload_limits import new_request_ref

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGION = os.environ.get("AWS_REGION", "us-east-1")
TABLE_NAME = "operator-audit"  # fixed (cdk/data_stack.py); no env override
JSONL_NAME = "operator_audit.jsonl"

ACTIONS = frozenset({
    "PIPELINE_RUN", "PAN_TEST", "INJECTION_TEST", "SOX_TEST", "BREAKER_TRIP",
    "RELEASE_REQUEST", "RELEASE_APPROVE", "DRIFT_INJECTION", "AUDIT_READ",
    "GATE_RUN", "MODEL_REGISTRY_VIEW", "SIGN_IN", "SIGN_OUT", "SIGN_IN_FAILED",
})
PHASES = frozenset({"REQUESTED", "COMPLETED", "FAILED"})

SINK_JSONL = "jsonl"
SINK_DYNAMODB = "dynamodb"
SINKS = frozenset({SINK_JSONL, SINK_DYNAMODB})

MAX_DETAIL_KEYS = 20
MAX_DETAIL_STR = 256
INVALID_OPERATOR_ID = "<invalid>"

_DETAIL_KEY_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_TARGET_RE = re.compile(r"[A-Za-z0-9._:#/-]{1,256}")
_OUTCOME_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_OPERATOR_ID_RE = re.compile(r"[a-z][a-z0-9_-]{2,31}")


def valid_target(value) -> str | None:
    """`value` if it is a well-formed target id, else None (callers pass
    record ids through this rather than failing the audit write)."""
    return value if isinstance(value, str) and _TARGET_RE.fullmatch(value) else None


def _validate_details(details) -> dict:
    if details is None:
        return {}
    if not isinstance(details, dict) or len(details) > MAX_DETAIL_KEYS:
        raise ValueError("details must be a dict of at most 20 keys")
    clean = {}
    for key, value in details.items():
        if not isinstance(key, str) or not _DETAIL_KEY_RE.fullmatch(key):
            raise ValueError("invalid details key")
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("details values must be str or int")
        if isinstance(value, str) and len(value) > MAX_DETAIL_STR:
            raise ValueError("details string value too long")
        clean[key] = value
    return clean


def _output_dir() -> Path:
    return Path(os.environ.get("LOCAL_OUTPUT_DIR") or PROJECT_ROOT / "cached_output")


def _append_jsonl(item: dict) -> None:
    out_dir = _output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(item, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(out_dir / JSONL_NAME, flags, 0o600)
    try:
        view = memoryview(line)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)


def _put_dynamodb(item: dict, session) -> None:
    if session is None:
        raise NoAwsAuthorityError()
    table = session.resource("dynamodb", region_name=REGION).Table(TABLE_NAME)
    table.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")


def record_console_action(principal, action, phase, target=None, outcome=None, details=None,
                          session=None, *, sink=None, attempted_operator_id=None) -> str:
    """Write one operator-audit record and return its event_id.

    Raises ValueError on a malformed call, NoAwsAuthorityError when the live
    sink has no session, and any sink error unchanged (callers decide)."""
    if action not in ACTIONS:
        raise ValueError("unknown operator-audit action")
    if phase not in PHASES:
        raise ValueError("unknown operator-audit phase")
    if action == "SIGN_IN_FAILED":
        if session is not None:
            raise ValueError("SIGN_IN_FAILED is never written through an AWS session")
        sink = SINK_JSONL
    elif not isinstance(principal, Principal):
        raise ValueError("a signed-in principal is required")
    if sink is None:
        sink = SINK_DYNAMODB if os.environ.get("MODE", "local") == "live" else SINK_JSONL
    if sink not in SINKS:
        raise ValueError("unknown operator-audit sink")
    if target is not None and (not isinstance(target, str) or not _TARGET_RE.fullmatch(target)):
        raise ValueError("target must be an id")
    if outcome is not None and (not isinstance(outcome, str) or not _OUTCOME_RE.fullmatch(outcome)):
        raise ValueError("outcome must be a short code")
    clean_details = _validate_details(details)

    now = datetime.now(timezone.utc)
    # The event id doubles as the agents' request_ref, which refuse a
    # PAN-shaped uuid; new_request_ref regenerates one (about 2 % of ids).
    event_id = new_request_ref()
    item = {
        "event_id": event_id,
        "record_day": now.date().isoformat(),
        "timestamp": now.isoformat(),
        "event_type": "CONSOLE_ACTION",
        "action": action,
        "phase": phase,
    }
    if target is not None:
        item["target"] = target
    if outcome is not None:
        item["outcome"] = outcome
    if clean_details:
        item["details"] = clean_details
    if action == "SIGN_IN_FAILED":
        valid = isinstance(attempted_operator_id, str) and _OPERATOR_ID_RE.fullmatch(attempted_operator_id)
        item["attempted_operator_id"] = attempted_operator_id if valid else INVALID_OPERATOR_ID
    else:
        item.update(actor_fields(principal))

    if sink == SINK_DYNAMODB:
        _put_dynamodb(item, session)
    else:
        _append_jsonl(item)
    return event_id
