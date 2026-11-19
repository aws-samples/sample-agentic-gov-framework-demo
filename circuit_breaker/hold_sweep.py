"""
Governance-hold state.

The governance-state item (governance_state.py) is the source of truth:
the hold is active when its status is HELD, or when a trip recorded in the
governance-audit index never managed to claim the item (unclaimed_hold).
Every reader (sweep, alarm recheck, release request/approval and the
post-detach check) uses that one rule. hold_active() is the pre-upgrade
fallback for when the item does not exist yet: it reads the newest hold,
intent and release events from the by_event_type index.

This module imports nothing from handler.py: every dependency is a
parameter, so both modules can import each other's callers without a cycle.
"""
from collections import namedtuple
from datetime import datetime, timedelta, timezone

HOLD_EVENT_TYPES = ("GOVERNANCE_HOLD", "GOVERNANCE_HOLD_INTENT")
RELEASE_EVENT_TYPES = ("GOVERNANCE_HOLD_RELEASED", "BREAK_GLASS_RELEASE_STARTED")
INTENT_PREFIX = "intent-"

# held_at is the client time taken just before the claim call, which can
# take up to 3 s (one single-attempt call: connect 1 s + read 2 s). 5 s
# covers that plus clock skew.
CLAIM_SLACK_SECONDS = 5

_OLDEST = datetime.min.replace(tzinfo=timezone.utc)

# active: the newest hold/intent is newer than the newest release.
# hold_event_id: event_id of the newest hold/intent (None if none).
# newest_hold_at: its parsed timestamp (None if none).
# newest_event_at: the newest parsed timestamp over all four types (None if
#   there is no history at all).
HoldState = namedtuple("HoldState", "active hold_event_id newest_hold_at newest_event_at")


def parse_timestamp(value):
    """Aware datetime, or None. A naive value is treated as UTC."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _newest(table, event_type):
    from boto3.dynamodb.conditions import Key
    page = table.query(
        IndexName="by_event_type",
        KeyConditionExpression=Key("event_type").eq(event_type),
        ScanIndexForward=False,
        Limit=1,
    )
    items = page.get("Items", [])
    return items[0] if items else None


def hold_active(table, now=None) -> HoldState:
    """Hold state from the four newest events. Raises on a query error
    (callers treat that as "unknown", never as "no hold")."""
    newest = {t: _newest(table, t) for t in HOLD_EVENT_TYPES + RELEASE_EVENT_TYPES}

    def when(item):
        # A missing or unparseable timestamp counts as the oldest.
        return (parse_timestamp(item.get("timestamp")) or _OLDEST) if item else None

    holds = [(when(newest[t]), newest[t]) for t in HOLD_EVENT_TYPES if newest[t]]
    releases = [when(newest[t]) for t in RELEASE_EVENT_TYPES if newest[t]]
    hold_at, hold_item = max(holds, key=lambda h: h[0]) if holds else (None, None)
    release_at = max(releases) if releases else None
    active = hold_at is not None and (release_at is None or hold_at > release_at)
    every = [h[0] for h in holds] + releases
    return HoldState(
        active=active,
        hold_event_id=hold_item.get("event_id") if hold_item else None,
        newest_hold_at=hold_at,
        newest_event_at=max(every) if every else None,
    )


# ─── Governance-state item ───────────────────────────────────────

def state_from_item(item) -> HoldState:
    """HoldState from the governance-state item. newest_event_at includes
    break_glass_at, so a break-glass inside an alarm episode suppresses the
    alarm recheck the same way a release does."""
    times = [parse_timestamp(item.get(k)) for k in ("held_at", "released_at", "break_glass_at")]
    times = [t for t in times if t is not None]
    return HoldState(
        active=item.get("status") == "HELD",
        hold_event_id=item.get("hold_event_id"),
        newest_hold_at=parse_timestamp(item.get("held_at")),
        newest_event_at=max(times) if times else None,
    )


def claim_baseline(state_item):
    """The latest time a trip can have started and still be covered by the
    current claim: max(held_at + CLAIM_SLACK_SECONDS, break_glass_at), over
    whichever parse; None if neither does. released_at is deliberately left
    out: a trip whose claim failed while an in-band release was in flight
    must still count as unclaimed."""
    held_at = parse_timestamp(state_item.get("held_at"))
    candidates = [parse_timestamp(state_item.get("break_glass_at"))]
    if held_at is not None:
        candidates.append(held_at + timedelta(seconds=CLAIM_SLACK_SECONDS))
    candidates = [c for c in candidates if c is not None]
    return max(candidates) if candidates else None


def record_start(record):
    """A hold/intent record's trip start (trip_started_at, else timestamp)."""
    return parse_timestamp(record.get("trip_started_at") or record.get("timestamp"))


def unclaimed_hold(table, state_item):
    """The newest hold or intent record of a trip that never claimed the
    state item, or None. Raises on a query error.

    A record is unclaimed when its id (intent- prefix stripped) is not the
    item's hold_event_id and its start is strictly after claim_baseline().
    A missing or unparseable start, or no baseline, counts as unclaimed
    (fail closed).

    Every trip's start precedes its own claim, and a claim request lands
    within 3 s of the held_at it carries, so any trip that claimed before
    the current claimant's write landed started before held_at + 3 s, inside
    the baseline. For INTENT records (written at the start, sorted by start)
    the newest is sufficient: if any trip started after the baseline, the
    newest intent did too. GOVERNANCE_HOLD records are sorted by write time
    and are a secondary signal for a trip whose intent write failed.
    """
    baseline = claim_baseline(state_item)
    current = state_item.get("hold_event_id")
    for event_type in HOLD_EVENT_TYPES:
        record = _newest(table, event_type)
        if record is None:
            continue
        event_id = str(record.get("event_id", ""))
        if event_id.startswith(INTENT_PREFIX):
            event_id = event_id[len(INTENT_PREFIX):]
        if event_id == current:
            continue
        start = record_start(record)
        if start is None or baseline is None or start > baseline:
            return record
    return None


def current_hold(table, read_state, now=None):
    """(HoldState, unclaimed record or None) by the one rule: the state item
    when it exists (HELD, or an unclaimed trip), else the hold_active()
    index fallback. Raises on any read error."""
    item = read_state() if read_state is not None else None
    if item is None:
        return hold_active(table, now), None
    state = state_from_item(item)
    if state.active:
        return state, None
    unclaimed = unclaimed_hold(table, item)
    if unclaimed is None:
        return state, None
    event_id = str(unclaimed.get("event_id", ""))
    if event_id.startswith(INTENT_PREFIX):
        event_id = event_id[len(INTENT_PREFIX):]
    hold_at = parse_timestamp(unclaimed.get("timestamp"))
    every = [t for t in (state.newest_event_at, record_start(unclaimed), hold_at) if t is not None]
    return state._replace(active=True, hold_event_id=event_id or None, newest_hold_at=hold_at,
                          newest_event_at=max(every) if every else None), unclaimed


# ─── Reconciling sweep (partial containment) ─────────────────────
#
# While the governance hold is active, re-attach governance-hold-deny-all to
# any agent role missing it. Attach-only: this module never detaches (its
# deployed role, governance-hold-sweep-role, has no iam:DetachRolePolicy
# either). Idempotent: nothing missing -> no IAM write, no audit write.

import logging  # noqa: E402
import uuid  # noqa: E402

logger = logging.getLogger(__name__)

RECONCILED_EVENT_TYPE = "GOVERNANCE_HOLD_RECONCILED"
MIN_HOLD_AGE_SECONDS = 60
MAX_LIST_PAGES = 10
RETENTION_EXPIRES = "2033-08-17T00:00:00Z"


class HoldReconcileAuditError(RuntimeError):
    """The GOVERNANCE_HOLD_RECONCILED record could not be written (after the
    attach: containment first)."""


def _error_class(exc) -> str:
    response = getattr(exc, "response", None)
    code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
    if code in ("AccessDenied", "AccessDeniedException"):
        return "AccessDenied"
    if code in ("Throttling", "ThrottlingException"):
        return "Throttling"
    return "Unknown"


def _held_roles(iam, roles, deny_policy_arn):
    """Roles with the deny-all attached. A list error counts as missing."""
    held = []
    for role in roles:
        try:
            kwargs = {"RoleName": role}
            for _page in range(MAX_LIST_PAGES):
                page = iam.list_attached_role_policies(**kwargs)
                if any(isinstance(p, dict) and p.get("PolicyArn") == deny_policy_arn
                       for p in page.get("AttachedPolicies", []) or []):
                    held.append(role)
                    break
                marker = page.get("Marker")
                if page.get("IsTruncated") is not True or not isinstance(marker, str) or not marker:
                    break
                kwargs["Marker"] = marker
        except Exception as exc:  # noqa: BLE001 - unverifiable == missing
            logger.warning("sweep: could not list attached policies for %s (%s)", role, _error_class(exc))
    return held


def reconcile_hold(iam, table, *, roles, deny_policy_arn, trigger, emit_metric, hold_event_id=None,
                   assume_active=False, now=None, read_state=None) -> dict:
    """Re-attach the deny-all to every role missing it while the hold is
    active. Never detaches and never writes the state item. Audited
    (GOVERNANCE_HOLD_RECONCILED) only when something was missing.

    read_state() returns the governance-state item (consistent read) or
    None; when it is not given, or the item does not exist yet, the hold
    state comes from the index (hold_active). Acting on a trip that never
    claimed the item emits HoldStateWriteFailed.

    assume_active=True (the breaker's own post-trip reconcile) skips the
    hold-state reads: the caller has just written the hold.
    """
    now = now or datetime.now(timezone.utc)
    if not assume_active:
        try:
            state, unclaimed = current_hold(table, read_state, now)
        except Exception as exc:  # noqa: BLE001 - unknown state: no attach, alert
            logger.error("sweep: hold-state query failed (%s); no attach", type(exc).__name__)
            emit_metric("HoldSweepFailed", 1)
            return {"status": "ERROR"}
        if not state.active:
            return {"status": "NO_HOLD"}
        if state.newest_hold_at is not None and (now - state.newest_hold_at).total_seconds() < MIN_HOLD_AGE_SECONDS:
            return {"status": "HOLD_TOO_RECENT"}  # the trip's own post-trip reconcile covers it
        if unclaimed is not None:
            logger.error("sweep: a trip never claimed the governance-state item; enforcing it "
                         "as the active hold")
            emit_metric("HoldStateWriteFailed", 1)
        hold_event_id = hold_event_id or state.hold_event_id

    held = _held_roles(iam, roles, deny_policy_arn)
    missing = [r for r in roles if r not in held]
    if not missing:
        return {"status": "HOLD_CONFIRMED", "roles_held": held}

    if not assume_active:
        # A release may have landed since the first read (it detaches after
        # writing GOVERNANCE_HOLD_RELEASED): never re-attach over it.
        try:
            if not current_hold(table, read_state, now)[0].active:
                return {"status": "NO_HOLD", "raced_release": True}
        except Exception as exc:  # noqa: BLE001
            logger.error("sweep: hold-state re-check failed (%s); no attach", type(exc).__name__)
            emit_metric("HoldSweepFailed", 1)
            return {"status": "ERROR"}

    reattached, attach_failures = [], {}
    for role in missing:
        try:
            iam.attach_role_policy(RoleName=role, PolicyArn=deny_policy_arn)
            reattached.append(role)
            logger.warning("sweep: re-attached the governance hold to %s", role)
        except Exception as exc:  # noqa: BLE001
            error_id = str(uuid.uuid4())
            logger.error("sweep: re-attach failed for %s [%s] (%s)", role, error_id, type(exc).__name__)
            attach_failures[role] = {"error_id": error_id, "error_class": _error_class(exc)}
    confirmed_after = _held_roles(iam, roles, deny_policy_arn)

    record = {
        "event_id": f"reconcile#{uuid.uuid4()}",
        "event_type": RECONCILED_EVENT_TYPE,
        "timestamp": now.isoformat(),
        "hold_event_id": hold_event_id or "UNKNOWN",
        "trigger": trigger,
        "roles_reattached": reattached,
        "roles_already_held": held,
        "attach_failures": attach_failures,
        "roles_confirmed_after": confirmed_after,
        "retention_expires": RETENTION_EXPIRES,
    }
    try:
        table.put_item(Item=record, ConditionExpression="attribute_not_exists(event_id)")
    except Exception as exc:  # noqa: BLE001
        logger.error("sweep: GOVERNANCE_HOLD_RECONCILED write failed (%s)", type(exc).__name__)  # nosemgrep: logging-error-without-handling -- fail-closed: reconcile audit write failure stays ERROR, re-raised as HoldReconcileAuditError; class name only
        raise HoldReconcileAuditError("governance-audit write failed (GOVERNANCE_HOLD_RECONCILED)") from exc
    emit_metric("HoldReconciled", len(reattached))
    return {"status": "RECONCILED", "event_id": record["event_id"], "roles_reattached": reattached,
            "attach_failures": attach_failures, "roles_confirmed_after": confirmed_after}
