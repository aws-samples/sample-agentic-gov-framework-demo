"""
The breaker's governance-state item (table governance-state, key
state_id = "breaker").

Trip and release both claim this one strongly consistent item with
conditional writes on a monotonically increasing ``generation``, so a
release can only detach the hold generation it was approved for:

- claim_trip always wins and always bumps the generation (status HELD).
- claim_release succeeds only while the item still holds the approved
  generation and hold, with status HELD (status RELEASED).
- claim_break_glass succeeds while the item still holds the generation and
  hold the script read; it does not check status and never touches the
  in-band release fields.

Imports only the stdlib, boto3 and botocore and never a sibling module, so it
loads as top-level ``governance_state`` in the Lambda asset and as
``circuit_breaker.governance_state`` from scripts/break_glass_release.py.
Every function returns plain values; errors other than a failed condition
are raised to the caller.
"""
from botocore.exceptions import ClientError

STATE_KEY = {"state_id": "breaker"}
HELD = "HELD"
RELEASED = "RELEASED"

CLAIMED = "CLAIMED"
ALREADY_RELEASED = "ALREADY_RELEASED"
ABSENT = "ABSENT"
SUPERSEDED = "SUPERSEDED"

CLAIM_TRIP_UPDATE = (
    "SET generation = if_not_exists(generation, :zero) + :one, #s = :held, "
    "hold_event_id = :eid, trip_started_at = :start, held_at = :now, updated_at = :now")
CLAIM_RELEASE_UPDATE = (
    "SET #s = :released, released_generation = :g, release_request_id = :rid, "
    "released_by = :by, released_at = :now, updated_at = :now")
CLAIM_RELEASE_CONDITION = "generation = :g AND hold_event_id = :eid AND #s = :held"
CLAIM_BREAK_GLASS_UPDATE = (
    "SET #s = :released, break_glass_id = :bgid, break_glass_by = :by, "
    "break_glass_at = :now, updated_at = :now")
CLAIM_BREAK_GLASS_CONDITION = "generation = :g AND hold_event_id = :eid"
STATUS_NAME = {"#s": "status"}


def read(table):
    """The state item (ConsistentRead), or None when it does not exist."""
    return table.get_item(Key=dict(STATE_KEY), ConsistentRead=True).get("Item")


def claim_trip(table, hold_event_id, started_at, now) -> int:
    """Claim the item for a new hold. Unconditional; returns the new
    generation. ``now`` is taken by the caller immediately before this call
    (held_at is the claim write time)."""
    response = table.update_item(
        Key=dict(STATE_KEY),
        UpdateExpression=CLAIM_TRIP_UPDATE,
        ExpressionAttributeNames=dict(STATUS_NAME),
        ExpressionAttributeValues={":zero": 0, ":one": 1, ":held": HELD, ":eid": hold_event_id,
                                   ":start": started_at, ":now": now},
        ReturnValues="UPDATED_NEW",
    )
    return int(response["Attributes"]["generation"])


def _is_conditional_failure(e) -> bool:
    return isinstance(e, ClientError) and \
        e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"


def _classify_lost_claim(e, generation) -> str:
    old = e.response.get("Item")
    if not old:
        return ABSENT
    if old.get("generation") == generation and old.get("status") == RELEASED:
        return ALREADY_RELEASED
    return SUPERSEDED


def _conditional_update(table, update, condition, values, generation, hold_event_id):
    try:
        table.update_item(
            Key=dict(STATE_KEY),
            UpdateExpression=update,
            ConditionExpression=condition,
            ExpressionAttributeNames=dict(STATUS_NAME),
            ExpressionAttributeValues={":g": generation, ":eid": hold_event_id, **values},
            ReturnValuesOnConditionCheckFailure="ALL_OLD",
        )
    except ClientError as e:
        if _is_conditional_failure(e):
            return _classify_lost_claim(e, generation)
        raise
    return CLAIMED


def claim_release(table, generation, hold_event_id, request_id, released_by, now) -> str:
    """In-band release of exactly ``generation``/``hold_event_id``.
    CLAIMED, ALREADY_RELEASED (same generation already released), ABSENT
    (no item) or SUPERSEDED (a newer generation or hold)."""
    return _conditional_update(
        table, CLAIM_RELEASE_UPDATE, CLAIM_RELEASE_CONDITION,
        {":held": HELD, ":released": RELEASED, ":rid": request_id, ":by": released_by, ":now": now},
        generation, hold_event_id)


def claim_break_glass(table, generation, hold_event_id, incident_id, by, now) -> str:
    """Out-of-band release of ``generation``/``hold_event_id`` (any status).
    Same return codes as claim_release."""
    return _conditional_update(
        table, CLAIM_BREAK_GLASS_UPDATE, CLAIM_BREAK_GLASS_CONDITION,
        {":released": RELEASED, ":bgid": incident_id, ":by": by, ":now": now},
        generation, hold_event_id)
