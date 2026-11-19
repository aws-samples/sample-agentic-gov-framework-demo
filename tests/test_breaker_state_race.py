"""
Trip and release serialized on the governance-state item. A trip that lands
while an approved release is detaching must leave the deny-all on every
agent role, and the sweep must keep it there. Live mode, mocked AWS
(tests/_breaker_fixtures.py), deterministic clock.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import ACCOUNT, Clock, FakeBreakerAws, cb, client_error, corroborating_decisions, \
    principal  # noqa: E402

OPERATOR = principal("fsi-breaker-operator", "alice")
APPROVER = principal("fsi-breaker-approver", "bob")
REASON = cb.KNOWN_MANUAL_TRIGGER_REASONS["OPERATOR_PRECAUTION"]
ROLES = set(cb.AGENT_ROLES)


def cb_error(code):
    return client_error(code, "UpdateItem")


def _times():
    # t1 is the release time; the sweep below runs on the real clock, so t1
    # is anchored 120 s in the past (the sweep runs at t1 + 120 s).
    t1 = datetime.now(timezone.utc) - timedelta(seconds=120)
    return t1 - timedelta(seconds=1), t1


@pytest.fixture
def race(monkeypatch):
    t0, t1 = _times()
    clock = Clock(t1).install(monkeypatch)
    aws = FakeBreakerAws().install(monkeypatch)
    aws.record_hold("hold-A", (t1 - timedelta(minutes=10)).isoformat())
    return aws, clock, t0, t1


def _request(aws):
    return cb.handler({"action": "request_release", **aws.proof(OPERATOR, "req")})


def _approve(aws, rid):
    return cb.handler({"action": "approve_release", "release_request_id": rid,
                       **aws.proof(APPROVER, "approve")})


def _trip_at(clock, when):
    """A trip that starts at ``when`` (earlier than the release's RELEASED
    record) and runs to completion inside the release."""
    resume = clock.t
    clock.set(when)
    try:
        return cb.invoke_circuit_breaker(REASON, "live")
    finally:
        clock.set(resume)


def _sweep(monkeypatch):
    monkeypatch.setenv("BREAKER_ENTRY", "sweep")
    return cb.handler({"action": "reconcile_hold"})


def _metric_names(aws):
    return [data[0]["MetricName"] for _, data in aws.cw.metrics]


def test_trip_during_release_detach_keeps_the_hold(race, monkeypatch):
    """The trip runs from a hook on the release's first
    detach_role_policy."""
    aws, clock, t0, _t1 = race
    rid = _request(aws)["release_request_id"]
    original = aws.iam.detach_role_policy
    trips = []

    def detach(RoleName, PolicyArn):
        if not trips:
            trips.append(_trip_at(clock, t0))
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    aws.iam.detach_role_policy = detach

    result = _approve(aws, rid)
    held_after_release = set(aws.iam.held)
    sweep = _sweep(monkeypatch)
    assert held_after_release == ROLES and aws.iam.held == ROLES, (result, sweep)

    new_hold = trips[0]["event_id"]
    assert result["code"] == "RELEASE_SUPERSEDED" and result["newer_hold_detected"] is True
    assert sorted(result["roles_reattached"]) == sorted(ROLES)
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert completed["final_status"] == "SUPERSEDED"
    assert sorted(completed["roles_reattached"]) == sorted(ROLES)
    assert completed["hold_generation_after"] == 2 and completed["hold_event_id_after"] == new_hold
    assert {"NewerHoldDetected", "ReleaseSuperseded"} <= set(_metric_names(aws))
    assert sweep["status"] == "HOLD_CONFIRMED"


def test_trip_during_release_pre_record_supersedes_without_detach(race, monkeypatch):
    """The trip runs from a hook on the release's
    GOVERNANCE_HOLD_RELEASED write, before the release claims the state."""
    aws, clock, t0, _t1 = race
    rid = _request(aws)["release_request_id"]
    trips = []
    aws.gov.on_put["GOVERNANCE_HOLD_RELEASED"] = lambda item: trips.append(_trip_at(clock, t0))
    result = _approve(aws, rid)
    assert result["code"] == "RELEASE_SUPERSEDED" and result["http_status"] == 409
    assert "newer_hold_detected" not in result
    assert not [e for e in aws.log if e[0] == "detach"] and aws.iam.held == ROLES
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    assert completed["final_status"] == "SUPERSEDED" and completed["roles_detached"] == []
    names = _metric_names(aws)
    assert "ReleaseSuperseded" in names and "NewerHoldDetected" not in names
    assert aws.state.item["hold_event_id"] == trips[0]["event_id"] and aws.state.item["generation"] == 2
    assert _sweep(monkeypatch)["status"] == "HOLD_CONFIRMED"


def _hide_trip_records(aws, written):
    """Index lag: hold/intent records written from now on stay out of the
    by_event_type index until unhidden."""
    original = aws.gov.put_item

    def put_item(Item, ConditionExpression=None):
        if Item["event_type"] in ("GOVERNANCE_HOLD", "GOVERNANCE_HOLD_INTENT"):
            aws.gov.index_hidden.add(Item["event_id"])
            written.append(Item["event_id"])
        return original(Item=Item, ConditionExpression=ConditionExpression)
    aws.gov.put_item = put_item


def test_trip_whose_claims_fail_is_restored_by_the_sweep(race, monkeypatch):
    """Both of the trip's claims fail and index lag hides it
    from the release's post-detach check."""
    aws, clock, t0, _t1 = race
    rid = _request(aws)["release_request_id"]
    written, errors = [], []
    original = aws.iam.detach_role_policy

    def detach(RoleName, PolicyArn):
        if not errors and not written:
            _hide_trip_records(aws, written)
            aws.state.update_errors = [cb_error("InternalServerError"), cb_error("InternalServerError")]
            try:
                _trip_at(clock, t0)
            except cb.GovernanceStateWriteError as e:
                errors.append(e)
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    aws.iam.detach_role_policy = detach

    result = _approve(aws, rid)
    assert errors and result["status"] == "ACTIVE" and aws.iam.held == set()
    (hold,) = [h for h in aws.gov.by_type("GOVERNANCE_HOLD") if h["event_id"] in written]
    assert hold["state_claimed"] is False and "hold_generation" not in hold
    assert ("metric", "FSI/GovernanceIntegrity", "HoldStateWriteFailed") in aws.log
    aws.gov.index_hidden.clear()

    sweep = _sweep(monkeypatch)
    assert sweep["status"] == "RECONCILED" and aws.iam.held == ROLES
    assert _metric_names(aws).count("HoldStateWriteFailed") == 2  # the trip's, then the sweep's
    monkeypatch.setenv("BREAKER_ENTRY", "human")
    assert _request(aws)["code"] == "TRIP_IN_PROGRESS"


def test_first_claim_fails_and_retry_lands_after_the_release(race, monkeypatch):
    """The trip's first claim fails, it
    attaches, the release claims and detaches and sees no newer hold (index
    lag), then the trip's retry claim lands. The sweep restores the hold."""
    import threading
    aws, clock, t0, t1 = race
    rid = _request(aws)["release_request_id"]
    reached, proceed, outcome, written = threading.Event(), threading.Event(), [], []

    def paused_sleep(seconds):
        if threading.current_thread() is trip_thread:
            reached.set()
            proceed.wait(5)
    monkeypatch.setattr(cb.time, "sleep", paused_sleep)

    def run_trip():
        try:
            outcome.append(cb.invoke_circuit_breaker(REASON, "live"))
        except Exception as e:  # noqa: BLE001 - surfaced by the assertions below
            outcome.append(e)

    trip_thread = threading.Thread(target=run_trip)
    original = aws.iam.detach_role_policy

    def detach(RoleName, PolicyArn):
        if not written:
            _hide_trip_records(aws, written)
            aws.state.update_errors = [cb_error("InternalServerError")]  # first claim only
            clock.set(t0)
            trip_thread.start()
            assert reached.wait(5), "trip did not reach its claim retry"
            clock.set(t1)
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    aws.iam.detach_role_policy = detach

    result = _approve(aws, rid)
    assert result["status"] == "ACTIVE" and "newer_hold_detected" not in result
    proceed.set()
    trip_thread.join(5)
    assert isinstance(outcome[0], dict) and outcome[0]["hold_generation"] == 2
    assert aws.state.item["status"] == "HELD" and aws.state.item["generation"] == 2
    assert [d[0]["Value"] for _, d in aws.cw.metrics if d[0]["MetricName"] == "HoldStateWriteFailed"] == [1]
    aws.gov.index_hidden.clear()
    assert aws.iam.held == set()

    sweep = _sweep(monkeypatch)
    assert sweep["status"] == "RECONCILED" and aws.iam.held == ROLES
    assert "HoldReconciled" in _metric_names(aws)


# ─── Request / approval refusals ─────────────────────────────────────────────

def _now():
    return datetime.now(timezone.utc)


@pytest.fixture
def held(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.record_hold("hold-A", (_now() - timedelta(minutes=10)).isoformat())
    return aws


def _release_record(aws, final_status=None, event_id="rel-1"):
    aws.gov.items[event_id] = {"event_id": event_id, "event_type": "GOVERNANCE_HOLD_RELEASED",
                               "timestamp": (_now() - timedelta(minutes=5)).isoformat(),
                               "prior_hold_event_id": "hold-A"}
    if final_status:
        aws.gov.items[f"completed-{event_id}"] = {
            "event_id": f"completed-{event_id}", "event_type": "GOVERNANCE_HOLD_RELEASE_COMPLETED",
            "timestamp": (_now() - timedelta(minutes=5)).isoformat(), "final_status": final_status}


@pytest.mark.parametrize("final_status, code", [("ACTIVE", "HOLD_ALREADY_RELEASED"), (None, "HOLD_ALREADY_RELEASED"),
                                                ("GOVERNANCE_HOLD", "HOLD_ALREADY_RELEASED"),
                                                ("ABORTED", None), ("SUPERSEDED", None)])
def test_request_for_an_already_released_hold(held, final_status, code):
    """A request bound to a hold whose release completed (or crashed) is
    refused; one whose release was aborted or superseded is allowed."""
    _release_record(held, final_status)
    result = _request(held)
    if code is None:
        assert result["http_status"] == 202
    else:
        assert result["http_status"] == 409 and result["code"] == code
    assert ("get_item", "completed-rel-1", True) in held.log


def test_approval_for_an_already_released_hold_is_refused(held):
    rid = _request(held)["release_request_id"]
    _release_record(held, "ACTIVE")
    result = _approve(held, rid)
    assert result["code"] == "HOLD_ALREADY_RELEASED"
    assert not held.gov.by_type("RELEASE_APPROVED") and "detach" not in held.kinds()


@pytest.mark.parametrize("timestamp", ["minutes", "garbage"])
def test_unclaimed_trip_blocks_request_and_approval(held, timestamp):
    """A trip that started after the claim and never claimed blocks release,
    and so does an unparseable start (fail closed)."""
    rid = _request(held)["release_request_id"]
    held.gov.items["intent-T"] = {
        "event_id": "intent-T", "event_type": "GOVERNANCE_HOLD_INTENT",
        "timestamp": (_now() - timedelta(minutes=5)).isoformat() if timestamp == "minutes" else "garbage"}
    result = _approve(held, rid)
    assert result["http_status"] == 409 and result["code"] == "TRIP_IN_PROGRESS"
    assert not held.gov.by_type("RELEASE_APPROVED") and "detach" not in held.kinds()
    assert _request(held)["code"] == "TRIP_IN_PROGRESS"


def test_state_read_failure_is_503(held):
    held.state.get_errors = [cb_error("InternalServerError")]
    result = _request(held)
    assert result["http_status"] == 503 and result["code"] == "HOLD_LOOKUP_UNAVAILABLE"


def test_released_state_is_hold_state_mismatch(held):
    held.state.item["status"] = "RELEASED"
    assert _request(held)["code"] == "HOLD_STATE_MISMATCH"


def test_request_binds_hold_and_generation_and_reads_consistently(held):
    rid = _request(held)["release_request_id"]
    request = held.gov.items[f"release-request#{rid}"]
    assert request["hold_event_id"] == "hold-A" and request["hold_generation"] == 1
    assert ("state_get", True) in held.log
    _approve(held, rid)
    (approved,) = held.gov.by_type("RELEASE_APPROVED")
    (released,) = held.gov.by_type("GOVERNANCE_HOLD_RELEASED")
    assert approved["hold_generation"] == 1 and released["hold_generation"] == 1
    assert held.state.item["status"] == "RELEASED" and held.state.item["release_request_id"] == rid


# ─── Concurrent trips ────────────────────────────────────────────────────────

DISPUTE = "fsi-challenger-dispute-rate-breach"


def _recheck_setup(monkeypatch, aws, transitioned=timedelta(minutes=5)):
    arn = f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:{DISPUTE}"
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [arn])
    aws.cw.alarm_pages = [[{"AlarmName": DISPUTE, "AlarmArn": arn, "StateValue": "ALARM",
                            "StateTransitionedTimestamp": _now() - transitioned}]]
    aws.compliance.items = corroborating_decisions()


def _hold_sweep(aws):
    metrics = []
    result = cb.hold_sweep.reconcile_hold(
        aws.iam, aws.gov, roles=list(cb.AGENT_ROLES), deny_policy_arn=cb.resolve_deny_policy_arn(),
        trigger="schedule", emit_metric=lambda name, value: metrics.append(name),
        read_state=lambda: cb.governance_state.read(aws.state))
    return result, metrics


def _intent(aws, event_id, start):
    aws.gov.items[f"intent-{event_id}"] = {"event_id": f"intent-{event_id}",
                                           "event_type": "GOVERNANCE_HOLD_INTENT",
                                           "timestamp": start.isoformat()}


def test_concurrent_trips_are_not_flagged(monkeypatch):
    """Trip 1 starts, trip 2 starts, trip 2 claims, trip 1 claims."""
    aws = FakeBreakerAws().install(monkeypatch)
    base = _now() - timedelta(minutes=10)
    s1, s2 = base, base + timedelta(seconds=1)
    _intent(aws, "trip-1", s1)
    _intent(aws, "trip-2", s2)
    aws.state.claim("trip-2", (base + timedelta(seconds=2)).isoformat())
    aws.state.claim("trip-1", (base + timedelta(seconds=3)).isoformat())
    for event_id, start, written in (("trip-2", s2, 4), ("trip-1", s1, 5)):
        aws.gov.items[event_id] = {"event_id": event_id, "event_type": "GOVERNANCE_HOLD",
                                   "timestamp": (base + timedelta(seconds=written)).isoformat(),
                                   "trip_started_at": start.isoformat()}
    aws.iam.held.update(ROLES)
    # Accepted edge: a trip that started before the current claim and whose
    # claims all failed is coalesced into it.
    _intent(aws, "trip-0", base + timedelta(seconds=2, milliseconds=500))
    assert _request(aws)["http_status"] == 202
    sweep, metrics = _hold_sweep(aws)
    assert sweep["status"] == "HOLD_CONFIRMED" and "HoldStateWriteFailed" not in metrics
    _recheck_setup(monkeypatch, aws)
    assert cb.recheck_alarms() == {"status": "HOLD_ACTIVE"}
    assert "HoldStateWriteFailed" not in _metric_names(aws)


def test_claim_in_flight_covers_a_trip_that_started_after_it(monkeypatch):
    """Trip 2 takes its claim time, trip 1 starts 1 s later, writes
    its intent and claims, then trip 2's claim lands last."""
    now0 = _now() - timedelta(minutes=10)
    clock = Clock(now0).install(monkeypatch)
    aws = FakeBreakerAws().install(monkeypatch)
    nested = []

    def t1_runs_inside_t2_claim(kind):
        clock.set(now0 + timedelta(seconds=1))
        nested.append(cb.invoke_circuit_breaker(REASON, "live"))
        clock.set(now0)
    aws.state.before_update = [t1_runs_inside_t2_claim]
    t2 = cb.invoke_circuit_breaker(REASON, "live")
    assert aws.state.item["hold_event_id"] == t2["event_id"] and aws.state.item["generation"] == 2
    assert aws.state.item["held_at"] == now0.isoformat()
    assert nested[0]["hold_generation"] == 1

    assert _request(aws)["http_status"] == 202
    sweep, metrics = _hold_sweep(aws)
    assert sweep["status"] == "HOLD_CONFIRMED" and "HoldStateWriteFailed" not in metrics
    _recheck_setup(monkeypatch, aws)
    assert cb.recheck_alarms() == {"status": "HOLD_ACTIVE"}
    assert "HoldStateWriteFailed" not in _metric_names(aws)

    # Counter-case: a trip starting 6 s after the claim that never claimed.
    _intent(aws, "X", now0 + timedelta(seconds=6))
    assert _request(aws)["code"] == "TRIP_IN_PROGRESS"


def test_recheck_after_break_glass_in_the_episode_does_not_trip(monkeypatch):
    """A break-glass inside the alarm episode suppresses the recheck, like a
    release."""
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.record_hold("hold-A", (_now() - timedelta(minutes=30)).isoformat())
    aws.state.item.update(status="RELEASED", break_glass_at=(_now() - timedelta(minutes=10)).isoformat())
    aws.iam.held.clear()
    _recheck_setup(monkeypatch, aws, transitioned=timedelta(minutes=20))
    result = cb.recheck_alarms()
    assert result["status"] == "RECHECKED" and result["tripped"] is None
    assert "attach" not in aws.kinds()


def test_recheck_treats_an_unclaimed_trip_as_the_active_hold(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.record_hold("hold-A", (_now() - timedelta(minutes=30)).isoformat())
    aws.state.item.update(status="RELEASED", released_at=(_now() - timedelta(minutes=25)).isoformat())
    _intent(aws, "T", _now() - timedelta(minutes=5))
    _recheck_setup(monkeypatch, aws)
    assert cb.recheck_alarms() == {"status": "HOLD_ACTIVE"}
    assert "HoldStateWriteFailed" in _metric_names(aws)


# ─── Trip records and budgets ────────────────────────────────────────────────

def test_hold_record_timestamp_is_the_write_time(monkeypatch):
    start = _now() - timedelta(minutes=1)
    Clock(start, step=timedelta(seconds=1)).install(monkeypatch)
    aws = FakeBreakerAws().install(monkeypatch)
    result = cb.invoke_circuit_breaker(REASON, "live")
    (intent,) = aws.gov.by_type("GOVERNANCE_HOLD_INTENT")
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert result["timestamp"] == intent["timestamp"] == hold["trip_started_at"] == start.isoformat()
    assert hold["timestamp"] > hold["trip_started_at"] and result["held_at"] == hold["timestamp"]
    assert hold["hold_generation"] == 1 and result["hold_generation"] == 1
    assert aws.state.item["held_at"] > start.isoformat()  # claim time, taken just before the claim
    assert aws.state.item["trip_started_at"] == start.isoformat()


def test_claims_use_a_single_attempt_client_and_fit_the_budget(monkeypatch):
    """Two timed-out claims stay inside the 6.2 s claim budget, and the
    breaker budgets fit the 45 s timeout."""
    start = _now()
    clock = Clock(start).install(monkeypatch)
    aws = FakeBreakerAws().install(monkeypatch)
    spent = []

    def timed_out(kind):
        clock.advance(3)  # connect 1 s + read 2 s, then a timeout
        spent.append(3)
    aws.state.before_update = [timed_out, timed_out]
    aws.state.update_errors = [cb_error("RequestTimeout"), cb_error("RequestTimeout")]
    monkeypatch.setattr(cb.time, "sleep", lambda seconds: spent.append(seconds))
    with pytest.raises(cb.GovernanceStateWriteError):
        cb.invoke_circuit_breaker(REASON, "live")
    assert sum(spent) <= 6.2
    configs = [cfg for name, cfg in aws.configs if name == "table:" + cb.STATE_TABLE]
    assert configs and all(cfg.retries == {"total_max_attempts": 1, "mode": "standard"}
                           and cfg.connect_timeout == 1 and cfg.read_timeout == 2 for cfg in configs)
    budget = cb.BREAKER_TIMEOUT_SECONDS * 1000 - cb.POST_TRIP_MARGIN_MS
    assert cb.CORROBORATION_DEADLINE_SECONDS * 1000 + cb.TRIP_PATH_BUDGET_MS <= budget
    assert cb.RECHECK_PRETRIP_BUDGET_SECONDS * 1000 + cb.RECHECK_MIN_TRIP_HEADROOM_MS <= budget
    assert cb.RECHECK_MIN_TRIP_HEADROOM_MS >= cb.TRIP_PATH_BUDGET_MS


@pytest.mark.parametrize("generation", [True, Decimal("1.5"), 0, "3", None, Decimal("NaN")])
def test_bad_request_generation_is_stale(held, generation):
    """hold_generation must be an integer >= 1."""
    rid = _request(held)["release_request_id"]
    request = held.gov.items[f"release-request#{rid}"]
    if generation is None:
        del request["hold_generation"]
    else:
        request["hold_generation"] = generation
    result = _approve(held, rid)
    assert result["code"] == "STALE_REQUEST" and "detach" not in held.kinds()


def test_decimal_request_generation_is_accepted(held):
    """DynamoDB returns numbers as Decimal."""
    held.state.item["generation"] = Decimal("3")
    rid = _request(held)["release_request_id"]
    held.gov.items[f"release-request#{rid}"]["hold_generation"] = Decimal("3")
    assert _approve(held, rid)["status"] == "ACTIVE"


def test_failed_claims_record_state_claimed_false(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.state.update_errors = [cb_error("InternalServerError"), cb_error("InternalServerError")]
    with pytest.raises(cb.GovernanceStateWriteError):
        cb.invoke_circuit_breaker(REASON, "live")
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert hold["state_claimed"] is False and "hold_generation" not in hold
    assert aws.iam.held == ROLES  # containment first
    assert [e for e in aws.log if e[0] == "state_update"] == [("state_update", "trip")] * 2
    assert aws.sleeps == [cb.CLAIM_RETRY_SLEEP_SECONDS]


def test_retry_claim_after_the_attach_loop(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.state.update_errors = [cb_error("InternalServerError")]
    result = cb.invoke_circuit_breaker(REASON, "live")
    assert result["hold_generation"] == 1
    claims = [i for i, e in enumerate(aws.log) if e == ("state_update", "trip")]
    attaches = [i for i, e in enumerate(aws.log) if e[0] == "attach"]
    hold_put = next(i for i, e in enumerate(aws.log) if e[:2] == ("put", "GOVERNANCE_HOLD"))
    assert claims[0] < attaches[0] and attaches[-1] < claims[1] < hold_put
    assert [d[0]["Value"] for _, d in aws.cw.metrics if d[0]["MetricName"] == "HoldStateWriteFailed"] == [1]


def test_intent_and_state_failures_raise_the_audit_error_from_the_state_error(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch)
    aws.gov.put_error["GOVERNANCE_HOLD_INTENT"] = RuntimeError("ddb down")
    state_error = cb_error("InternalServerError")
    aws.state.update_errors = [cb_error("InternalServerError"), state_error]
    with pytest.raises(cb.GovernanceAuditWriteError) as info:
        cb.invoke_circuit_breaker(REASON, "live")
    assert type(info.value) is cb.GovernanceAuditWriteError and info.value.__cause__ is state_error
