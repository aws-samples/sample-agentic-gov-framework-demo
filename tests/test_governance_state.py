"""
The governance-state item (circuit_breaker/governance_state.py) and the
hold rule built on it (circuit_breaker/hold_sweep.py): the claim return
codes, release claims through _perform_release, and the sweep reading the
item. Mocked AWS only (tests/_breaker_fixtures.py).
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import DENY_ARN, FakeBreakerAws, FakeStateTable, cb, client_error  # noqa: E402

gs = cb.governance_state
hold_sweep = cb.hold_sweep
ROLES = list(cb.AGENT_ROLES)
NOW = "2026-01-01T00:00:00+00:00"


def _now():
    return datetime.now(timezone.utc)


def _ago(**kwargs):
    return (_now() - timedelta(**kwargs)).isoformat()


# ─── governance_state ────────────────────────────────────────────────────────

@pytest.fixture
def table():
    return FakeStateTable([])


def test_read_is_consistent_and_absent_is_none(table):
    assert gs.read(table) is None
    assert table.log == [("state_get", True)]


def test_claim_trip_bumps_the_generation_unconditionally(table):
    assert gs.claim_trip(table, "hold-A", NOW, NOW) == 1
    assert gs.claim_trip(table, "hold-B", NOW, NOW) == 2
    assert table.item["status"] == "HELD" and table.item["hold_event_id"] == "hold-B"
    assert table.item["held_at"] == NOW and table.item["trip_started_at"] == NOW


def test_claim_release_codes(table):
    assert gs.claim_release(table, 1, "hold-A", "r-1", "bob", NOW) == gs.ABSENT
    gs.claim_trip(table, "hold-A", NOW, NOW)
    assert gs.claim_release(table, 2, "hold-A", "r-1", "bob", NOW) == gs.SUPERSEDED
    assert gs.claim_release(table, 1, "hold-B", "r-1", "bob", NOW) == gs.SUPERSEDED
    assert gs.claim_release(table, 1, "hold-A", "r-1", "bob", NOW) == gs.CLAIMED
    assert table.item["status"] == "RELEASED" and table.item["released_generation"] == 1
    assert table.item["release_request_id"] == "r-1" and table.item["released_by"] == "bob"
    assert gs.claim_release(table, 1, "hold-A", "r-2", "carol", NOW) == gs.ALREADY_RELEASED
    assert table.item["release_request_id"] == "r-1"


def test_claim_break_glass_ignores_status_and_keeps_in_band_fields(table):
    gs.claim_trip(table, "hold-A", NOW, NOW)
    assert gs.claim_release(table, 1, "hold-A", "r-1", "bob", NOW) == gs.CLAIMED
    assert gs.claim_break_glass(table, 1, "hold-A", "INC-1", "glass", "2026-01-01T01:00:00+00:00") == gs.CLAIMED
    item = table.item
    assert item["status"] == "RELEASED" and item["break_glass_id"] == "INC-1"
    assert item["break_glass_by"] == "glass" and item["break_glass_at"] == "2026-01-01T01:00:00+00:00"
    assert item["release_request_id"] == "r-1" and item["released_by"] == "bob" and item["released_at"] == NOW
    assert gs.claim_break_glass(table, 2, "hold-A", "INC-1", "glass", NOW) == gs.SUPERSEDED


def test_other_errors_raise(table):
    gs.claim_trip(table, "hold-A", NOW, NOW)
    table.update_errors = [client_error("ProvisionedThroughputExceededException", "UpdateItem")]
    with pytest.raises(Exception, match="ProvisionedThroughputExceeded"):
        gs.claim_release(table, 1, "hold-A", "r-1", "bob", NOW)


def test_module_imports_no_sibling():
    with open(gs.__file__, encoding="utf-8") as f:
        source = f.read()
    imports = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert imports == ["from botocore.exceptions import ClientError"]


# ─── hold rule ───────────────────────────────────────────────────────────────

def test_state_from_item_includes_break_glass_time():
    state = hold_sweep.state_from_item({"status": "RELEASED", "hold_event_id": "h",
                                        "held_at": "2026-01-01T00:00:00+00:00",
                                        "released_at": "2026-01-01T00:10:00+00:00",
                                        "break_glass_at": "2026-01-01T00:20:00+00:00"})
    assert state.active is False and state.hold_event_id == "h"
    assert state.newest_hold_at.isoformat() == "2026-01-01T00:00:00+00:00"
    assert state.newest_event_at.isoformat() == "2026-01-01T00:20:00+00:00"


def test_claim_baseline():
    held = "2026-01-01T00:00:00+00:00"
    assert hold_sweep.claim_baseline({"held_at": held}).isoformat() == "2026-01-01T00:00:05+00:00"
    assert hold_sweep.claim_baseline({"held_at": held, "break_glass_at": "2026-01-01T01:00:00+00:00",
                                      "released_at": "2026-01-01T02:00:00+00:00"}
                                     ).isoformat() == "2026-01-01T01:00:00+00:00"
    assert hold_sweep.claim_baseline({"held_at": "garbage"}) is None


def test_claim_slack_covers_one_single_attempt_call():
    """The slack exceeds one state call's connect + read
    timeouts."""
    config = cb._corroboration_client_config()
    assert hold_sweep.CLAIM_SLACK_SECONDS * 1000 > (config.connect_timeout + config.read_timeout) * 1000


# ─── Release claim through _perform_release ──────────────────────────────────

APPROVAL = {"release_request_id": "r-1", "hold_event_id": "hold-A", "hold_generation": 1,
            "requested_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-operator/alice",
            "approved_by": "arn:aws:sts::123456789012:assumed-role/fsi-breaker-approver/bob"}


@pytest.fixture
def aws(monkeypatch):
    a = FakeBreakerAws().install(monkeypatch)
    a.record_hold("hold-A", _ago(minutes=10))
    return a


def _detaches(aws):
    return [e for e in aws.log if e[0] == "detach"]


def _metric_names(aws):
    return [data[0]["MetricName"] for _, data in aws.cw.metrics]


def _completed(aws):
    (completed,) = aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED")
    return completed


def test_second_release_of_the_same_generation_is_already_released(aws):
    assert cb._perform_release(dict(APPROVAL))["status"] == "ACTIVE"
    aws.iam.held.update(ROLES)  # re-attached out of band; the item stays RELEASED at generation 1
    before = len(_detaches(aws))
    result = cb._perform_release(dict(APPROVAL))
    assert result["http_status"] == 409 and result["code"] == "ALREADY_RELEASED"
    assert len(_detaches(aws)) == before and _metric_names(aws) == []
    finals = sorted(i["final_status"] for i in aws.gov.by_type("GOVERNANCE_HOLD_RELEASE_COMPLETED"))
    assert finals == ["ABORTED", "ACTIVE"]


def test_ambiguous_claim_error_that_landed_proceeds_to_detach(aws):
    def land(kind):
        aws.state.item.update(status="RELEASED", release_request_id="r-1")
    aws.state.before_update = [land]
    aws.state.update_errors = [client_error("InternalServerError", "UpdateItem")]
    result = cb._perform_release(dict(APPROVAL))
    assert result["status"] == "ACTIVE" and sorted(e[1] for e in _detaches(aws)) == sorted(ROLES)
    assert _completed(aws)["final_status"] == "ACTIVE"


def test_ambiguous_claim_error_that_did_not_land_is_503_without_detach(aws):
    aws.state.update_errors = [client_error("InternalServerError", "UpdateItem")]
    result = cb._perform_release(dict(APPROVAL))
    assert result["http_status"] == 503 and result["code"] == "STATE_UNAVAILABLE"
    assert _detaches(aws) == [] and aws.iam.held == set(ROLES)
    completed = _completed(aws)
    assert completed["final_status"] == "ABORTED" and completed["state_unverified"] is False


def test_ambiguous_claim_error_with_failed_reread_is_unverified(aws):
    aws.state.update_errors = [client_error("InternalServerError", "UpdateItem")]
    aws.state.get_errors = [client_error("InternalServerError", "GetItem")]
    result = cb._perform_release(dict(APPROVAL))
    assert result["http_status"] == 503 and _detaches(aws) == []
    completed = _completed(aws)
    assert completed["final_status"] == "ABORTED" and completed["state_unverified"] is True


def test_missing_state_item_refuses_without_detach(aws):
    aws.state.item = None
    result = cb._perform_release(dict(APPROVAL))
    assert result["http_status"] == 409 and result["code"] == "HOLD_EVENT_UNKNOWN"
    assert _detaches(aws) == [] and _metric_names(aws) == []


def test_post_detach_read_failure_reports_unverified_and_alerts(aws):
    aws.state.get_errors = [client_error("InternalServerError", "GetItem")]
    result = cb._perform_release(dict(APPROVAL))
    assert result["status"] == "ACTIVE" and result["state_unverified"] is True
    assert _metric_names(aws) == ["HoldStateReadFailed"]
    assert _completed(aws)["state_unverified"] is True


def test_release_uses_the_single_attempt_state_table(aws):
    cb._perform_release(dict(APPROVAL))
    configs = [cfg for name, cfg in aws.configs if name == "table:" + cb.STATE_TABLE]
    assert configs and all(cfg.retries == {"total_max_attempts": 1, "mode": "standard"} for cfg in configs)


# ─── Sweep on the state item ─────────────────────────────────────────────────

class _NoDetachIam:
    def __init__(self, iam):
        self._iam = iam

    def __getattr__(self, name):
        if name == "detach_role_policy":
            raise AssertionError("the sweep must never detach")
        return getattr(self._iam, name)


@pytest.fixture
def sweep_aws(monkeypatch):
    return FakeBreakerAws().install(monkeypatch, entry="sweep")


def _sweep(aws, read_state=None, now=None):
    metrics = []
    result = hold_sweep.reconcile_hold(
        _NoDetachIam(aws.iam), aws.gov, roles=ROLES, deny_policy_arn=DENY_ARN, trigger="schedule",
        emit_metric=lambda name, value: metrics.append((name, value)), now=now,
        read_state=read_state or (lambda: gs.read(aws.state)))
    return result, metrics


def _attaches(aws):
    return [e[1] for e in aws.log if e[0] == "attach"]


def _held_state(aws, held_ago=timedelta(minutes=10), event_id="hold-A"):
    aws.gov.items[event_id] = {"event_id": event_id, "event_type": "GOVERNANCE_HOLD",
                               "timestamp": (_now() - held_ago).isoformat()}
    aws.state.claim(event_id, (_now() - held_ago).isoformat())


def test_sweep_reattaches_when_held_and_detached(sweep_aws):
    _held_state(sweep_aws)
    result, metrics = _sweep(sweep_aws)
    assert result["status"] == "RECONCILED" and sorted(_attaches(sweep_aws)) == sorted(ROLES)
    (record,) = sweep_aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["hold_event_id"] == "hold-A"
    assert metrics == [("HoldReconciled", 3)]
    assert ("state_get", True) in sweep_aws.log


def test_sweep_no_attach_when_released_and_nothing_unclaimed(sweep_aws):
    _held_state(sweep_aws)
    sweep_aws.state.item.update(status="RELEASED", released_at=_ago(minutes=5))
    result, metrics = _sweep(sweep_aws)
    assert result == {"status": "NO_HOLD"} and _attaches(sweep_aws) == [] and metrics == []


def test_sweep_falls_back_to_the_index_when_the_item_is_absent(sweep_aws):
    sweep_aws.gov.items["hold-X"] = {"event_id": "hold-X", "event_type": "GOVERNANCE_HOLD",
                                     "timestamp": _ago(minutes=10)}
    result, _ = _sweep(sweep_aws)
    assert result["status"] == "RECONCILED" and sorted(_attaches(sweep_aws)) == sorted(ROLES)


def test_sweep_state_read_error_no_attach_and_alerts(sweep_aws):
    _held_state(sweep_aws)
    sweep_aws.state.get_errors = [client_error("ThrottlingException", "GetItem")]
    result, metrics = _sweep(sweep_aws)
    assert result == {"status": "ERROR"} and metrics == [("HoldSweepFailed", 1)] and _attaches(sweep_aws) == []


def test_sweep_release_racing_prevents_the_attach(sweep_aws):
    _held_state(sweep_aws)
    reads = []

    def read_state():
        item = gs.read(sweep_aws.state)
        reads.append(1)
        if len(reads) == 2:
            item["status"] = "RELEASED"
        return item
    result, _ = _sweep(sweep_aws, read_state=read_state)
    assert result == {"status": "NO_HOLD", "raced_release": True} and _attaches(sweep_aws) == []


def test_sweep_fresh_claim_is_left_to_the_trip(sweep_aws):
    _held_state(sweep_aws, held_ago=timedelta(seconds=30))
    assert _sweep(sweep_aws)[0] == {"status": "HOLD_TOO_RECENT"} and _attaches(sweep_aws) == []


def test_sweep_enforces_an_unclaimed_trip(sweep_aws):
    _held_state(sweep_aws, held_ago=timedelta(minutes=20))
    sweep_aws.state.item.update(status="RELEASED", released_at=_ago(minutes=15))
    sweep_aws.gov.items["intent-T"] = {"event_id": "intent-T", "event_type": "GOVERNANCE_HOLD_INTENT",
                                       "timestamp": _ago(minutes=10)}
    result, metrics = _sweep(sweep_aws)
    assert result["status"] == "RECONCILED" and sorted(_attaches(sweep_aws)) == sorted(ROLES)
    (record,) = sweep_aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["hold_event_id"] == "T"
    assert ("HoldStateWriteFailed", 1) in metrics


def test_sweep_entry_reads_the_state_item(sweep_aws):
    _held_state(sweep_aws)
    sweep_aws.state.item.update(status="RELEASED", released_at=_ago(minutes=5))
    sweep_aws.gov.items["hold-A"]["timestamp"] = _ago(minutes=1)  # the index alone would say active
    assert cb.handler({"action": "reconcile_hold"}) == {"status": "NO_HOLD"}
    assert ("state_get", True) in sweep_aws.log


def test_sweep_entry_state_table_is_single_attempt(sweep_aws):
    _held_state(sweep_aws)
    cb.handler({"action": "reconcile_hold"})
    configs = [cfg for name, cfg in sweep_aws.configs if name == "table:" + cb.STATE_TABLE]
    assert configs and all(cfg.retries["total_max_attempts"] == 1 for cfg in configs)


def test_reconcile_never_writes_state():
    with open(hold_sweep.__file__, encoding="utf-8") as f:
        source = f.read()
    for call in ("update_item", "claim_trip", "claim_release", "claim_break_glass", "delete_item"):
        assert call not in source, call
