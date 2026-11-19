"""
recheck_alarms: while a trusted drift alarm stays
in ALARM after an uncorroborated verdict, the scheduled recheck re-runs
corroboration and trips only when the stored records now corroborate.
Attach-only, alarm identity from DescribeAlarms, bounded pre-trip budget.
Live mode, mocked AWS (tests/_breaker_fixtures.py).
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import botocore.session
import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import ACCOUNT, FakeBreakerAws, cb, client_error, corroborating_decisions  # noqa: E402

DISPUTE = "fsi-challenger-dispute-rate-breach"
TRUSTED = [f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:{name}" for name in cb.KNOWN_ALARM_REASONS]


def _now():
    return datetime.now(timezone.utc)


def alarm(name=DISPUTE, transitioned=timedelta(minutes=5), updated=None, arn=None):
    entry = {"AlarmName": name, "AlarmArn": arn or f"arn:aws:cloudwatch:us-east-1:{ACCOUNT}:alarm:{name}",
             "StateValue": "ALARM"}
    if transitioned is not None:
        entry["StateTransitionedTimestamp"] = _now() - transitioned
    entry["StateUpdatedTimestamp"] = _now() - (updated if updated is not None else (transitioned or timedelta()))
    return entry


class Context:
    def __init__(self, remaining_ms):
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self):
        return self.remaining_ms


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", list(TRUSTED))
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = []
    return aws


def _gov_event(aws, event_type, ago, event_id=None):
    event_id = event_id or f"{event_type.lower()}-{ago.total_seconds()}"
    aws.gov.items[event_id] = {"event_id": event_id, "event_type": event_type,
                               "timestamp": (_now() - ago).isoformat()}


def _state(aws, status, held_ago, released_ago=None, break_glass_ago=None):
    """The governance-state item: claimed ``held_ago``, optionally released."""
    aws.state.claim("hold-S", (_now() - held_ago).isoformat())
    aws.state.item["status"] = status
    if released_ago is not None:
        aws.state.item["released_at"] = (_now() - released_ago).isoformat()
    if break_glass_ago is not None:
        aws.state.item["break_glass_at"] = (_now() - break_glass_ago).isoformat()


def _recheck(context=None, **event):
    return cb.handler({"action": "recheck_alarms", **event}, context)


def _metric_names(aws):
    return [data[0]["MetricName"] for _, data in aws.cw.metrics]


def test_recheck_trips_when_records_now_corroborate(aws):
    aws.cw.alarm_pages = [[alarm()]]
    _gov_event(aws, "ALARM_UNCORROBORATED", timedelta(minutes=4))
    aws.compliance.items = corroborating_decisions()
    result = _recheck()
    assert result["status"] == "RECHECKED" and result["tripped"] == DISPUTE
    assert sorted(e[1] for e in aws.log if e[0] == "attach") == sorted(cb.AGENT_ROLES)
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert hold["corroboration"]["trigger"] == "recheck" and hold["corroboration"]["corroborated"] is True
    assert hold["trigger_source"] == f"ALARM:{DISPUTE}"


def test_recheck_without_corroboration_writes_nothing(aws):
    aws.cw.alarm_pages = [[alarm()]]
    _gov_event(aws, "ALARM_UNCORROBORATED", timedelta(minutes=4))
    result = _recheck()
    assert result == {"status": "RECHECKED", "alarms": [{"alarm_name": DISPUTE, "corroborated": False}],
                      "tripped": None}
    assert not [e for e in aws.log if e[0] in ("attach", "detach", "put")]


def test_release_in_the_episode_skips(aws):
    aws.cw.alarm_pages = [[alarm(transitioned=timedelta(minutes=20))]]
    _gov_event(aws, "GOVERNANCE_HOLD", timedelta(minutes=15), event_id="hold-S")
    _state(aws, "RELEASED", timedelta(minutes=15), released_ago=timedelta(minutes=10))
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] is None
    assert "query_compliance" not in aws.kinds() and "attach" not in aws.kinds()


def test_evaluation_state_update_does_not_start_a_new_episode(aws):
    """StateTransitionedTimestamp 20 min ago, release 10 min ago,
    StateUpdatedTimestamp 1 min ago (EvaluationState change) -> no trip."""
    aws.cw.alarm_pages = [[alarm(transitioned=timedelta(minutes=20), updated=timedelta(minutes=1))]]
    _gov_event(aws, "GOVERNANCE_HOLD", timedelta(minutes=15))
    _gov_event(aws, "GOVERNANCE_HOLD_RELEASED", timedelta(minutes=10))
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] is None
    assert "query_compliance" not in aws.kinds() and "attach" not in aws.kinds()


def test_no_hold_history_still_corroborates(aws):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] == DISPUTE
    assert "query_compliance" in aws.kinds()


def test_alarm_without_transition_timestamp_is_skipped(aws, caplog):
    aws.cw.alarm_pages = [[alarm(transitioned=None)]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] is None
    assert "query_compliance" not in aws.kinds()
    assert "no StateTransitionedTimestamp" in caplog.text


def test_active_hold_returns_hold_active(aws):
    aws.cw.alarm_pages = [[alarm()]]
    _gov_event(aws, "GOVERNANCE_HOLD", timedelta(minutes=1), event_id="hold-S")
    _state(aws, "HELD", timedelta(minutes=1))
    aws.compliance.items = corroborating_decisions()
    assert _recheck() == {"status": "HOLD_ACTIVE"}
    assert ("state_get", True) in aws.log
    assert "attach" not in aws.kinds() and "query_compliance" not in aws.kinds()


def test_transition_in_flight_is_skipped(aws):
    aws.cw.alarm_pages = [[alarm(transitioned=timedelta(seconds=30))]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] is None and "attach" not in aws.kinds()


def test_insufficient_lambda_time_defers_without_intent(aws):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck(Context(10000)) == {"status": "DEFERRED"}
    assert "CorroborationUnavailable" in _metric_names(aws)
    assert not [e for e in aws.log if e[0] in ("attach", "put")]


def test_enough_lambda_time_trips(aws):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck(Context(22000))["tripped"] == DISPUTE


def _clock(monkeypatch, values):
    seq = list(values)
    monkeypatch.setattr(cb.time, "monotonic", lambda: seq.pop(0) if len(seq) > 1 else seq[0])


def test_deadline_before_hold_query_defers(aws, monkeypatch):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.items = corroborating_decisions()
    _clock(monkeypatch, [0, 1, 50])  # deadline, describe page, before hold_active
    assert _recheck() == {"status": "DEFERRED"}
    assert "query_events" not in aws.kinds() and "query_holds" not in aws.kinds()
    assert not [e for e in aws.log if e[0] in ("attach", "put")]


def test_deadline_before_corroborate_defers(aws, monkeypatch):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.items = corroborating_decisions()
    _clock(monkeypatch, [0, 1, 2, 50])  # deadline, describe page, hold_active, corroborate
    assert _recheck() == {"status": "DEFERRED"}
    assert "query_compliance" not in aws.kinds()
    assert not [e for e in aws.log if e[0] in ("attach", "put")]


def _effective_attempts(config):
    client = botocore.session.get_session().create_client(
        "dynamodb", region_name="us-east-1", config=config,
        aws_access_key_id="testing", aws_secret_access_key="testing")
    return client.meta.config


def test_pretrip_clients_are_single_attempt(aws):
    """Every pre-trip client is one attempt
    (total_max_attempts=1), connect 1 s, read 2 s."""
    aws.cw.alarm_pages = [[alarm()]]
    _recheck()
    configs = dict((name, cfg) for name, cfg in aws.configs
                   if name in ("cloudwatch", "table:" + cb.AUDIT_TABLE, "table:" + cb.COMPLIANCE_TABLE))
    assert set(configs) == {"cloudwatch", "table:" + cb.AUDIT_TABLE, "table:" + cb.COMPLIANCE_TABLE}
    for name, cfg in configs.items():
        effective = _effective_attempts(cfg)
        assert effective.retries["total_max_attempts"] == 1, name
        assert effective.connect_timeout == 1 and effective.read_timeout == 2, name


@pytest.mark.parametrize("setup", ["describe_error", "hold_error", "corroboration_none", "deferred"])
def test_recheck_metric_clients_are_single_attempt(aws, setup):
    """The PutMetricData client on the recheck path is one
    attempt (total_max_attempts=1), so a DEFERRED / no-trip run stays inside
    the Lambda timeout."""
    if setup == "describe_error":
        aws.cw.describe_error = client_error("AccessDenied", "DescribeAlarms")
    else:
        aws.cw.alarm_pages = [[alarm()]]
    if setup == "hold_error":
        aws.gov.query_error = client_error("ThrottlingException", "Query")
    if setup == "corroboration_none":
        aws.compliance.error = client_error("ThrottlingException", "Query")
    context = Context(10000) if setup == "deferred" else None
    if setup == "deferred":
        aws.compliance.items = corroborating_decisions()
    _recheck(context)
    assert _metric_names(aws) == ["CorroborationUnavailable"]
    cw_configs = [cfg for name, cfg in aws.configs if name == "cloudwatch"]
    assert len(cw_configs) == 2  # DescribeAlarms client + one metric client
    for cfg in cw_configs:
        effective = _effective_attempts(cfg)
        assert effective.retries["total_max_attempts"] == 1
        assert effective.connect_timeout == 1 and effective.read_timeout == 2


def test_unavailable_then_deferred_emits_one_metric(aws, monkeypatch):
    """Corroboration None at the deadline, then DEFERRED for
    the next alarm, makes a single CorroborationUnavailable call."""
    first, second = list(cb.KNOWN_ALARM_REASONS)[:2]
    aws.cw.alarm_pages = [[alarm(first), alarm(second)]]
    clock = [0.0]
    monkeypatch.setattr(cb.time, "monotonic", lambda: clock[0])

    def unavailable_at_deadline(name, now=None, deadline=None):
        clock[0] = deadline + 1
        return {"corroborated": None}

    monkeypatch.setattr(cb, "corroborate", unavailable_at_deadline)
    assert _recheck() == {"status": "DEFERRED"}
    assert _metric_names(aws) == ["CorroborationUnavailable"]
    assert not [e for e in aws.log if e[0] in ("attach", "put")]


def test_describe_alarms_pages_are_followed(aws):
    aws.cw.alarm_pages = [[], [alarm()]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck()["tripped"] == DISPUTE
    assert len(aws.cw.describe_calls) == 2 and aws.cw.describe_calls[1]["NextToken"] == "1"
    first = aws.cw.describe_calls[0]
    assert first["AlarmNames"] == list(cb.KNOWN_ALARM_REASONS) and first["StateValue"] == "ALARM"
    assert first["AlarmTypes"] == ["MetricAlarm"]


def test_untrusted_alarm_arn_is_ignored(aws):
    aws.cw.alarm_pages = [[alarm(arn="arn:aws:cloudwatch:us-east-1:999999999999:alarm:" + DISPUTE)]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck() == {"status": "NO_ALARMS"}
    assert "attach" not in aws.kinds()


def test_describe_alarms_error_no_trip(aws):
    aws.cw.describe_error = client_error("AccessDenied", "DescribeAlarms")
    assert _recheck() == {"status": "ERROR"}
    assert _metric_names(aws) == ["CorroborationUnavailable"]
    assert "attach" not in aws.kinds()


def test_hold_query_error_no_trip(aws):
    aws.cw.alarm_pages = [[alarm()]]
    aws.state.get_errors = [client_error("ThrottlingException", "GetItem")]
    assert _recheck() == {"status": "ERROR"}
    assert _metric_names(aws) == ["CorroborationUnavailable"] and "attach" not in aws.kinds()


def test_corroboration_unavailable_on_recheck_never_trips(aws):
    aws.cw.alarm_pages = [[alarm()]]
    aws.compliance.error = client_error("ThrottlingException", "Query")
    result = _recheck()
    assert result["tripped"] is None and result["alarms"] == [{"alarm_name": DISPUTE, "corroborated": None}]
    assert _metric_names(aws) == ["CorroborationUnavailable"] and "attach" not in aws.kinds()


def test_recheck_on_human_entry_is_refused(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="human")
    result = _recheck()
    assert result["http_status"] == 403 and aws.log == []


def test_event_payload_fields_are_ignored(aws):
    aws.cw.alarm_pages = [[]]
    aws.compliance.items = corroborating_decisions()
    assert _recheck(alarm_name=DISPUTE, alarmArn=TRUSTED[0]) == {"status": "NO_ALARMS"}
    assert "attach" not in aws.kinds()


def test_local_mode_makes_no_aws_calls(monkeypatch):
    monkeypatch.setenv("BREAKER_ENTRY", "automated")
    monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("aws")))
    assert cb.handler({"action": "recheck_alarms", "mode": "local"}) == {"status": "NO_ALARMS"}
