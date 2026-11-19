"""
Drift signal integrity. The
compliance agent stores drift counts and publishes nothing (the drift metric
publisher derives datapoints from stored VERIFIED records); the breaker
corroborates every drift alarm against those records before any deny-all,
and an uncorroborated alarm is recorded and alerts instead of attaching.
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import (  # noqa: E402
    DISPUTE_HIGH, FakeAws, FakeBedrock, cluster, detection_output,
)
from _cdk_synth import DEFAULT_CONTEXT, logical_id, notifies_on_call_only, render, synth  # noqa: E402


def _run(det):
    return ch.handler({"mode": "live", "detection_output": det})


def test_unverified_run_publishes_no_metrics(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    aws = FakeAws().install(monkeypatch, ch)
    _run(detection_output())
    assert "put_metric_data" not in aws.kinds() and "cloudwatch" not in aws.clients_built


def test_not_checked_run_publishes_no_metrics(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch, durable=False)
    _run(detection_output())
    assert "put_metric_data" not in aws.kinds() and "cloudwatch" not in aws.clients_built


def test_verified_run_publishes_no_metrics_from_the_agent(monkeypatch):
    """Drift metrics come only from fsi-drift-metric-publisher,
    never from compliance-agent-role. The stored item carries started_at
    (run start) and timestamp (decision time)."""
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output()
    aws.store_detection(det)
    out = _run(det)
    assert "put_metric_data" not in aws.kinds() and "cloudwatch" not in aws.clients_built
    item = aws.decision_item()
    assert item["drift_counts"]["clusters"] == 1
    assert item["started_at"] <= item["timestamp"] == out["timestamp"]
    assert item["record_day"] == item["timestamp"][:10]


def test_write_failure_publishes_no_metrics(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output()
    aws.store_detection(det)
    aws.write_error = RuntimeError("ddb down")
    with pytest.raises(ch.ComplianceAuditWriteError):
        _run(det)
    assert aws.metrics == []


def test_drift_counts_on_record_exclude_output_rejections(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output([cluster("c1"), cluster("c2"), cluster("c3")])
    aws.store_detection(det)
    replies = iter(['Sure: {"verdict":"AGREE"}', DISPUTE_HIGH, "not json"])

    class Bedrock(FakeBedrock):
        def converse(self, **kwargs):
            if kwargs["modelId"] != ch.MODEL_ID:
                self.challenger_text = next(replies)
            return super().converse(**kwargs)

    aws.bedrock = Bedrock(aws)
    _run(det)
    counts = aws.decision_item()["drift_counts"]
    assert counts == {"clusters": 3, "disputes": 1, "guardrail_hits": 0,
                      "challenger_failures": 0, "output_rejections": 2}
    assert aws.metrics == []


def test_unverified_record_still_carries_drift_counts(monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    aws = FakeAws().install(monkeypatch, ch)
    _run(detection_output())
    assert aws.puts[0]["drift_counts"]["clusters"] == 1


def test_compliance_agent_no_longer_publishes():
    assert not hasattr(ch, "publish_drift_metrics")
    assert not hasattr(ch, "MIN_CLUSTERS_FOR_RATE")
    with open(os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"), encoding="utf-8") as f:
        assert "put_metric_data" not in f.read()


# ─── CDK: fsi-challenger-output-rejected ─────────────────────────────────────

@pytest.fixture(scope="module")
def agents():
    return synth(DEFAULT_CONTEXT)["agents"]


def test_output_rejected_alarm_is_hourly_actionless_and_untrusted(agents):
    alarm_id = logical_id(agents, "AWS::CloudWatch::Alarm", "AlarmName", "fsi-challenger-output-rejected")
    props = agents["Resources"][alarm_id]["Properties"]
    assert props["Threshold"] == 0.2
    assert props["EvaluationPeriods"] == 1
    assert props["ComparisonOperator"] == "GreaterThanThreshold"
    assert props["TreatMissingData"] == "notBreaching"
    assert notifies_on_call_only(props)
    metrics = props["Metrics"]
    expression = next(m for m in metrics if "Expression" in m)
    assert expression["Expression"] == "IF(clusters >= 20, rejected / clusters, 0)"
    stats = {m["Id"]: m["MetricStat"] for m in metrics if "MetricStat" in m}
    assert stats["rejected"]["Metric"]["MetricName"] == "ChallengerOutputRejectedCount"
    assert stats["clusters"]["Metric"]["MetricName"] == "ClustersAssessed"
    assert {s["Period"] for s in stats.values()} == {3600}
    assert {s["Stat"] for s in stats.values()} == {"Sum"}
    fn_id = logical_id(agents, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    trusted = render(agents["Resources"][fn_id]["Properties"]["Environment"]["Variables"]["TRUSTED_ALARM_ARNS"])
    assert "fsi-challenger-output-rejected" not in trusted


# ─── Breaker corroboration of alarm trips ─

import circuit_breaker.handler as cb  # noqa: E402
from datetime import datetime, timezone  # noqa: E402
from decimal import Decimal  # noqa: E402

from boto3.dynamodb.types import TypeSerializer  # noqa: E402
from _breaker_fixtures import FakeBreakerAws, client_error, decision  # noqa: E402

_DISPUTE_ALARM = "arn:aws:cloudwatch:us-east-1:123456789012:alarm:fsi-challenger-dispute-rate-breach"
_DISPUTE = "fsi-challenger-dispute-rate-breach"
NOW = datetime(2026, 3, 10, 12, 30, 0, tzinfo=timezone.utc)


def _arn(name):
    return _DISPUTE_ALARM.replace(_DISPUTE, name)


def _alarm_trip(monkeypatch, items=(), error=None, alarm_arn=_DISPUTE_ALARM):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [alarm_arn])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = [dict(i) for i in items]
    aws.compliance.error = error
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": alarm_arn,
                         "alarmData": {"state": {"value": "ALARM"}}})
    holds = aws.gov.by_type("GOVERNANCE_HOLD")
    return aws, result, (holds[0] if holds else None)


def _corroborate(monkeypatch, name, items, **kwargs):
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = [dict(i) for i in items]
    return aws, cb.corroborate(name, now=NOW, **kwargs)


def _metric_names(aws):
    return [data[0]["MetricName"] for _, data in aws.cw.metrics]


# ─── Alarm path: corroborate before deny-all ────────────────────

def test_uncorroborated_alarm_does_not_attach_deny_all(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, [])
    assert result == {"status": "UNCORROBORATED", "http_status": 409, "alarm_name": _DISPUTE,
                      "corroborated": False}
    assert "attach" not in aws.kinds() and hold is None
    assert aws.gov.by_type("GOVERNANCE_HOLD_INTENT") == []
    (event,) = aws.gov.by_type("ALARM_UNCORROBORATED")
    assert event["event_id"].startswith("alarm-uncorroborated#")
    assert event["trigger_source"] == f"ALARM:{_DISPUTE}" and event["alarm_name"] == _DISPUTE
    assert event["corroboration"]["corroborated"] is False
    assert _metric_names(aws) == ["UncorroboratedAlarm"]
    assert aws.sleeps == [3]  # retried once for GSI propagation


def test_corroborated_alarm_still_trips(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, [decision(25, 15, minutes_ago=4)])
    assert result["status"] == "GOVERNANCE_HOLD" and result["corroborated"] is True
    assert sorted(e[1] for e in aws.log if e[0] == "attach") == sorted(cb.AGENT_ROLES)
    assert hold["corroboration"]["corroborated"] is True and hold["corroboration"]["window_minutes"] == 5
    assert hold["trigger_source"] == "ALARM:fsi-challenger-dispute-rate-breach"
    assert not aws.cw.metrics and aws.sleeps == []
    # corroboration runs before the intent and the attach
    kinds = aws.kinds()
    assert kinds.index("query_compliance") < kinds.index("put") < kinds.index("attach")


def test_eight_minute_old_record_is_recent_nine_is_baseline(monkeypatch):
    _, c = _corroborate(monkeypatch, _DISPUTE, [decision(25, 15, minutes_ago=8, now=NOW)])
    assert c["records"] == 1 and c["corroborated"] is True
    _, c = _corroborate(monkeypatch, _DISPUTE, [decision(25, 15, minutes_ago=9, now=NOW)])
    assert c["records"] == 0 and c["baseline_records"] == 1 and c["corroborated"] is False


def test_unverified_records_do_not_corroborate(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, [decision(40, 30, status="UNVERIFIED"),
                                                  decision(40, 30, minutes_ago=2, status="NOT_CHECKED")])
    assert result["status"] == "UNCORROBORATED" and hold is None
    (event,) = aws.gov.by_type("ALARM_UNCORROBORATED")
    assert event["corroboration"]["clusters"] == 0


def test_corroboration_read_error_trips_and_emits_unavailable(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, error=client_error("ProvisionedThroughputExceededException"))
    assert result["status"] == "GOVERNANCE_HOLD" and "attach" in aws.kinds()
    assert hold["corroboration"] == {"window_minutes": 5, "slack_minutes": 3,
                                     "error_class": "ClientError", "corroborated": None}
    assert _metric_names(aws) == ["CorroborationUnavailable"]


def test_non_botocore_error_propagates(monkeypatch):
    with pytest.raises(RuntimeError):
        _alarm_trip(monkeypatch, error=RuntimeError("code bug"))


def _clock(monkeypatch, values):
    seq = list(values)
    monkeypatch.setattr(cb.time, "monotonic", lambda: seq.pop(0) if len(seq) > 1 else seq[0])


def test_deadline_exceeded_trips(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    _clock(monkeypatch, [0, 100])
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                         "alarmData": {"state": {"value": "ALARM"}}})
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert result["status"] == "GOVERNANCE_HOLD"
    assert hold["corroboration"]["error_class"] == "DeadlineExceeded"
    assert hold["corroboration"]["corroborated"] is None
    assert "query_compliance" not in aws.kinds() and aws.sleeps == []


def test_no_retry_when_budget_below_four_seconds(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = []
    _clock(monkeypatch, [0, 7])
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                         "alarmData": {"state": {"value": "ALARM"}}})
    assert result["status"] == "UNCORROBORATED" and aws.sleeps == []


def test_retry_once_on_false(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = []

    def sleep(seconds):
        aws.sleeps.append(seconds)
        aws.compliance.items = [decision(25, 15)]  # the GSI caught up
    monkeypatch.setattr(cb.time, "sleep", sleep)
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                         "alarmData": {"state": {"value": "ALARM"}}})
    assert result["status"] == "GOVERNANCE_HOLD" and aws.sleeps == [3]
    queries = aws.kinds().count("query_compliance")  # one or two day partitions, twice
    assert queries in (2, 4)


def test_malformed_verified_item_alone_is_uncorroborated(monkeypatch):
    bad = decision(25, 15, counts={"clusters": "25", "disputes": 15, "guardrail_hits": 0,
                                   "challenger_failures": 0, "output_rejections": 0})
    aws, result, hold = _alarm_trip(monkeypatch, [bad])
    assert result["status"] == "UNCORROBORATED" and hold is None and "attach" not in aws.kinds()
    (event,) = aws.gov.by_type("ALARM_UNCORROBORATED")
    assert event["corroboration"]["invalid_records"] == 1


@pytest.mark.parametrize("counts", [
    {"clusters": 25, "disputes": 15, "guardrail_hits": 0, "challenger_failures": 0},           # missing key
    {"clusters": 25, "disputes": 15, "guardrail_hits": 0, "challenger_failures": 0,
     "output_rejections": 0, "extra": 1},                                                    # extra key
    {"clusters": True, "disputes": 0, "guardrail_hits": 0, "challenger_failures": 0, "output_rejections": 0},
    {"clusters": 25, "disputes": -1, "guardrail_hits": 0, "challenger_failures": 0, "output_rejections": 0},
    {"clusters": 25, "disputes": 26, "guardrail_hits": 0, "challenger_failures": 0, "output_rejections": 0},
    {"clusters": Decimal("2.5"), "disputes": 0, "guardrail_hits": 0, "challenger_failures": 0,
     "output_rejections": 0},
    "not a dict",
])
def test_malformed_counts_are_skipped_never_raised(monkeypatch, counts):
    _, c = _corroborate(monkeypatch, _DISPUTE, [decision(25, 15, counts=counts, now=NOW)])
    assert c["invalid_records"] == 1 and c["corroborated"] is False


def test_volume_corroboration(monkeypatch):
    name = "fsi-detection-volume-anomaly"
    _, c = _corroborate(monkeypatch, name, [decision(30, now=NOW), decision(10, minutes_ago=30, now=NOW)])
    assert c["corroborated"] is True
    _, c = _corroborate(monkeypatch, name, [decision(30, now=NOW), decision(600, minutes_ago=30, now=NOW)])
    assert c["corroborated"] is False


def test_volume_alarm_trip_is_corroborated_from_records(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, [decision(30)],
                                    alarm_arn=_arn("fsi-detection-volume-anomaly"))
    assert result["status"] == "GOVERNANCE_HOLD" and hold["corroboration"]["corroborated"] is True


def test_injected_volume_datapoint_without_records_is_uncorroborated(monkeypatch):
    aws, result, hold = _alarm_trip(monkeypatch, [], alarm_arn=_arn("fsi-detection-volume-anomaly"))
    assert result["status"] == "UNCORROBORATED" and hold is None and "attach" not in aws.kinds()


def test_newest_first_truncation_keeps_recent_items(monkeypatch):
    monkeypatch.setattr(cb, "CORROBORATION_MAX_ITEMS", 3)
    items = [decision(25, 15, minutes_ago=1, now=NOW), decision(25, 15, minutes_ago=2, now=NOW)]
    items += [decision(5, minutes_ago=20 + i, now=NOW) for i in range(5)]
    aws, c = _corroborate(monkeypatch, _DISPUTE, items)
    assert c["truncated"] is True and c["records"] == 2 and c["corroborated"] is True
    assert all(call["ScanIndexForward"] is False for call in aws.compliance.calls)
    aws.compliance.page_size = 2
    c = cb.corroborate(_DISPUTE, now=NOW)
    assert c["truncated"] is True and c["records"] == 2 and c["corroborated"] is True


def test_shaping_suspected_is_computed_and_never_decides(monkeypatch):
    items = [decision(2, minutes_ago=0.5 * i, now=NOW) for i in range(1, 13)]
    _, c = _corroborate(monkeypatch, _DISPUTE, items)
    assert c["records"] == 12 and c["shaping_suspected"] is True and c["invocation_ratio"] > 3
    assert c["corroborated"] is False  # shaping never trips
    _, c = _corroborate(monkeypatch, _DISPUTE, items[:5])
    assert c["shaping_suspected"] is False


def test_shaping_metric_emitted_on_uncorroborated_alarm(monkeypatch):
    items = [decision(2, minutes_ago=0.5 * i) for i in range(1, 13)]
    aws, result, _ = _alarm_trip(monkeypatch, items)
    assert result["status"] == "UNCORROBORATED"
    assert _metric_names(aws) == ["UncorroboratedAlarm", "ShapingSuspected"]
    (event,) = aws.gov.by_type("ALARM_UNCORROBORATED")
    assert event["corroboration"]["shaping_suspected"] is True


def test_uncorroborated_audit_write_failure_raises(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = []
    aws.gov.put_error["ALARM_UNCORROBORATED"] = client_error("InternalServerError", "PutItem")
    with pytest.raises(cb.GovernanceAuditWriteError):
        cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                    "alarmData": {"state": {"value": "ALARM"}}})
    assert "attach" not in aws.kinds()


def _dilution(breaching):
    padding = [decision(100, minutes_ago=m, now=NOW) for m in (8, 7, 6, 5, 4, 3)]
    return padding + breaching


def test_dilution_two_breaching_minutes_corroborate(monkeypatch):
    items = _dilution([decision(25, 15, minutes_ago=2, now=NOW), decision(25, 15, minutes_ago=1, now=NOW)])
    _, c = _corroborate(monkeypatch, _DISPUTE, items)
    assert c["corroborated"] is True and c["breaching_minutes"] == 2
    assert c["recomputed_rate"] < Decimal("0.51")  # the aggregate alone would miss it


def test_dilution_trip_attaches_all_three(monkeypatch):
    items = [decision(100, minutes_ago=m) for m in (8, 7, 6, 5, 4, 3)]
    items += [decision(25, 15, minutes_ago=2), decision(25, 15, minutes_ago=1)]
    aws, result, hold = _alarm_trip(monkeypatch, items)
    assert result["status"] == "GOVERNANCE_HOLD" and hold["corroboration"]["breaching_minutes"] == 2
    assert sorted(e[1] for e in aws.log if e[0] == "attach") == sorted(cb.AGENT_ROLES)


def test_dilution_sub_floor_minutes_do_not_corroborate(monkeypatch):
    items = _dilution([decision(19, 15, minutes_ago=2, now=NOW), decision(19, 15, minutes_ago=1, now=NOW)])
    _, c = _corroborate(monkeypatch, _DISPUTE, items)
    assert c["corroborated"] is False and c["breaching_minutes"] == 0


def test_dilution_single_breaching_minute_does_not_corroborate(monkeypatch):
    items = _dilution([decision(25, 15, minutes_ago=1, now=NOW)])
    _, c = _corroborate(monkeypatch, _DISPUTE, items)
    assert c["corroborated"] is False and c["breaching_minutes"] == 1


def test_guardrail_alarm_uses_guardrail_hits(monkeypatch):
    name = "fsi-guardrail-intervention-rate-breach"
    _, c = _corroborate(monkeypatch, name, [decision(25, 0, 5, minutes_ago=m, now=NOW) for m in (1, 2)])
    assert c["corroborated"] is True and c["breaching_minutes"] == 2
    _, c = _corroborate(monkeypatch, name, [decision(25, 25, 0, minutes_ago=m, now=NOW) for m in (1, 2)])
    assert c["corroborated"] is False


def test_sustained_alarm_uses_one_hour_window(monkeypatch):
    arn = _arn("fsi-challenger-dispute-rate-sustained")
    _, result, hold = _alarm_trip(monkeypatch, [decision(25, 15, minutes_ago=50)], alarm_arn=arn)
    assert hold["corroboration"]["window_minutes"] == 60 and hold["corroboration"]["corroborated"] is True
    assert hold["trigger_reason"] == cb.KNOWN_ALARM_REASONS["fsi-challenger-dispute-rate-sustained"]
    assert hold["trigger_source"] == "ALARM:fsi-challenger-dispute-rate-sustained"


def test_corroboration_query_projects_counters_only(monkeypatch):
    aws, _, _ = _alarm_trip(monkeypatch, [decision(25, 15)])
    call = aws.compliance.calls[0]
    assert call["IndexName"] == "by_day_ts" and call["Select"] == "SPECIFIC_ATTRIBUTES"
    assert call["ScanIndexForward"] is False
    assert "sar_narrative" not in call["ProjectionExpression"]
    assert set(x.strip() for x in call["ProjectionExpression"].split(",")) == {
        "compliance_id", "record_day", "#ts", "drift_counts", "provenance_status"}


def test_corroboration_client_is_single_attempt(monkeypatch):
    """total_max_attempts=1 (max_attempts=1 would be
    two attempts in the pinned botocore)."""
    import botocore.session
    aws, _ = _corroborate(monkeypatch, _DISPUTE, [])
    (config,) = [cfg for name, cfg in aws.configs if name == "table:" + cb.COMPLIANCE_TABLE]
    client = botocore.session.get_session().create_client(
        "dynamodb", region_name="us-east-1", config=config,
        aws_access_key_id="testing", aws_secret_access_key="testing")
    assert client.meta.config.retries["total_max_attempts"] == 1
    assert client.meta.config.connect_timeout == 1 and client.meta.config.read_timeout == 2


def test_rule_tables_agree():
    assert set(cb.CORROBORATION_RULES) == set(cb.KNOWN_ALARM_REASONS)
    for name, (_numerator, threshold) in cb.PER_MINUTE_ALARMS.items():
        assert cb.CORROBORATION_RULES[name].threshold == threshold
        assert cb.CORROBORATION_RULES[name].numerator == _numerator
        assert cb.CORROBORATION_RULES[name].window_minutes == 5


def test_auto_trip_has_trigger_source_and_no_corroboration(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS",
                        ["arn:aws:iam::123456789012:role/executor-agent-role"])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    cb.handler({"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"})
    (hold,) = aws.gov.by_type("GOVERNANCE_HOLD")
    assert hold["trigger_source"] == "AUTO_TRIP:EXECUTOR_CONTAINMENT" and "corroboration" not in hold
    assert "query_compliance" not in aws.kinds()


# ─── DynamoDB-safe results ───────────────────────────────────────────────────

def _result_shapes(monkeypatch):
    shapes = []
    for items in ([decision(25, 15, now=NOW)], [], [decision(2, minutes_ago=0.5 * i, now=NOW) for i in range(1, 13)]):
        shapes.append(_corroborate(monkeypatch, _DISPUTE, items)[1])
    for items in ([decision(30, now=NOW)], [decision(30, now=NOW), decision(600, minutes_ago=30, now=NOW)]):
        shapes.append(_corroborate(monkeypatch, "fsi-detection-volume-anomaly", items)[1])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.error = client_error("ThrottlingException")
    shapes.append(cb.corroborate(_DISPUTE, now=NOW))
    shapes.append(cb.corroborate(_DISPUTE, now=NOW, deadline=-1))
    return shapes


def test_every_corroboration_shape_serializes(monkeypatch):
    shapes = _result_shapes(monkeypatch)
    assert {s["corroborated"] for s in shapes} == {True, False, None}
    assert any(s.get("shaping_suspected") for s in shapes)
    assert any(s.get("error_class") == "DeadlineExceeded" for s in shapes)
    for shape in shapes:
        TypeSerializer().serialize(shape)


def test_ddb_safe_conversions():
    assert cb._ddb_safe({"a": 0.123456, "b": [float("nan"), float("inf")], "c": True, "d": 3}) == {
        "a": Decimal("0.1235"), "b": [None, None], "c": True, "d": 3}
    with pytest.raises(TypeError):
        cb._ddb_safe({"x": object()})


def _stubbed_governance_table(monkeypatch, responses):
    import boto3 as real_boto3
    from botocore.stub import Stubber
    table = real_boto3.resource("dynamodb", region_name="us-east-1", aws_access_key_id="testing",
                                aws_secret_access_key="testing").Table(cb.AUDIT_TABLE)
    stubber = Stubber(table.meta.client)
    for _ in range(responses):
        stubber.add_response("put_item", {})
    stubber.activate()
    monkeypatch.setattr(cb, "_governance_table", lambda: table)
    return stubber


def test_uncorroborated_record_through_a_real_table(monkeypatch):
    stubber = _stubbed_governance_table(monkeypatch, 1)
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    aws = FakeBreakerAws().install(monkeypatch, entry="automated")
    aws.compliance.items = [decision(2, minutes_ago=0.5 * i) for i in range(1, 13)]
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                         "alarmData": {"state": {"value": "ALARM"}}})
    assert result["status"] == "UNCORROBORATED"
    stubber.assert_no_pending_responses()


def test_corroborated_hold_through_a_real_table(monkeypatch):
    stubber = _stubbed_governance_table(monkeypatch, 2)  # INTENT + GOVERNANCE_HOLD
    monkeypatch.setattr(cb, "TRUSTED_ALARM_ARNS", [_DISPUTE_ALARM])
    FakeBreakerAws().install(monkeypatch, entry="automated")
    result = cb.handler({"source": "aws.cloudwatch", "alarmArn": _DISPUTE_ALARM,
                         "alarmData": {"state": {"value": "ALARM"}}})
    assert result["status"] == "GOVERNANCE_HOLD"
    stubber.assert_no_pending_responses()


# ─── Console drift injection ─────────────────────

import boto3  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

import app.cloudwatch_metrics as cwm  # noqa: E402
import app.invoke_live as invoke_live  # noqa: E402
from app import operator_audit  # noqa: E402
from app.console_identity import Principal  # noqa: E402


def _console_principal(roles=("operator",)):
    return Principal(principal_id="local:alice", display_name="Alice", auth_mode="local",
                     roles=frozenset(roles), authenticated_at="2026-01-01T00:00:00+00:00")


@pytest.fixture
def console_publish(monkeypatch, tmp_path):
    """Operator session whose CloudWatch client records put_metric_data;
    ambient boto3 forbidden; MODE=local so REQUESTED goes to a temp JSONL."""
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("CONSOLE_ALLOW_DRIFT_INJECTION", "true")

    def _no_ambient(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, _no_ambient)
    cw = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda service, **k: {"cloudwatch": cw}[service]
    return session, cw, tmp_path


def _authorize_and_publish(session):
    grant = invoke_live.authorize_drift_injection(_console_principal(), "challenger", audit_session=None)
    return grant, invoke_live.publish_breach_metric_live("challenger", session=session, grant=grant)


def test_console_publish_with_flag_role_and_requested_record(console_publish):
    session, cw, out = console_publish
    grant, ok = _authorize_and_publish(session)
    assert ok is True and cw.put_metric_data.call_count == 1
    assert cw.put_metric_data.call_args.kwargs["Namespace"] == "FSI/AgenticCompliance"
    (line,) = [json.loads(l) for l in (out / operator_audit.JSONL_NAME).read_text().splitlines()]
    assert line["action"] == "DRIFT_INJECTION" and line["phase"] == "REQUESTED"
    assert line["event_id"] == grant.event_id and line["actor_id"] == "local:alice"


def test_console_publish_refused_without_env_flag(console_publish, monkeypatch):
    session, cw, out = console_publish
    monkeypatch.delenv("CONSOLE_ALLOW_DRIFT_INJECTION")
    with pytest.raises(invoke_live.DriftInjectionRefused):
        _authorize_and_publish(session)
    grant = invoke_live.DriftInjectionGrant(event_id="e", principal_id="local:alice", metric_key="challenger")
    with pytest.raises(invoke_live.DriftInjectionRefused):
        invoke_live.publish_breach_metric_live("challenger", session=session, grant=grant)
    cw.put_metric_data.assert_not_called()
    assert not (out / operator_audit.JSONL_NAME).exists()


def test_console_publish_refused_without_operator_role(console_publish):
    session, cw, out = console_publish
    with pytest.raises(invoke_live.DriftInjectionRefused):
        invoke_live.authorize_drift_injection(_console_principal(("auditor",)), "challenger",
                                              audit_session=None)
    with pytest.raises(invoke_live.DriftInjectionRefused):
        invoke_live.publish_breach_metric_live("challenger", session=session, grant=None)
    cw.put_metric_data.assert_not_called()
    assert not (out / operator_audit.JSONL_NAME).exists()


def test_console_publish_refused_when_requested_write_fails(console_publish, monkeypatch):
    session, cw, _ = console_publish

    def failing_write(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(operator_audit, "record_console_action", failing_write)
    with pytest.raises(OSError):
        _authorize_and_publish(session)
    cw.put_metric_data.assert_not_called()


def test_grant_is_bound_to_its_metric(console_publish):
    session, cw, _ = console_publish
    grant = invoke_live.authorize_drift_injection(_console_principal(), "volume", audit_session=None)
    with pytest.raises(invoke_live.DriftInjectionRefused):
        invoke_live.publish_breach_metric_live("challenger", session=session, grant=grant)
    cw.put_metric_data.assert_not_called()


def test_console_alarm_state_helpers_are_gone():
    assert not hasattr(invoke_live, "reset_cloudwatch_alarms_live")
    assert not hasattr(cwm, "set_alarm_state")
    assert not hasattr(cwm, "reset_all_alarms")
    app_dir = os.path.join(PROJECT_ROOT, "app")
    for name in os.listdir(app_dir):
        if name.endswith(".py"):
            with open(os.path.join(app_dir, name), encoding="utf-8") as f:
                assert "set_alarm_state" not in f.read(), name


def test_makefile_ui_live_does_not_enable_drift_injection():
    with open(os.path.join(PROJECT_ROOT, "Makefile"), encoding="utf-8") as f:
        assert "CONSOLE_ALLOW_DRIFT_INJECTION" not in f.read()
