"""
CDK for the drift metric publisher: PutMetricData on FSI/AgenticCompliance
only on the dedicated publisher role (plus fsi-console-operator with the
demo context), the KEYS_ONLY stream and its filtered event source, the new
action-less alarms, the alarm recheck schedule and the breaker's
DescribeAlarms grant. Synthesized locally (default and full context).
"""
import os
import sys

import pytest

from _cdk_synth import (
    DEFAULT_CONTEXT, FULL_CONTEXT, as_list, logical_id, render, resources, role_actions, role_props,
    role_statements, statements_with_action, synth, notifies_on_call_only,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
import circuit_breaker.handler as cb  # noqa: E402

PUBLISHER_ROLE = "fsi-drift-metric-publisher-role"
NEW_ACTION_LESS_ALARMS = (
    "fsi-uncorroborated-drift-alarm", "fsi-corroboration-unavailable", "fsi-drift-shaping-suspected",
    "fsi-drift-metric-publisher-dlq-not-empty", "fsi-drift-metric-publisher-iterator-age",
    "fsi-drift-metric-publisher-errors", "fsi-compliance-invocation-surge",
)
READ_ACTIONS = ("dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
                "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:PartiQLSelect")


@pytest.fixture(scope="module")
def default():
    return synth(DEFAULT_CONTEXT)


@pytest.fixture(scope="module")
def full():
    return synth(FULL_CONTEXT)


def _role_names(template):
    return {r["Properties"].get("RoleName") for r in resources(template, "AWS::IAM::Role").values()}


def _put_metric_holders(template):
    """Role names holding PutMetricData scoped to FSI/AgenticCompliance."""
    holders = set()
    for name in _role_names(template) - {None}:
        for s in statements_with_action(template, name, "cloudwatch:PutMetricData"):
            ns = s.get("Condition", {}).get("StringEquals", {}).get("cloudwatch:namespace")
            assert ns is not None, (name, s)  # never an unconditioned PutMetricData
            if ns == "FSI/AgenticCompliance":
                holders.add(name)
    return holders


def test_put_metric_data_only_on_publisher_by_default(default):
    assert _put_metric_holders(default["agents"]) == {PUBLISHER_ROLE}
    assert "cloudwatch:PutMetricData" not in role_actions(default["agents"], "compliance-agent-role")


def test_put_metric_data_with_demo_context_adds_only_the_direct_console_operator(full):
    assert _put_metric_holders(full["agents"]) == {PUBLISHER_ROLE, "fsi-console-operator"}


def test_publisher_role_reads_only_conditioned_drift_attributes(default):
    t = default["agents"]
    assert role_props(t, PUBLISHER_ROLE)["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
        "Service": "lambda.amazonaws.com"}
    gets = statements_with_action(t, PUBLISHER_ROLE, "dynamodb:GetItem")
    (get,) = gets
    assert get["Condition"] == {
        "ForAllValues:StringEquals": {"dynamodb:Attributes": [
            "compliance_id", "timestamp", "drift_counts", "provenance_status"]},
        "StringEqualsIfExists": {"dynamodb:Select": "SPECIFIC_ATTRIBUTES"}}
    (resource,) = as_list(get["Resource"])
    assert "ComplianceDecisions" in render(resource) and "/index" not in render(resource)
    for s in role_statements(t, PUBLISHER_ROLE):
        actions = set(as_list(s["Action"]))
        for action in actions & {"dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
                                 "dynamodb:PartiQLSelect"}:
            raise AssertionError(f"publisher holds {action}")
        if actions & {"dynamodb:GetRecords", "dynamodb:GetShardIterator"}:
            assert all("StreamArn" in render(r) for r in as_list(s["Resource"])), s


def test_stream_is_keys_only(default):
    (table,) = [r for r in resources(default["data"], "AWS::DynamoDB::Table").values()
                if r["Properties"]["TableName"] == "compliance-decisions"]
    assert table["Properties"]["StreamSpecification"] == {"StreamViewType": "KEYS_ONLY"}
    # The other four archived audit tables stream NEW_IMAGE to the immutable
    # audit archiver only (test_audit_archive_cdk.py); the drift ESM is
    # unchanged. governance-state is not archived and has no stream.
    archived = {"detection-results", "executor-audit", "governance-audit", "operator-audit"}
    tables = {r["Properties"]["TableName"]: r for r in resources(default["data"], "AWS::DynamoDB::Table").values()}
    assert archived <= set(tables)
    for name in archived:
        assert tables[name]["Properties"]["StreamSpecification"] == {"StreamViewType": "NEW_IMAGE"}


def test_event_source_mapping(default):
    t = default["agents"]
    (esm,) = resources(t, "AWS::Lambda::EventSourceMapping").values()
    p = esm["Properties"]
    fn_id = logical_id(t, "AWS::Lambda::Function", "FunctionName", "fsi-drift-metric-publisher")
    assert p["FunctionName"] == {"Ref": fn_id}
    assert "StreamArn" in render(p["EventSourceArn"])
    assert p["StartingPosition"] == "LATEST" and p["BatchSize"] == 100
    assert p["BisectBatchOnFunctionError"] is True and p["MaximumRetryAttempts"] == 3
    assert p["MaximumRecordAgeInSeconds"] == 3600
    assert p["FunctionResponseTypes"] == ["ReportBatchItemFailures"]
    assert p["FilterCriteria"] == {"Filters": [{"Pattern": '{"eventName":["INSERT"]}'}]}
    dlq_id = logical_id(t, "AWS::SQS::Queue", "QueueName", "fsi-drift-metric-publisher-dlq")
    assert p["DestinationConfig"]["OnFailure"]["Destination"] == {"Fn::GetAtt": [dlq_id, "Arn"]}


def test_publisher_function_props(default):
    t = default["agents"]
    fn = t["Resources"][logical_id(t, "AWS::Lambda::Function", "FunctionName", "fsi-drift-metric-publisher")]
    p = fn["Properties"]
    assert p["Runtime"] == "python3.13" and p["MemorySize"] == 128 and p["Timeout"] == 30
    assert p["Role"] == {"Fn::GetAtt": [logical_id(t, "AWS::IAM::Role", "RoleName", PUBLISHER_ROLE), "Arn"]}
    assert p["DeadLetterConfig"]["TargetArn"]
    queue = t["Resources"][logical_id(t, "AWS::SQS::Queue", "QueueName", "fsi-drift-metric-publisher-dlq")]
    assert queue["Properties"]["SqsManagedSseEnabled"] is True
    assert queue["Properties"]["MessageRetentionPeriod"] == 14 * 24 * 3600


def _alarms(template):
    return {r["Properties"]["AlarmName"]: r["Properties"]
            for r in resources(template, "AWS::CloudWatch::Alarm").values()}


def test_new_alarms_are_action_less_and_untrusted(default):
    t = default["agents"]
    alarms = _alarms(t)
    trusted = render(t["Resources"][logical_id(t, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")]
                     ["Properties"]["Environment"]["Variables"]["TRUSTED_ALARM_ARNS"])
    for name in NEW_ACTION_LESS_ALARMS:
        props = alarms[name]
        assert notifies_on_call_only(props), name
        assert f":alarm:{name}" not in trusted
    assert "fsi-uncorroborated-trip" not in alarms
    assert alarms["fsi-uncorroborated-drift-alarm"]["MetricName"] == "UncorroboratedAlarm"
    assert alarms["fsi-corroboration-unavailable"]["MetricName"] == "CorroborationUnavailable"
    assert alarms["fsi-drift-shaping-suspected"]["MetricName"] == "ShapingSuspected"
    age = alarms["fsi-drift-metric-publisher-iterator-age"]
    assert age["MetricName"] == "IteratorAge" and age["Statistic"] == "Maximum"
    assert age["Threshold"] == 900000 and age["Period"] == 300 and age["TreatMissingData"] == "notBreaching"
    errors = alarms["fsi-drift-metric-publisher-errors"]
    assert errors["MetricName"] == "Errors" and errors["Statistic"] == "Sum" and errors["Threshold"] == 0


def test_invocation_surge_anomaly_alarm(default):
    props = _alarms(default["agents"])["fsi-compliance-invocation-surge"]
    assert props["Metrics"] == [
        {"Id": "m1", "ReturnData": True,
         "MetricStat": {"Metric": {"Namespace": "FSI/AgenticCompliance", "MetricName": "ComplianceInvocations"},
                        "Period": 300, "Stat": "Sum"}},
        {"Id": "ad1", "ReturnData": True, "Expression": "ANOMALY_DETECTION_BAND(m1, 3)"},
    ]
    assert props["ThresholdMetricId"] == "ad1"
    assert props["ComparisonOperator"] == "GreaterThanUpperThreshold"
    assert props["EvaluationPeriods"] == 1 and props["DatapointsToAlarm"] == 1
    assert props["TreatMissingData"] == "notBreaching" and notifies_on_call_only(props)


def test_recheck_schedule(default):
    t = default["agents"]
    (rule,) = [r for r in resources(t, "AWS::Events::Rule").values()
               if r["Properties"].get("Name") == "fsi-breaker-alarm-recheck"]
    p = rule["Properties"]
    assert p["ScheduleExpression"] == "rate(2 minutes)" and "EventPattern" not in p
    (target,) = p["Targets"]
    breaker = logical_id(t, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    dlq = logical_id(t, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    assert target["Arn"] == {"Fn::GetAtt": [breaker, "Arn"]}
    assert target["Input"] == '{"action":"recheck_alarms"}'
    assert target["DeadLetterConfig"] == {"Arn": {"Fn::GetAtt": [dlq, "Arn"]}}
    assert target["RetryPolicy"] == {"MaximumRetryAttempts": 2}


def test_breaker_describe_alarms_exactly_the_trusted_alarms(default):
    t = default["agents"]
    (stmt,) = statements_with_action(t, "circuit-breaker-role", "cloudwatch:DescribeAlarms")
    assert sorted(render(r) for r in as_list(stmt["Resource"])) == sorted(
        f"arn:aws:cloudwatch:${{AWS::Region}}:${{AWS::AccountId}}:alarm:{name}" for name in cb.KNOWN_ALARM_REASONS)


@pytest.mark.parametrize("name", sorted(cb.PER_MINUTE_ALARMS))
def test_alarm_floor_constants_pinned_to_per_minute_alarms(default, name):
    props = _alarms(default["agents"])[name]
    assert props["EvaluationPeriods"] == cb.ALARM_EVALUATION_PERIODS
    assert props["DatapointsToAlarm"] == cb.ALARM_DATAPOINTS_TO_ALARM
    (expr,) = [m["Expression"] for m in props["Metrics"] if m.get("Expression")]
    assert expr.startswith(f"IF(clusters >= {cb.MIN_CLUSTERS_FOR_CORROBORATION}, ")
    assert str(props["Threshold"]) == str(float(cb.PER_MINUTE_ALARMS[name][1]))
