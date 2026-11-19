"""
Test: cdk_nag findings #3, #4, #5, #7.

Synthesizes the real AgentsStack (same subprocess approach as
tests/test_txn_ref_secret_cdk.py, since Lambda assets resolve relative to
cwd=cdk/) and asserts:
  #3 (AwsSolutions-IAM5 / CKV_AWS_111) the three AgentCore agent roles have
     no logs:* action on Resource "*"; their log actions are scoped to the
     AgentCore runtime log groups exactly as the AWS AgentCore Runtime
     execution-role documentation shows.
  #4 (AwsSolutions-IAM4) the three agent roles have no
     AWSLambdaBasicExecutionRole (no managed policies at all); neither do
     PanFilterRole and CircuitBreakerRole (scoped log-group statements
     instead). Governance-hold detection still works for a role with zero
     managed policies.
  #5 (AwsSolutions-L1) fsi-circuit-breaker runs python3.13.
  #7 (LambdaDLQ / CKV_AWS_116) fsi-circuit-breaker has a DeadLetterConfig
     on an SSE + TLS-only SQS queue, CircuitBreakerRole may only
     sqs:SendMessage on it, and fsi-circuit-breaker-dlq-not-empty alarms on
     it without invoking any Lambda (its only action notifies on-call).
  The three drift alarms, their Lambda permissions and TRUSTED_ALARM_ARNS
  are unchanged.
"""
import json
import os
import subprocess
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cdk_synth import notifies_on_call_only  # noqa: E402

AGENT_ROLES = ("detection-agent-role", "compliance-agent-role", "executor-agent-role")
LAMBDA_ROLES = ("pan-filter-role", "circuit-breaker-role")
DRIFT_ALARMS = (
    "fsi-challenger-dispute-rate-breach",
    "fsi-guardrail-intervention-rate-breach",
    "fsi-detection-volume-anomaly",
)
# Low-volume sustained dispute alarm: the fourth breaker trigger.
SUSTAINED_ALARM = "fsi-challenger-dispute-rate-sustained"
TRIGGER_ALARMS = DRIFT_ALARMS + (SUSTAINED_ALARM,)
ACTION_LESS_ALARMS = (
    "fsi-circuit-breaker-dlq-not-empty", "fsi-out-of-band-hold-change", "fsi-break-glass-assumed",
    "fsi-challenger-output-rejected",
    # drift-signal integrity
    "fsi-uncorroborated-drift-alarm", "fsi-corroboration-unavailable", "fsi-drift-shaping-suspected",
    "fsi-drift-metric-publisher-dlq-not-empty", "fsi-drift-metric-publisher-iterator-age",
    "fsi-drift-metric-publisher-errors", "fsi-compliance-invocation-surge",
    # governance-hold sweep
    "fsi-hold-reconciled", "fsi-hold-sweep-failed", "fsi-hold-sweep-not-running",
    # governance-state trip/release serialization
    "fsi-newer-hold-detected", "fsi-hold-release-superseded", "fsi-hold-state-write-failed",
    "fsi-hold-state-read-failed",
)
RUNTIME_LOG_GROUP = "log-group:/aws/bedrock-agentcore/runtimes/*"

_SYNTH_SCRIPT = """
import json
from aws_cdk import App
from aws_cdk.assertions import Template
from agents_stack import AgentsStack
from data_stack import DataStack
app = App()
data = DataStack(app, "TestFsiComplianceData")
agents = AgentsStack(app, "TestFsiComplianceAgents", data_stack=data)
print(json.dumps(Template.from_stack(agents).to_json()))
"""


@pytest.fixture(scope="module")
def template():
    result = subprocess.run(
        [sys.executable, "-c", _SYNTH_SCRIPT],
        cwd=CDK_ROOT, capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, f"synth failed:\n{result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


def _resources(template, resource_type):
    return {
        lid: res for lid, res in template["Resources"].items()
        if res["Type"] == resource_type
    }


def _logical_id(template, resource_type, prop, value):
    for lid, res in _resources(template, resource_type).items():
        if res.get("Properties", {}).get(prop) == value:
            return lid
    raise AssertionError(f"{resource_type} with {prop}={value} not found")


def _role_statements(template, role_name):
    role_id = _logical_id(template, "AWS::IAM::Role", "RoleName", role_name)
    statements = []
    for res in _resources(template, "AWS::IAM::Policy").values():
        if {"Ref": role_id} in res["Properties"].get("Roles", []):
            statements.extend(res["Properties"]["PolicyDocument"]["Statement"])
    return statements


def _as_list(v):
    return v if isinstance(v, list) else [v]


def _render(value):
    """Flatten a CFN Fn::Join / Ref / string into a comparable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(_render(p) for p in parts)
    if isinstance(value, dict) and "Ref" in value:
        return "${" + value["Ref"] + "}"
    if isinstance(value, dict) and "Fn::GetAtt" in value:
        return "${" + ".".join(value["Fn::GetAtt"]) + "}"
    return json.dumps(value, sort_keys=True)


def _log_statements(template, role_name):
    return [
        s for s in _role_statements(template, role_name)
        if any(a.startswith("logs:") or a in ("*", "logs:*") for a in _as_list(s["Action"]))
    ]


# ─── #3: AgentCore runtime log scoping ───────────────────────────────────────

@pytest.mark.parametrize("role_name", AGENT_ROLES)
def test_agent_role_has_no_logs_on_wildcard_resource(template, role_name):
    for s in _log_statements(template, role_name):
        assert "*" not in _as_list(s["Resource"]), s
        assert "logs:*" not in _as_list(s["Action"]), s


@pytest.mark.parametrize("role_name", AGENT_ROLES)
def test_agent_role_log_actions_scoped_to_agentcore_runtime_log_groups(template, role_name):
    expected = {
        ("logs:CreateLogGroup", "logs:DescribeLogStreams"):
            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:" + RUNTIME_LOG_GROUP,
        ("logs:DescribeLogGroups",):
            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:*",
        ("logs:CreateLogStream", "logs:PutLogEvents"):
            "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:" + RUNTIME_LOG_GROUP + ":log-stream:*",
    }
    actual = {}
    for s in _log_statements(template, role_name):
        assert s["Effect"] == "Allow"
        resources = [_render(r) for r in _as_list(s["Resource"])]
        assert len(resources) == 1, s
        actual[tuple(sorted(_as_list(s["Action"])))] = resources[0]
    assert actual == expected


# ─── #4: no AWSLambdaBasicExecutionRole on the AgentCore roles ───────────────

@pytest.mark.parametrize("role_name", AGENT_ROLES)
def test_agent_role_has_no_managed_policies(template, role_name):
    role_id = _logical_id(template, "AWS::IAM::Role", "RoleName", role_name)
    props = template["Resources"][role_id]["Properties"]
    managed = [_render(a) for a in props.get("ManagedPolicyArns", [])]
    assert not any("AWSLambdaBasicExecutionRole" in a for a in managed), managed
    assert managed == []
    principals = props["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]
    assert principals == {"Service": "bedrock-agentcore.amazonaws.com"}


LAMBDA_LOG_GROUPS = {
    "pan-filter-role": ["fsi-pan-filter"],
    "circuit-breaker-role": ["fsi-circuit-breaker", "fsi-circuit-breaker-human"],
}


@pytest.mark.parametrize("role_name", LAMBDA_ROLES)
def test_lambda_roles_log_only_to_their_own_groups(template, role_name):
    role_id = _logical_id(template, "AWS::IAM::Role", "RoleName", role_name)
    assert not template["Resources"][role_id]["Properties"].get("ManagedPolicyArns")
    log_statements = [s for s in _role_statements(template, role_name)
                      if any(a.startswith("logs:") for a in _as_list(s["Action"]))]
    (statement,) = log_statements
    assert sorted(_as_list(statement["Action"])) == ["logs:CreateLogStream", "logs:PutLogEvents"]
    assert sorted(_render(r) for r in _as_list(statement["Resource"])) == sorted(
        f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/fsi/lambda/{fn}:*"
        for fn in LAMBDA_LOG_GROUPS[role_name])


def test_circuit_breaker_attach_detach_grant_unchanged(template):
    """The kill switch still attaches/detaches ONLY governance-hold-deny-all."""
    deny_id = _logical_id(template, "AWS::IAM::ManagedPolicy", "ManagedPolicyName",
                          "governance-hold-deny-all")
    statements = _role_statements(template, "circuit-breaker-role")
    attach = [s for s in statements
              if sorted(_as_list(s["Action"])) == ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]]
    assert len(attach) == 1
    assert attach[0]["Condition"] == {"ArnEquals": {"iam:PolicyARN": {"Ref": deny_id}}}
    role_targets = {_render(r) for r in _as_list(attach[0]["Resource"])}
    expected_targets = {
        "${" + _logical_id(template, "AWS::IAM::Role", "RoleName", r) + ".Arn}"
        for r in AGENT_ROLES
    }
    assert role_targets == expected_targets


def _held_roles_from_zero_managed_policy_account(deny_arn):
    def fake_list_attached(RoleName):
        if RoleName == "compliance-agent-role":
            return {"AttachedPolicies": [{"PolicyName": "governance-hold-deny-all",
                                          "PolicyArn": deny_arn}]}
        return {"AttachedPolicies": []}
    iam = MagicMock()
    iam.list_attached_role_policies.side_effect = fake_list_attached
    return iam


def test_circuit_breaker_status_with_zero_managed_policies(monkeypatch):
    import circuit_breaker.handler as cb
    deny_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
    iam = _held_roles_from_zero_managed_policy_account(deny_arn)
    monkeypatch.setattr(cb, "resolve_deny_policy_arn", lambda: deny_arn)
    monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: iam)
    assert cb.get_status("live") == {
        "status": "GOVERNANCE_HOLD", "revoked_roles": ["compliance-agent-role"],
    }
    iam.list_attached_role_policies.side_effect = lambda RoleName: {"AttachedPolicies": []}
    assert cb.get_status("live")["status"] == "ACTIVE"


def test_dashboard_hold_state_with_zero_managed_policies(monkeypatch):
    from app import invoke_live
    deny_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
    iam = _held_roles_from_zero_managed_policy_account(deny_arn)
    monkeypatch.setattr(invoke_live, "_get_account_id", lambda session: "123456789012")
    session = MagicMock()
    session.client.return_value = iam  # explicit session, never ambient boto3
    state = invoke_live.get_agent_role_hold_state_live(session=session)
    assert state["compliance-agent-role"] == {
        "held": True, "policies": ["governance-hold-deny-all"], "error": None,
    }
    for role in ("detection-agent-role", "executor-agent-role"):
        assert state[role] == {"held": False, "policies": [], "error": None}


# ─── #5: circuit breaker runtime ─────────────────────────────────────────────

def test_circuit_breaker_runtime_is_python313(template):
    fn_id = _logical_id(template, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    assert template["Resources"][fn_id]["Properties"]["Runtime"] == "python3.13"


# ─── #7: circuit breaker DLQ ─────────────────────────────────────────────────

def test_circuit_breaker_dead_letter_queue(template):
    queue_id = _logical_id(template, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    queue = template["Resources"][queue_id]["Properties"]
    assert queue["SqsManagedSseEnabled"] is True
    assert queue["MessageRetentionPeriod"] == 14 * 24 * 3600

    fn_id = _logical_id(template, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    fn = template["Resources"][fn_id]["Properties"]
    assert fn["DeadLetterConfig"] == {"TargetArn": {"Fn::GetAtt": [queue_id, "Arn"]}}
    # Async retries stay at Lambda's default (no EventInvokeConfig override)
    # and no reserved concurrency is set.
    assert not _resources(template, "AWS::Lambda::EventInvokeConfig")
    assert "ReservedConcurrentExecutions" not in fn


def test_circuit_breaker_dlq_enforces_tls(template):
    queue_id = _logical_id(template, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    policies = [
        res["Properties"] for res in _resources(template, "AWS::SQS::QueuePolicy").values()
        if {"Ref": queue_id} in res["Properties"]["Queues"]
    ]
    assert len(policies) == 1
    statements = policies[0]["PolicyDocument"]["Statement"]
    assert any(
        s["Effect"] == "Deny"
        and s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
        and "sqs:*" in _as_list(s["Action"])
        for s in statements
    ), statements


def test_circuit_breaker_role_sqs_send_only_on_dlq(template):
    queue_id = _logical_id(template, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    sqs_statements = [
        s for s in _role_statements(template, "circuit-breaker-role")
        if any(a.startswith("sqs:") for a in _as_list(s["Action"]))
    ]
    assert len(sqs_statements) == 1
    assert _as_list(sqs_statements[0]["Action"]) == ["sqs:SendMessage"]
    assert _as_list(sqs_statements[0]["Resource"]) == [{"Fn::GetAtt": [queue_id, "Arn"]}]
    # No other role may write to the circuit breaker DLQ.
    for role_name in AGENT_ROLES + ("pan-filter-role",):
        for s in _role_statements(template, role_name):
            assert {"Fn::GetAtt": [queue_id, "Arn"]} not in _as_list(s["Resource"])


def test_circuit_breaker_dlq_alarm_has_no_lambda_action(template):
    queue_id = _logical_id(template, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    alarm_id = _logical_id(template, "AWS::CloudWatch::Alarm", "AlarmName",
                           "fsi-circuit-breaker-dlq-not-empty")
    alarm = template["Resources"][alarm_id]["Properties"]
    assert alarm["MetricName"] == "ApproximateNumberOfMessagesVisible"
    assert alarm["Namespace"] == "AWS/SQS"
    assert alarm["Dimensions"] == [{"Name": "QueueName",
                                    "Value": {"Fn::GetAtt": [queue_id, "QueueName"]}}]
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold"
    assert alarm["Threshold"] == 0
    assert alarm["EvaluationPeriods"] == 1
    assert alarm["DatapointsToAlarm"] == 1
    assert alarm["Period"] in (60, 300)
    assert notifies_on_call_only(alarm), alarm.get("AlarmActions")


# ─── Unchanged: drift alarms + their Lambda permissions ──────────────────────

def test_drift_alarms_and_lambda_permissions_unchanged(template):
    fn_id = _logical_id(template, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    fn_arn = {"Fn::GetAtt": [fn_id, "Arn"]}
    alarm_ids = {}
    for name in TRIGGER_ALARMS:
        alarm_id = _logical_id(template, "AWS::CloudWatch::Alarm", "AlarmName", name)
        assert template["Resources"][alarm_id]["Properties"]["AlarmActions"] == [fn_arn]
        alarm_ids[name] = alarm_id

    all_perms = [
        p["Properties"] for p in _resources(template, "AWS::Lambda::Permission").values()
        if p["Properties"].get("FunctionName") == fn_arn
    ]
    # Who can invoke the breaker stays pinned: the four alarm actions plus
    # exactly one EventBridge permission for fsi-breaker-alarm-recheck,
    # and nothing else.
    perms = [p for p in all_perms if p["Principal"] == "lambda.alarms.cloudwatch.amazonaws.com"]
    events_perms = [p for p in all_perms if p["Principal"] == "events.amazonaws.com"]
    assert len(perms) == len(TRIGGER_ALARMS)
    assert len(all_perms) == len(TRIGGER_ALARMS) + 1
    recheck_id = _logical_id(template, "AWS::Events::Rule", "Name", "fsi-breaker-alarm-recheck")
    (events_perm,) = events_perms
    assert events_perm["Action"] == "lambda:InvokeFunction"
    assert events_perm["SourceArn"] == {"Fn::GetAtt": [recheck_id, "Arn"]}
    for p in perms:
        assert p["Action"] == "lambda:InvokeFunction"
        assert p["Principal"] == "lambda.alarms.cloudwatch.amazonaws.com"
    assert {json.dumps(p["SourceArn"], sort_keys=True) for p in perms} == {
        json.dumps({"Fn::GetAtt": [alarm_ids[n], "Arn"]}, sort_keys=True) for n in TRIGGER_ALARMS
    }

    trusted = _render(template["Resources"][fn_id]["Properties"]["Environment"]
                      ["Variables"]["TRUSTED_ALARM_ARNS"])
    assert trusted == ",".join(
        f"arn:aws:cloudwatch:${{AWS::Region}}:${{AWS::AccountId}}:alarm:{n}" for n in TRIGGER_ALARMS
    )
    # The alarms in the stack: the three drift alarms, the sustained
    # dispute alarm, the DLQ alarm, the two hold-change
    # monitoring alarms, the challenger output-rejected alarm,
    # and the drift-signal integrity alarms (uncorroborated drift alarm,
    # corroboration unavailable, shaping suspected, publisher DLQ /
    # iterator age / errors, invocation surge).
    # Only the four trigger alarms invoke the automated breaker (and nothing
    # else); every other alarm only notifies on-call.
    alarms = _resources(template, "AWS::CloudWatch::Alarm").values()
    assert sorted(a["Properties"]["AlarmName"] for a in alarms) == sorted(
        TRIGGER_ALARMS + ACTION_LESS_ALARMS)
    for a in alarms:
        if a["Properties"]["AlarmName"] not in TRIGGER_ALARMS:
            assert notifies_on_call_only(a["Properties"]), a["Properties"]["AlarmName"]
