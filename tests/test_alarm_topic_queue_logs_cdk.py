"""
Synthesized-template checks for three hardening fixes (local synth only):
- fsi-governance-alarms: KMS-encrypted SNS topic that only this account's
  CloudWatch alarms may publish to (TLS only); every review-only alarm
  notifies it, the four breaker-trigger alarms don't; optional alarm_email.
- fsi-analyst-review: SendMessage denied to everyone but executor-agent-role.
- Lambda logging: no AWSLambdaBasicExecutionRole on any stack role; each
  function writes to its own /fsi/lambda/<fn> group (30-day retention).
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _cdk_synth import (  # noqa: E402
    CDK_ROOT, DEFAULT_CONTEXT, FULL_CONTEXT, as_list, logical_id, notifies_on_call_only, render, resources,
    role_props, role_statements, synth,
)

TRIGGER_ALARMS = {
    "fsi-challenger-dispute-rate-breach", "fsi-guardrail-intervention-rate-breach",
    "fsi-detection-volume-anomaly", "fsi-challenger-dispute-rate-sustained",
}
LAMBDA_FUNCTIONS = {
    "fsi-audit-archiver": "fsi-audit-archiver-role",
    "fsi-pan-filter": "pan-filter-role",
    "fsi-circuit-breaker": "circuit-breaker-role",
    "fsi-circuit-breaker-human": "circuit-breaker-role",
    "fsi-governance-hold-sweep": "governance-hold-sweep-role",
    "fsi-drift-metric-publisher": "fsi-drift-metric-publisher-role",
}
EMAIL_CONTEXT = {"alarm_email": "oncall@example.com"}


@pytest.fixture(scope="module")
def default():
    return synth(DEFAULT_CONTEXT)


def _topic(data):
    return logical_id(data, "AWS::SNS::Topic", "TopicName", "fsi-governance-alarms")


# ─── Alarm topic ─────────────────────────────────────────────────────────────
def test_topic_is_encrypted_with_its_own_rotating_cmk(default):
    data = default["data"]
    topic = data["Resources"][_topic(data)]["Properties"]
    key_id = topic["KmsMasterKeyId"]["Fn::GetAtt"][0]
    key = data["Resources"][key_id]
    assert key["Type"] == "AWS::KMS::Key" and key["Properties"]["EnableKeyRotation"] is True
    (alias,) = [a["Properties"] for a in resources(data, "AWS::KMS::Alias").values()
                if a["Properties"]["AliasName"] == "alias/fsi-governance-alarms"]
    assert alias["TargetKeyId"] == {"Fn::GetAtt": [key_id, "Arn"]}
    statements = {s["Sid"]: s for s in key["Properties"]["KeyPolicy"]["Statement"]}
    assert set(statements) == {"KeyAdministration", "CloudWatchAlarmsPublishEncrypted"}
    cw = statements["CloudWatchAlarmsPublishEncrypted"]
    assert cw["Principal"] == {"Service": "cloudwatch.amazonaws.com"}
    assert sorted(as_list(cw["Action"])) == ["kms:Decrypt", "kms:GenerateDataKey*"]
    assert render(cw["Condition"]["StringEquals"]["aws:SourceAccount"]) == "${AWS::AccountId}"
    assert render(cw["Condition"]["ArnLike"]["aws:SourceArn"]) == \
        "arn:aws:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:*"
    admin = statements["KeyAdministration"]
    assert not any(a.startswith(("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt"))
                   or a in ("kms:*", "*") for a in as_list(admin["Action"]))


def test_topic_policy_cloudwatch_alarms_of_this_account_only_and_tls(default):
    data = default["data"]
    topic_id = _topic(data)
    (policy,) = [p["Properties"] for p in resources(data, "AWS::SNS::TopicPolicy").values()
                 if p["Properties"]["Topics"] == [{"Ref": topic_id}]]
    statements = policy["PolicyDocument"]["Statement"]
    allows = [s for s in statements if s["Effect"] == "Allow"]
    (allow,) = allows
    assert allow["Principal"] == {"Service": "cloudwatch.amazonaws.com"} and allow["Action"] == "sns:Publish"
    assert render(allow["Condition"]["StringEquals"]["aws:SourceAccount"]) == "${AWS::AccountId}"
    alarm_arns = "arn:aws:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:*"
    assert render(allow["Condition"]["ArnLike"]["aws:SourceArn"]) == alarm_arns
    denies = [s for s in statements if s["Effect"] == "Deny"]
    assert any(s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}} for s in denies)
    (others,) = [s for s in denies if "ArnNotLike" in s.get("Condition", {})]
    assert others["Principal"] in ("*", {"AWS": "*"}) and others["Action"] == "sns:Publish"
    assert render(others["Condition"]["ArnNotLike"]["aws:SourceArn"]) == alarm_arns


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_review_only_alarms_notify_and_trigger_alarms_do_not(context):
    templates = synth(context)
    alarms = {}
    for name in ("data", "agents"):
        for r in resources(templates[name], "AWS::CloudWatch::Alarm").values():
            alarms[r["Properties"]["AlarmName"]] = r["Properties"]
    breaker = {"Fn::GetAtt": [logical_id(templates["agents"], "AWS::Lambda::Function", "FunctionName",
                                         "fsi-circuit-breaker"), "Arn"]}
    assert TRIGGER_ALARMS <= set(alarms)
    for name, props in alarms.items():
        if name in TRIGGER_ALARMS:
            assert props["AlarmActions"] == [breaker], name
        else:
            assert notifies_on_call_only(props), name
    # The data-stack alarms reference the topic directly; the agents-stack
    # ones import that same export.
    topic_ref = {"Ref": _topic(templates["data"])}
    exports = {o["Export"]["Name"] for o in templates["data"]["Outputs"].values()
               if o.get("Value") == topic_ref and "Export" in o}
    for name, props in alarms.items():
        if name not in TRIGGER_ALARMS:
            (action,) = props["AlarmActions"]
            assert action == topic_ref or action.get("Fn::ImportValue") in exports, name


def test_no_email_subscription_without_context(default):
    assert not resources(default["data"], "AWS::SNS::Subscription")


def test_alarm_email_context_adds_one_email_subscription():
    data = synth(EMAIL_CONTEXT)["data"]
    (sub,) = [r["Properties"] for r in resources(data, "AWS::SNS::Subscription").values()]
    assert sub == {"Endpoint": "oncall@example.com", "Protocol": "email", "TopicArn": {"Ref": _topic(data)}}


def test_alarm_email_context_parser():
    sys.path.insert(0, CDK_ROOT)
    try:
        m = importlib.import_module("governance_alarms")
    finally:
        sys.path.remove(CDK_ROOT)
    assert m.context_alarm_email(None) is None and m.context_alarm_email("") is None
    assert m.context_alarm_email("on-call+fsi@example.co.uk") == "on-call+fsi@example.co.uk"
    for bad in ("not-an-email", "a@b", "a@example.com,b@example.com", "Name <a@example.com>", True, 7,
                "x" * 250 + "@example.com"):
        with pytest.raises(ValueError):
            m.context_alarm_email(bad)


# ─── Analyst queue ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_analyst_queue_send_denied_except_executor(context):
    data = synth(context)["data"]
    queue_id = logical_id(data, "AWS::SQS::Queue", "QueueName", "fsi-analyst-review")
    (policy,) = [p["Properties"] for p in resources(data, "AWS::SQS::QueuePolicy").values()
                 if p["Properties"]["Queues"] == [{"Ref": queue_id}]]
    statements = policy["PolicyDocument"]["Statement"]
    assert all(s["Effect"] == "Deny" for s in statements)
    assert any(s["Action"] == "sqs:*" and s["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
               for s in statements)
    (send,) = [s for s in statements if s.get("Sid") == "DenySendExceptExecutor"]
    assert send["Principal"] == {"AWS": "*"} and send["Action"] == "sqs:SendMessage"
    assert send["Resource"] == {"Fn::GetAtt": [queue_id, "Arn"]}
    (arn,) = send["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]
    assert render(arn) == "arn:aws:iam::${AWS::AccountId}:role/executor-agent-role"


def test_executor_role_name_matches_the_queue_exemption(default):
    agents = default["agents"]
    assert logical_id(agents, "AWS::IAM::Role", "RoleName", "executor-agent-role")
    sends = [s for s in role_statements(agents, "executor-agent-role") if "sqs:SendMessage" in as_list(s["Action"])]
    assert sends


# ─── Lambda logging ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_no_stack_role_attaches_aws_lambda_basic_execution_role(context):
    templates = synth(context)
    for t in templates.values():
        for lid, role in resources(t, "AWS::IAM::Role").items():
            if lid.startswith("CustomS3AutoDeleteObjectsCustomResourceProvider"):
                continue  # CDK's own auto-delete provider (not a stack function role)
            managed = [render(a) for a in role["Properties"].get("ManagedPolicyArns", [])]
            assert not any("AWSLambdaBasicExecutionRole" in a for a in managed), lid


@pytest.mark.parametrize("function_name", sorted(LAMBDA_FUNCTIONS))
def test_function_logs_to_its_own_group_with_retention(default, function_name):
    template = default["data"] if function_name == "fsi-audit-archiver" else default["agents"]
    fn = template["Resources"][logical_id(template, "AWS::Lambda::Function", "FunctionName", function_name)]
    group = template["Resources"][fn["Properties"]["LoggingConfig"]["LogGroup"]["Ref"]]
    assert group["Properties"] == {"LogGroupName": f"/fsi/lambda/{function_name}", "RetentionInDays": 30}
    assert group["DeletionPolicy"] == "Delete"


@pytest.mark.parametrize("role_name", sorted(set(LAMBDA_FUNCTIONS.values())))
def test_role_logs_only_to_its_functions_groups(default, role_name):
    template = default["data"] if role_name == "fsi-audit-archiver-role" else default["agents"]
    assert not role_props(template, role_name).get("ManagedPolicyArns")
    log_statements = [s for s in role_statements(template, role_name)
                      if any(a.startswith("logs:") for a in as_list(s["Action"]))]
    (statement,) = log_statements
    assert statement["Effect"] == "Allow"
    assert sorted(as_list(statement["Action"])) == ["logs:CreateLogStream", "logs:PutLogEvents"]
    expected = sorted(f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/fsi/lambda/{fn}:*"
                      for fn, role in LAMBDA_FUNCTIONS.items() if role == role_name)
    assert sorted(render(r) for r in as_list(statement["Resource"])) == expected
