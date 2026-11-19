"""
Test: governance IAM/KMS/monitoring in the synthesized CDK.

Two synths (shared, cached): no context, and allow_console_drift_injection +
console_host_role_arn + ci_role_arn.
"""
import importlib
import sys

import pytest

from _cdk_synth import (
    CDK_ROOT, DEFAULT_CONTEXT, FULL_CONTEXT, as_list, is_account_root, logical_id, render, resources,
    role_actions, role_id, role_props, role_statements, statements_with_action, synth,
    notifies_on_call_only,
)

BREAKER_HUMAN_ROLES = ("fsi-breaker-operator", "fsi-breaker-approver", "fsi-breaker-break-glass")
HUMAN_ROLES = ("fsi-model-risk-approver", "fsi-deploy-gate-signer", "fsi-compliance-reader",
               "fsi-console-operator", "fsi-console-operator-hosted") + BREAKER_HUMAN_ROLES
MFA_TRUST = {"Bool": {"aws:MultiFactorAuthPresent": "true"},
             "StringEquals": {"sts:RoleSessionName": "${aws:username}"}}
HOST_ARN = "arn:aws:iam::123456789012:role/console-host"
CI_ARN = "arn:aws:iam::123456789012:role/ci"
CONSOLE_OPERATOR_ACTIONS = {
    "bedrock-agentcore:InvokeAgentRuntime", "ssm:GetParameter",
    "dynamodb:PutItem", "dynamodb:Query", "iam:ListAttachedRolePolicies", "cloudwatch:DescribeAlarms",
    "bedrock:InvokeModel", "bedrock:ApplyGuardrail", "lambda:InvokeFunction",
}
# Pre-change set (the S3 auto-delete provider, fsi-pan-filter,
# fsi-circuit-breaker) plus the human breaker entry point and the
# drift metric publisher and the reconciling sweep.
EXPECTED_FUNCTION_NAMES = {None, "fsi-pan-filter", "fsi-circuit-breaker", "fsi-circuit-breaker-human",
                           "fsi-drift-metric-publisher", "fsi-governance-hold-sweep"}
PRE_CHANGE_ROLES = {None, "detection-agent-role", "compliance-agent-role", "executor-agent-role",
                    "pan-filter-role", "circuit-breaker-role", "fsi-drift-metric-publisher-role",
                    "governance-hold-sweep-role"}


@pytest.fixture(scope="module")
def agents():
    return synth(DEFAULT_CONTEXT)["agents"]


@pytest.fixture(scope="module")
def ctx_agents():
    return synth(FULL_CONTEXT)["agents"]


def _present_human_roles(template):
    names = {r["Properties"].get("RoleName") for r in resources(template, "AWS::IAM::Role").values()}
    return [n for n in HUMAN_ROLES if n in names]


# ─── Signing keys ────────────────────────────────────────────────────────────

def _key_by_alias(template, alias):
    (a,) = [r for r in resources(template, "AWS::KMS::Alias").values() if r["Properties"]["AliasName"] == alias]
    key_id = a["Properties"]["TargetKeyId"]["Fn::GetAtt"][0] if "Fn::GetAtt" in a["Properties"]["TargetKeyId"] \
        else a["Properties"]["TargetKeyId"]["Ref"]
    return key_id, template["Resources"][key_id]


@pytest.mark.parametrize("alias,signer", [("alias/fsi-model-registry-signing", "fsi-model-risk-approver"),
                                          ("alias/fsi-deploy-gate-signing", "fsi-deploy-gate-signer")])
def test_signing_keys(agents, alias, signer):
    _, key = _key_by_alias(agents, alias)
    props = key["Properties"]
    assert props["KeySpec"] == "ECC_NIST_P256" and props["KeyUsage"] == "SIGN_VERIFY"
    assert key["DeletionPolicy"] == "Retain"
    statements = props["KeyPolicy"]["Statement"]
    for s in statements:
        actions = as_list(s["Action"])
        assert "kms:*" not in actions
        if is_account_root(s["Principal"]):
            assert "kms:Sign" not in actions, s
    signers = [s for s in statements if "kms:Sign" in as_list(s["Action"])]
    assert len(signers) == 1
    assert signers[0]["Principal"] == {"AWS": {"Fn::GetAtt": [role_id(agents, signer), "Arn"]}}
    verify = [s for s in statements if "kms:Verify" in as_list(s["Action"])]
    assert len(verify) == 1 and is_account_root(verify[0]["Principal"])
    assert sorted(as_list(verify[0]["Action"])) == ["kms:DescribeKey", "kms:GetPublicKey", "kms:Verify"]


def test_signing_key_outputs(agents):
    assert {"RegistrySigningKeyArn", "GateSigningKeyArn"} <= set(agents["Outputs"])


def test_agent_roles_verify_gate_key_and_compliance_registry_key(agents):
    gate_id, _ = _key_by_alias(agents, "alias/fsi-deploy-gate-signing")
    registry_id, _ = _key_by_alias(agents, "alias/fsi-model-registry-signing")
    for role in ("detection-agent-role", "compliance-agent-role", "executor-agent-role"):
        kms = [s for s in role_statements(agents, role) if "kms:Verify" in as_list(s["Action"])]
        resources_ = {render(r) for s in kms for r in as_list(s["Resource"])}
        assert "${" + gate_id + ".Arn}" in resources_, role
        assert ("${" + registry_id + ".Arn}" in resources_) is (role == "compliance-agent-role"), role
        for s in kms:
            assert sorted(as_list(s["Action"])) == ["kms:DescribeKey", "kms:Verify"]


def test_executor_encrypts_with_sar_key_only(agents):
    stmts = statements_with_action(agents, "executor-agent-role", "kms:GenerateDataKey")
    assert len(stmts) == 1
    assert sorted(as_list(stmts[0]["Action"])) == ["kms:Encrypt", "kms:GenerateDataKey"]
    assert [("SarFilingsKey" in render(r)) for r in as_list(stmts[0]["Resource"])] == [True]
    for role in ("detection-agent-role", "compliance-agent-role"):
        assert not statements_with_action(agents, role, "kms:GenerateDataKey")


# ─── Signer and approver roles ───────────────────────────────────────────────

def test_gate_signer_exact_actions_and_resources(agents):
    assert role_actions(agents, "fsi-deploy-gate-signer") == {
        "kms:Sign", "kms:DescribeKey", "kms:Verify", "bedrock-agentcore:ListAgentRuntimes",
        "bedrock-agentcore:GetAgentRuntime", "iam:GetRole", "cloudformation:DescribeStacks"}
    gate_id, _ = _key_by_alias(agents, "alias/fsi-deploy-gate-signing")
    registry_id, _ = _key_by_alias(agents, "alias/fsi-model-registry-signing")
    by_actions = {tuple(sorted(as_list(s["Action"]))): [render(r) for r in as_list(s["Resource"])]
                  for s in role_statements(agents, "fsi-deploy-gate-signer")}
    assert by_actions[("kms:DescribeKey", "kms:Sign")] == ["${" + gate_id + ".Arn}"]
    assert by_actions[("kms:DescribeKey", "kms:Verify")] == ["${" + registry_id + ".Arn}"]
    assert by_actions[("bedrock-agentcore:ListAgentRuntimes",)] == ["*"]
    assert by_actions[("bedrock-agentcore:GetAgentRuntime",)] == [
        "arn:aws:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:runtime/ComplianceAgent-*"]
    assert len(by_actions[("iam:GetRole",)]) == 3
    assert by_actions[("cloudformation:DescribeStacks",)] == [
        "arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/FsiComplianceAgents/*"]


def test_model_risk_approver_exact_actions(agents):
    registry_id, _ = _key_by_alias(agents, "alias/fsi-model-registry-signing")
    statements = role_statements(agents, "fsi-model-risk-approver")
    assert role_actions(agents, "fsi-model-risk-approver") == {"kms:Sign", "kms:DescribeKey", "kms:Verify"}
    assert {render(r) for s in statements for r in as_list(s["Resource"])} == {"${" + registry_id + ".Arn}"}


def test_signer_trust_without_ci(agents):
    (s,) = role_props(agents, "fsi-deploy-gate-signer")["AssumeRolePolicyDocument"]["Statement"]
    assert is_account_root(s["Principal"]) and s["Condition"] == MFA_TRUST


def test_signer_trust_with_ci(ctx_agents):
    statements = role_props(ctx_agents, "fsi-deploy-gate-signer")["AssumeRolePolicyDocument"]["Statement"]
    assert len(statements) == 2
    assert is_account_root(statements[0]["Principal"]) and statements[0]["Condition"] == MFA_TRUST
    assert statements[1]["Principal"] == {"AWS": CI_ARN}
    assert statements[1]["Action"] == "sts:AssumeRole" and "Condition" not in statements[1]


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_model_risk_approver_never_trusts_ci(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    (s,) = role_props(t, "fsi-model-risk-approver")["AssumeRolePolicyDocument"]["Statement"]
    assert is_account_root(s["Principal"]) and s["Condition"] == MFA_TRUST


# ─── Console operator roles ──────────────────────────────────────────────────

def test_console_operator_exact_actions_without_drift_context(agents):
    props = role_props(agents, "fsi-console-operator")
    assert props["Path"] == "/fsi-console/"
    assert role_actions(agents, "fsi-console-operator") == CONSOLE_OPERATOR_ACTIONS
    (invoke,) = statements_with_action(agents, "fsi-console-operator", "bedrock-agentcore:InvokeAgentRuntime")
    rendered = [render(r) for r in as_list(invoke["Resource"])]
    prefix = "arn:aws:bedrock-agentcore:${AWS::Region}:${AWS::AccountId}:runtime/"
    for agent in ("DetectionAgent", "ComplianceAgent", "ExecutorAgent"):
        assert f"{prefix}{agent}-*" in rendered
        assert f"{prefix}{agent}-*/runtime-endpoint/*" in rendered
    # The pinned runtime ARNs: one parameter, read only; no runtime listing.
    (pins,) = statements_with_action(agents, "fsi-console-operator", "ssm:GetParameter")
    assert as_list(pins["Action"]) == ["ssm:GetParameter"]
    assert [render(r) for r in as_list(pins["Resource"])] == [
        "arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter/fsi/governance/agentcore-runtime-arns"]
    (alarms,) = statements_with_action(agents, "fsi-console-operator", "cloudwatch:DescribeAlarms")
    assert [render(r) for r in as_list(alarms["Resource"])] == [
        "arn:aws:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:fsi-*"]


def test_hosted_role_absent_without_context(agents):
    names = {r["Properties"].get("RoleName") for r in resources(agents, "AWS::IAM::Role").values()}
    assert "fsi-console-operator-hosted" not in names


def test_drift_injection_grant_only_on_direct_operator_with_context(agents, ctx_agents):
    for name in _present_human_roles(agents):
        assert "cloudwatch:PutMetricData" not in role_actions(agents, name), name
    assert role_actions(ctx_agents, "fsi-console-operator") == CONSOLE_OPERATOR_ACTIONS | {"cloudwatch:PutMetricData"}
    (put,) = statements_with_action(ctx_agents, "fsi-console-operator", "cloudwatch:PutMetricData")
    assert put["Condition"] == {"StringEquals": {"cloudwatch:namespace": "FSI/AgenticCompliance"}}
    assert role_actions(ctx_agents, "fsi-console-operator-hosted") == CONSOLE_OPERATOR_ACTIONS


def test_hosted_role_trust(ctx_agents):
    props = role_props(ctx_agents, "fsi-console-operator-hosted")
    assert props["Path"] == "/fsi-console/" and props["MaxSessionDuration"] == 3600
    # One statement: the sts:SourceIdentity condition needs sts:SetSourceIdentity
    # in the same action block (Access Analyzer MISSING_ACTION_FOR_CONDITION_KEY).
    (s,) = props["AssumeRolePolicyDocument"]["Statement"]
    assert s["Action"] == ["sts:AssumeRole", "sts:SetSourceIdentity"]
    assert s["Principal"] == {"AWS": HOST_ARN}
    assert s["Condition"] == {"StringLike": {"sts:RoleSessionName": "cognito-*",
                                             "sts:SourceIdentity": "cognito-*"}}


# ─── Every human role ────────────────────────────────────────────────────────

def _fn_arn(template, name):
    return "${" + logical_id(template, "AWS::Lambda::Function", "FunctionName", name) + ".Arn}"


# Human lambda:InvokeFunction grants: the human breaker entry point
# for the breaker and console roles, plus fsi-pan-filter for the console roles.
HUMAN_INVOKE_TARGETS = {
    "fsi-breaker-operator": {"fsi-circuit-breaker-human"},
    "fsi-breaker-approver": {"fsi-circuit-breaker-human"},
    "fsi-console-operator": {"fsi-pan-filter", "fsi-circuit-breaker-human"},
    "fsi-console-operator-hosted": {"fsi-pan-filter", "fsi-circuit-breaker-human"},
}


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_no_human_role_can_invoke_the_automated_breaker(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    present = _present_human_roles(t)
    assert len(present) == (7 if which == "default" else 8)
    automated = _fn_arn(t, "fsi-circuit-breaker")
    for name in present:
        invoke_resources = set()
        for s in role_statements(t, name):
            actions = as_list(s["Action"])
            for action in actions:
                assert action not in ("*", "lambda:*"), (name, action)
                assert not action.startswith("lambda:") or action == "lambda:InvokeFunction", (name, action)
            rendered = {render(r) for r in as_list(s["Resource"])}
            assert automated not in rendered, name
            assert not any(r.endswith(":function:fsi-circuit-breaker") for r in rendered), name
            if "lambda:InvokeFunction" in actions:
                assert actions == ["lambda:InvokeFunction"] or actions == "lambda:InvokeFunction", name
                invoke_resources |= rendered
        expected = {_fn_arn(t, fn) for fn in HUMAN_INVOKE_TARGETS.get(name, set())}
        assert invoke_resources == expected, name


def test_only_the_executor_invokes_the_automated_breaker(agents):
    automated = "arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:fsi-circuit-breaker"
    holders = set()
    for policy in resources(agents, "AWS::IAM::Policy").values():
        for s in policy["Properties"]["PolicyDocument"]["Statement"]:
            rendered = {render(r) for r in as_list(s["Resource"])}
            if automated in rendered or _fn_arn(agents, "fsi-circuit-breaker") in rendered:
                holders.update(render(r) for r in policy["Properties"]["Roles"])
    assert holders == {"${" + role_id(agents, "executor-agent-role") + "}"}


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_human_roles_inline_only_one_hour_sessions_mfa_trust(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    for name in _present_human_roles(t):
        props = role_props(t, name)
        assert not props.get("ManagedPolicyArns"), name
        assert props["MaxSessionDuration"] == 3600, name
        if name == "fsi-console-operator-hosted":
            continue
        first = props["AssumeRolePolicyDocument"]["Statement"][0]
        assert is_account_root(first["Principal"]) and first["Condition"] == MFA_TRUST, name


def test_lambda_and_role_inventory(agents, ctx_agents):
    """Only fsi-circuit-breaker-human is new; no custom resource; only the expected new roles."""
    for t, new_roles in ((agents, set(HUMAN_ROLES) - {"fsi-console-operator-hosted"}),
                         (ctx_agents, set(HUMAN_ROLES) | {"fsi-console-audit-writer-hosted"})):
        functions = [r["Properties"].get("FunctionName") for r in resources(t, "AWS::Lambda::Function").values()]
        assert sorted(functions, key=str) == sorted(EXPECTED_FUNCTION_NAMES, key=str)
        roles = {r["Properties"].get("RoleName") for r in resources(t, "AWS::IAM::Role").values()}
        assert roles == PRE_CHANGE_ROLES | new_roles
        custom = {r["Type"] for r in t["Resources"].values() if r["Type"].startswith("Custom::")}
        assert custom == {"Custom::S3AutoDeleteObjects"}


# ─── Hold-change monitoring ──────────────────────────────────────────────────

EXPECTED_SCHEDULES = {"fsi-breaker-alarm-recheck": "rate(2 minutes)",
                      "fsi-governance-hold-sweep": "rate(5 minutes)"}
SCHEDULE_INPUTS = {"fsi-breaker-alarm-recheck": '{"action":"recheck_alarms"}',
                   "fsi-governance-hold-sweep": '{"action":"reconcile_hold"}'}
SCHEDULE_TARGETS = {"fsi-breaker-alarm-recheck": "fsi-circuit-breaker",
                    "fsi-governance-hold-sweep": "fsi-governance-hold-sweep"}


def test_hold_change_resources(agents):
    (lg_id, lg), = [(lid, r) for lid, r in resources(agents, "AWS::Logs::LogGroup").items()
                    if r["Properties"]["LogGroupName"] == "/fsi/governance/hold-changes"]
    assert lg["Properties"]["LogGroupName"] == "/fsi/governance/hold-changes"
    assert lg["Properties"]["RetentionInDays"] == 365
    assert lg["DeletionPolicy"] == "Retain"
    all_rules = resources(agents, "AWS::Events::Rule")
    # The CloudTrail rules (EventPattern, no schedule); the schedule rules
    # are asserted below. Every use of ``rules``,
    # including the ResourcePolicy loop, is the filtered CloudTrail set.
    rules = {lid: r for lid, r in all_rules.items()
             if "EventPattern" in r["Properties"] and "ScheduleExpression" not in r["Properties"]}
    assert len(rules) == 2
    schedules = {r["Properties"]["Name"]: r["Properties"] for r in all_rules.values()
                 if "ScheduleExpression" in r["Properties"]}
    assert {n: p["ScheduleExpression"] for n, p in schedules.items()} == EXPECTED_SCHEDULES
    for name, props in schedules.items():
        (target,) = props["Targets"]
        assert target["Input"] == SCHEDULE_INPUTS[name]
        assert target["Arn"] == {"Fn::GetAtt": [logical_id(agents, "AWS::Lambda::Function", "FunctionName",
                                                           SCHEDULE_TARGETS[name]), "Arn"]}
    for rule in rules.values():
        assert rule["Properties"]["Targets"] == [{"Arn": {"Fn::GetAtt": [lg_id, "Arn"]}, "Id": "Target0"}]
        assert "RoleArn" not in rule["Properties"]["Targets"][0]
    patterns = sorted((r["Properties"]["EventPattern"] for r in rules.values()), key=lambda p: p["source"])
    iam_pattern, sts_pattern = patterns
    assert iam_pattern == {
        "source": ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {"eventSource": ["iam.amazonaws.com"], "eventName": ["AttachRolePolicy", "DetachRolePolicy"],
                   "requestParameters": {"roleName": ["detection-agent-role", "compliance-agent-role",
                                                      "executor-agent-role"]}}}
    assert sts_pattern["source"] == ["aws.sts"]
    assert sts_pattern["detail"]["eventName"] == ["AssumeRole"]
    assert [render(a) for a in sts_pattern["detail"]["requestParameters"]["roleArn"]] == [
        "arn:aws:iam::${AWS::AccountId}:role/fsi-breaker/fsi-breaker-break-glass"]

    (policy,) = resources(agents, "AWS::Logs::ResourcePolicy").values()
    doc = render(policy["Properties"]["PolicyDocument"])
    assert '"events.amazonaws.com"' in doc and '"logs:PutLogEvents"' in doc
    assert "${" + lg_id + ".Arn}" in doc
    for rule_id in rules:
        assert "${" + rule_id + ".Arn}" in doc
    assert '"aws:SourceArn"' in doc and "ArnEquals" in doc
    assert not [r for r in agents["Resources"].values() if r["Type"] == "Custom::CloudwatchLogResourcePolicy"]


def test_metric_filters(agents):
    filters = {r["Properties"]["MetricTransformations"][0]["MetricName"]: r["Properties"]
               for r in resources(agents, "AWS::Logs::MetricFilter").values()}
    assert set(filters) == {"HoldChangeTotal", "HoldChangeByBreaker", "BreakGlassAssumed"}
    events_ = '($.detail.eventName = "AttachRolePolicy") || ($.detail.eventName = "DetachRolePolicy")'
    assert filters["HoldChangeTotal"]["FilterPattern"] == "{ " + events_ + " }"
    # Hold-sweep ATTACHES count as the breaker's.
    assert filters["HoldChangeByBreaker"]["FilterPattern"] == (
        "{ ((" + events_ + ") && "
        '($.detail.userIdentity.sessionContext.sessionIssuer.userName = "circuit-breaker-role")) || '
        '(($.detail.eventName = "AttachRolePolicy") && '
        '($.detail.userIdentity.sessionContext.sessionIssuer.userName = "governance-hold-sweep-role")) }')
    assert filters["BreakGlassAssumed"]["FilterPattern"] == '{ $.detail.eventName = "AssumeRole" }'
    for props in filters.values():
        (transform,) = props["MetricTransformations"]
        assert transform["MetricNamespace"] == "FSI/GovernanceIntegrity"
        assert transform["MetricValue"] == "1" and "DefaultValue" not in transform


def test_hold_sweep_liveness_alarm(agents):
    """No heartbeat for three sweep periods pages on-call; missing data
    (the sweep stopped) is breaching."""
    props = _alarm(agents, "fsi-hold-sweep-not-running")
    assert props["Namespace"] == "FSI/GovernanceIntegrity" and props["MetricName"] == "HoldSweepHeartbeat"
    assert props["Statistic"] == "Sum" and props["Period"] == 300
    assert props["Threshold"] == 1 and props["ComparisonOperator"] == "LessThanThreshold"
    assert props["EvaluationPeriods"] == 3 and props["DatapointsToAlarm"] == 3
    assert props["TreatMissingData"] == "breaching"
    assert notifies_on_call_only(props)


def test_hold_change_alarms_are_action_less(agents):
    alarms = {r["Properties"]["AlarmName"]: r["Properties"] for r in resources(agents, "AWS::CloudWatch::Alarm").values()}
    oob = alarms["fsi-out-of-band-hold-change"]
    expressions = [m.get("Expression") for m in oob["Metrics"] if m.get("Expression")]
    assert expressions == ["FILL(total,0) - FILL(breaker,0)"]
    assert oob["Threshold"] == 0 and oob["ComparisonOperator"] == "GreaterThanThreshold"
    assert oob["TreatMissingData"] == "notBreaching"
    glass = alarms["fsi-break-glass-assumed"]
    assert glass["MetricName"] == "BreakGlassAssumed" and glass["Statistic"] == "Sum" and glass["Period"] == 300
    for props in (oob, glass):
        assert notifies_on_call_only(props)


# ─── PAN reserved concurrency and context parsing ────────────────────────────

def test_pan_filter_reserved_concurrency_default(agents):
    fn = agents["Resources"][logical_id(agents, "AWS::Lambda::Function", "FunctionName", "fsi-pan-filter")]
    assert fn["Properties"]["ReservedConcurrentExecutions"] == 10


@pytest.fixture(scope="module")
def agents_stack_module():
    sys.path.insert(0, CDK_ROOT)
    try:
        return importlib.import_module("agents_stack")
    finally:
        sys.path.remove(CDK_ROOT)


def test_context_parsers(agents_stack_module):
    m = agents_stack_module
    assert m.context_reserved_concurrency(None) == 10
    assert m.context_reserved_concurrency("0") is None and m.context_reserved_concurrency(0) is None
    assert m.context_reserved_concurrency("25") == 25
    for bad in ("-1", -1, "ten", True):
        with pytest.raises(ValueError):
            m.context_reserved_concurrency(bad)
    assert m.context_flag(True) and m.context_flag("true")
    assert not any(m.context_flag(v) for v in (None, False, "false", "True", "1"))
    assert m.context_role_arn(None, "k") is None and m.context_role_arn(CI_ARN, "k") == CI_ARN
    for bad in ("arn:aws:iam::123:role/x", "arn:aws:iam::123456789012:user/x", "*", 7):
        with pytest.raises(ValueError):
            m.context_role_arn(bad, "ci_role_arn")


# ─── Breaker split, human roles and alarms ────

def _function(template, name):
    return template["Resources"][logical_id(template, "AWS::Lambda::Function", "FunctionName", name)]["Properties"]


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_two_breaker_functions_share_asset_role_runtime_and_dlq(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    auto, human = _function(t, "fsi-circuit-breaker"), _function(t, "fsi-circuit-breaker-human")
    for key in ("Runtime", "Handler", "Code", "Role", "Timeout", "MemorySize", "DeadLetterConfig"):
        assert auto[key] == human[key], key
    assert human["Runtime"] == "python3.13" and human["DeadLetterConfig"]["TargetArn"]
    assert auto["Environment"]["Variables"]["BREAKER_ENTRY"] == "automated"
    assert human["Environment"]["Variables"]["BREAKER_ENTRY"] == "human"
    a_env = {k: v for k, v in auto["Environment"]["Variables"].items() if k != "BREAKER_ENTRY"}
    h_env = {k: v for k, v in human["Environment"]["Variables"].items() if k != "BREAKER_ENTRY"}
    assert a_env == h_env
    for env in (a_env, h_env):
        assert "RELEASE_AUTHORIZED_PRINCIPAL_ARNS" not in env and "TRUSTED_BREAK_GLASS_ARNS" not in env
        assert "COMPLIANCE_TABLE" in env
    trusted = render(a_env["TRUSTED_ALARM_ARNS"]).split(",")
    assert len(trusted) == 4
    assert trusted[-1].endswith(":alarm:fsi-challenger-dispute-rate-sustained")


def test_no_alarm_targets_the_human_function(agents):
    human = {"Fn::GetAtt": [logical_id(agents, "AWS::Lambda::Function", "FunctionName",
                                       "fsi-circuit-breaker-human"), "Arn"]}
    for alarm in resources(agents, "AWS::CloudWatch::Alarm").values():
        for key in ("AlarmActions", "OKActions", "InsufficientDataActions"):
            assert human not in alarm["Properties"].get(key, [])
    for perm in resources(agents, "AWS::Lambda::Permission").values():
        assert perm["Properties"]["FunctionName"] != human


def _alarm(template, name):
    return template["Resources"][logical_id(template, "AWS::CloudWatch::Alarm", "AlarmName", name)]["Properties"]


def test_sustained_alarm_trips_the_automated_breaker(agents):
    props = _alarm(agents, "fsi-challenger-dispute-rate-sustained")
    assert props["Threshold"] == 0.51 and props["EvaluationPeriods"] == 1
    assert props["DatapointsToAlarm"] == 1 and props["TreatMissingData"] == "notBreaching"
    (expr,) = [m for m in props["Metrics"] if m.get("Expression")]
    assert expr["Expression"] == "IF(clusters >= 20, disputes / clusters, 0)"
    for m in props["Metrics"]:
        if "MetricStat" in m:
            assert m["MetricStat"]["Period"] == 3600 and m["MetricStat"]["Stat"] == "Sum"
    auto = logical_id(agents, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    assert props["AlarmActions"] == [{"Fn::GetAtt": [auto, "Arn"]}]


def test_uncorroborated_drift_alarm_is_action_less(agents):
    props = _alarm(agents, "fsi-uncorroborated-drift-alarm")
    assert props["MetricName"] == "UncorroboratedAlarm" and props["Namespace"] == "FSI/GovernanceIntegrity"
    assert notifies_on_call_only(props)


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_breaker_human_role_trust_and_paths(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    for name in BREAKER_HUMAN_ROLES:
        props = role_props(t, name)
        assert props["Path"] == "/fsi-breaker/" and props["MaxSessionDuration"] == 3600
        (statement,) = props["AssumeRolePolicyDocument"]["Statement"]  # approver: never host trust
        assert is_account_root(statement["Principal"]) and statement["Condition"] == MFA_TRUST


def test_break_glass_role_permissions(agents):
    assert role_actions(agents, "fsi-breaker-break-glass") == {
        "iam:DetachRolePolicy", "iam:ListAttachedRolePolicies", "iam:GetRole", "dynamodb:PutItem",
        "dynamodb:GetItem", "dynamodb:UpdateItem", "sts:GetCallerIdentity"}
    (detach,) = statements_with_action(agents, "fsi-breaker-break-glass", "iam:DetachRolePolicy")
    deny_id = logical_id(agents, "AWS::IAM::ManagedPolicy", "ManagedPolicyName", "governance-hold-deny-all")
    assert detach["Condition"] == {"ArnEquals": {"iam:PolicyARN": {"Ref": deny_id}}}
    assert len(as_list(detach["Resource"])) == 3
    (get_role,) = statements_with_action(agents, "fsi-breaker-break-glass", "iam:GetRole")
    assert [render(r) for r in as_list(get_role["Resource"])] == [
        "arn:aws:iam::${AWS::AccountId}:role/fsi-breaker/*"]


def test_breaker_role_additions(agents):
    (get_role,) = statements_with_action(agents, "circuit-breaker-role", "iam:GetRole")
    assert sorted(render(r) for r in as_list(get_role["Resource"])) == sorted([
        "arn:aws:iam::${AWS::AccountId}:role/fsi-breaker/*",
        "arn:aws:iam::${AWS::AccountId}:role/fsi-console/*",
        "arn:aws:iam::${AWS::AccountId}:role/aws-reserved/sso.amazonaws.com/*"])
    get_items = statements_with_action(agents, "circuit-breaker-role", "dynamodb:GetItem")
    (get_item,) = [s for s in get_items if "GovernanceAudit" in render(as_list(s["Resource"])[0])]
    assert get_item["Condition"] == {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": [
        "release-request#*", "completed-*"]}}
    (state,) = [s for s in get_items if "GovernanceState" in render(as_list(s["Resource"])[0])]
    assert state["Condition"] == {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["breaker"]}}
    queries = statements_with_action(agents, "circuit-breaker-role", "dynamodb:Query")
    by_resource = {render(as_list(q["Resource"])[0]).split("/index/")[-1]: q for q in queries}
    assert set(by_resource) == {"by_event_type", "by_day_ts"}
    assert "GovernanceAudit" in render(as_list(by_resource["by_event_type"]["Resource"])[0])
    corroboration = by_resource["by_day_ts"]
    assert "ComplianceDecisions" in render(as_list(corroboration["Resource"])[0])
    attrs = corroboration["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"]
    assert sorted(attrs) == sorted(["compliance_id", "record_day", "timestamp", "drift_counts", "provenance_status"])
    assert corroboration["Condition"]["StringEqualsIfExists"] == {"dynamodb:Select": "SPECIFIC_ATTRIBUTES"}
    (metric,) = statements_with_action(agents, "circuit-breaker-role", "cloudwatch:PutMetricData")
    assert metric["Condition"] == {"StringEquals": {"cloudwatch:namespace": "FSI/GovernanceIntegrity"}}


# ─── governance-state item: table, grants, alarms, timeout ───────────────────

STATE_ROLES = {"circuit-breaker-role": {"dynamodb:GetItem", "dynamodb:UpdateItem"},
               "fsi-breaker-break-glass": {"dynamodb:GetItem", "dynamodb:UpdateItem"},
               "governance-hold-sweep-role": {"dynamodb:GetItem"}}
STATE_ALARMS = {"fsi-newer-hold-detected": "NewerHoldDetected",
                "fsi-hold-release-superseded": "ReleaseSuperseded",
                "fsi-hold-state-write-failed": "HoldStateWriteFailed",
                "fsi-hold-state-read-failed": "HoldStateReadFailed"}


@pytest.fixture(scope="module")
def data_template():
    return synth(DEFAULT_CONTEXT)["data"]


def test_governance_state_table(data_template):
    lid = logical_id(data_template, "AWS::DynamoDB::Table", "TableName", "governance-state")
    table = data_template["Resources"][lid]
    props = table["Properties"]
    assert props["KeySchema"] == [{"AttributeName": "state_id", "KeyType": "HASH"}]
    assert props["BillingMode"] == "PAY_PER_REQUEST"
    assert props["PointInTimeRecoverySpecification"] == {"PointInTimeRecoveryEnabled": True}
    assert props["DeletionProtectionEnabled"] is True
    assert table["DeletionPolicy"] == "Retain" and table["UpdateReplacePolicy"] == "Retain"
    assert "StreamSpecification" not in props and "GlobalSecondaryIndexes" not in props


@pytest.mark.parametrize("which", ["default", "ctx"])
def test_governance_state_grants_are_key_scoped(agents, ctx_agents, which):
    t = agents if which == "default" else ctx_agents
    granted = {}
    for policy in resources(t, "AWS::IAM::Policy").values():
        for s in policy["Properties"]["PolicyDocument"]["Statement"]:
            if not any("GovernanceState" in render(r) for r in as_list(s["Resource"])):
                continue
            assert s["Effect"] == "Allow" and len(as_list(s["Resource"])) == 1, s
            assert "/index/" not in render(as_list(s["Resource"])[0])
            assert s["Condition"] == {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["breaker"]}}
            for role in policy["Properties"]["Roles"]:
                granted.setdefault(role["Ref"], set()).update(as_list(s["Action"]))
    assert granted == {role_id(t, name): actions for name, actions in STATE_ROLES.items()}


def test_governance_state_alarms_notify_on_call_only(agents):
    trusted = render(_function(agents, "fsi-circuit-breaker")["Environment"]["Variables"]["TRUSTED_ALARM_ARNS"])
    for name, metric in STATE_ALARMS.items():
        props = _alarm(agents, name)
        assert props["MetricName"] == metric and props["Namespace"] == "FSI/GovernanceIntegrity"
        assert props["Threshold"] == 0 and props["ComparisonOperator"] == "GreaterThanThreshold"
        assert notifies_on_call_only(props), name
        assert name not in trusted


def test_breaker_functions_timeout_and_state_table_env(agents, agents_stack_module):
    import circuit_breaker.handler as handler
    assert agents_stack_module.BREAKER_TIMEOUT_SECONDS == handler.BREAKER_TIMEOUT_SECONDS == 45
    for name in ("fsi-circuit-breaker", "fsi-circuit-breaker-human", "fsi-governance-hold-sweep"):
        fn = _function(agents, name)
        assert fn["Timeout"] == 45, name
        assert "GovernanceState" in render(fn["Environment"]["Variables"]["GOVERNANCE_STATE_TABLE"]), name
