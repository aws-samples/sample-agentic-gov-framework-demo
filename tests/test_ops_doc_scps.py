"""
The SCP JSON in docs/SECURITY_OPERATIONAL_STEPS.md. Every policy block parses, the step 5 read exceptions cover
every stack role that reads an audit table, and step 6 excepts only the
drift metric publisher (plus the demo console in the demo variant).
"""
import json
import os
import re

import pytest

from _cdk_synth import DEFAULT_CONTEXT, FULL_CONTEXT, as_list, render, resources, synth

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(PROJECT_ROOT, "docs", "SECURITY_OPERATIONAL_STEPS.md")
AUDIT_TABLES = ("detection-results", "compliance-decisions", "executor-audit", "governance-audit",
                "operator-audit")
AUDIT_TABLE_LOGICAL = ("DetectionResults", "ComplianceDecisions", "ExecutorAudit", "GovernanceAudit",
                       "OperatorAudit")
TABLE_READ_ACTIONS = {"dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan"}
STREAM_READ_ACTIONS = {"dynamodb:GetRecords", "dynamodb:GetShardIterator"}
READ_ACTIONS = TABLE_READ_ACTIONS | STREAM_READ_ACTIONS
DEPLOY_ROLE = "arn:aws:iam::<acct>:role/<ci deploy role>"


def _doc():
    with open(DOC, encoding="utf-8") as f:
        return f.read()


def _steps():
    """{step number: section text}."""
    text = _doc()
    parts = re.split(r"^### Step (\d+)\.", text, flags=re.M)
    return {int(parts[i]): parts[i + 1].split("\n## ")[0] for i in range(1, len(parts), 2)}


def _policies(section):
    return [json.loads(block) for block in re.findall(r"```json\n(.*?)```", section, flags=re.S)
            if '"2012-10-17"' in block]


def _statements(step):
    return {s["Sid"]: s for policy in _policies(_steps()[step]) for s in policy["Statement"]}


def test_every_policy_block_parses():
    blocks = [b for b in re.findall(r"```json\n(.*?)```", _doc(), flags=re.S) if '"2012-10-17"' in b]
    assert len(blocks) >= 7
    for block in blocks:
        policy = json.loads(block)
        assert policy["Version"] == "2012-10-17"
        for s in policy["Statement"]:
            assert s["Effect"] == "Deny" and s["Sid"]


# ─── Step 6: drift signal ────────────────────────────────────────────────────

def _step6_variants():
    return _policies(_steps()[6])


def test_step6_publish_exceptions():
    standard, demo = _step6_variants()
    by_sid = [{s["Sid"]: s for s in p["Statement"]} for p in (standard, demo)]
    std = by_sid[0]["DenyDriftMetricPublishExceptPublisher"]
    dem = by_sid[1]["DenyDriftMetricPublishExceptPublisherAndDemoConsole"]
    for s in (std, dem):
        assert s["Action"] == "cloudwatch:PutMetricData"
        assert s["Condition"]["StringEquals"] == {"cloudwatch:namespace": "FSI/AgenticCompliance"}
    assert std["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role"]
    assert dem["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
        "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role",
        "arn:aws:iam::<acct>:role/fsi-console/fsi-console-operator"]
    assert "compliance-agent-role" not in json.dumps([standard, demo])


@pytest.mark.parametrize("variant", [0, 1])
def test_step6_stream_statements(variant):
    statements = {s["Sid"]: s for s in _step6_variants()[variant]["Statement"]}
    esm = statements["DenyDriftPublisherStreamChangesExceptDeployRole"]
    assert sorted(esm["Action"]) == ["lambda:CreateEventSourceMapping", "lambda:DeleteEventSourceMapping",
                                     "lambda:UpdateEventSourceMapping"]
    assert esm["Condition"]["ArnLike"] == {
        "lambda:FunctionArn": "arn:aws:lambda:*:<acct>:function:fsi-drift-metric-publisher*"}
    table = statements["DenyComplianceStreamChangesExceptDeployRole"]
    assert table["Action"] == ["dynamodb:UpdateTable"]
    assert table["Resource"] == "arn:aws:dynamodb:*:<acct>:table/compliance-decisions"
    for s in (esm, table):
        assert s["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == [
            "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"]
    assert "DenyAlarmTamperingExceptDeployRole" in statements


# ─── Step 5: audit-table readers ─────────────────────────────────────────────

def _role_arn_with_path(props):
    return f"arn:aws:iam::<acct>:role{props.get('Path', '/')}{props['RoleName']}"


def _audit_readers(templates, actions=READ_ACTIONS):
    readers = set()
    for template in templates:
        readers |= _audit_readers_in(template, actions)
    return readers


def _audit_readers_in(template, actions):
    roles = {lid: r["Properties"] for lid, r in resources(template, "AWS::IAM::Role").items()
             if r["Properties"].get("RoleName")}
    readers = set()
    for policy in resources(template, "AWS::IAM::Policy").values():
        for s in policy["Properties"]["PolicyDocument"]["Statement"]:
            if s["Effect"] != "Allow" or not actions & set(as_list(s["Action"])):
                continue
            rendered = " ".join(render(r) for r in as_list(s["Resource"]))
            if not any(t in rendered for t in AUDIT_TABLE_LOGICAL + AUDIT_TABLES):
                continue
            for ref in policy["Properties"]["Roles"]:
                lid = ref["Ref"] if isinstance(ref, dict) else ref
                if lid in roles:
                    readers.add(_role_arn_with_path(roles[lid]))
    return readers


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_step5_excepts_every_audit_reader(context):
    """Over both stacks: the archiver role lives in the data stack."""
    statements = _statements(5)
    table = statements["DenyAuditTableReadsExceptGrantedRoles"]
    stream = statements["DenyAuditStreamReadsExceptConsumers"]
    templates = synth(context).values()
    table_readers = _audit_readers(templates, TABLE_READ_ACTIONS)
    stream_readers = _audit_readers(templates, STREAM_READ_ACTIONS)
    assert "arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role" in table_readers
    assert "arn:aws:iam::<acct>:role/fsi-audit-archiver-role" in table_readers
    assert table_readers <= set(table["Condition"]["ArnNotLike"]["aws:PrincipalArn"])
    assert stream_readers == {"arn:aws:iam::<acct>:role/fsi-drift-metric-publisher-role",
                              "arn:aws:iam::<acct>:role/fsi-audit-archiver-role"}
    assert set(stream["Condition"]["ArnNotLike"]["aws:PrincipalArn"]) == stream_readers | {DEPLOY_ROLE}


def test_step5_deploy_role_gets_stream_reads_only():
    statements = _statements(5)
    table = statements["DenyAuditTableReadsExceptGrantedRoles"]
    stream = statements["DenyAuditStreamReadsExceptConsumers"]
    assert DEPLOY_ROLE not in table["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
    assert not STREAM_READ_ACTIONS & set(table["Action"])
    assert set(stream["Action"]) == STREAM_READ_ACTIONS
    assert sorted(stream["Resource"]) == sorted(
        f"arn:aws:dynamodb:*:<acct>:table/{t}/stream/*" for t in AUDIT_TABLES)


# ─── Step 3: deploy-path containment ────────────────────────────

CONTAINMENT_FUNCTIONS = ("fsi-circuit-breaker", "fsi-circuit-breaker-human", "fsi-pan-filter",
                         "fsi-governance-hold-sweep", "fsi-drift-metric-publisher", "fsi-audit-archiver")
CONTAINMENT_ACTIONS = {
    # the five containment actions
    "lambda:UpdateFunctionConfiguration", "lambda:UpdateFunctionCode", "lambda:UpdateAlias",
    "lambda:PublishVersion", "lambda:PutFunctionConcurrency",
    # plus the ones that disable the kill switch another way
    "lambda:DeleteFunctionConcurrency", "lambda:AddPermission", "lambda:RemovePermission",
    "lambda:PutFunctionEventInvokeConfig", "lambda:UpdateFunctionEventInvokeConfig", "lambda:DeleteFunction",
}
DEPLOY_PRINCIPALS = ["arn:aws:iam::<acct>:role/<ci deploy role>",
                     "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"]


def test_step3_containment_function_statement():
    s = _statements(3)["DenyContainmentFunctionChangesExceptDeployRole"]
    assert set(s["Action"]) == CONTAINMENT_ACTIONS and len(s["Action"]) == len(CONTAINMENT_ACTIONS)
    expected = set()
    for name in CONTAINMENT_FUNCTIONS:
        expected |= {f"arn:aws:lambda:*:<acct>:function:{name}", f"arn:aws:lambda:*:<acct>:function:{name}:*"}
    assert set(s["Resource"]) == expected
    for name in ("fsi-circuit-breaker", "fsi-circuit-breaker-human", "fsi-pan-filter"):
        assert f"arn:aws:lambda:*:<acct>:function:{name}" in s["Resource"]      # unqualified
        assert f"arn:aws:lambda:*:<acct>:function:{name}:*" in s["Resource"]    # versions / aliases
    assert s["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": DEPLOY_PRINCIPALS}}


def test_step3_schedule_and_floor_statements():
    statements = _statements(3)
    sched = statements["DenyContainmentScheduleChangesExceptDeployRole"]
    assert set(sched["Action"]) == {"events:DisableRule", "events:DeleteRule", "events:PutRule",
                                    "events:PutTargets", "events:RemoveTargets"}
    assert set(sched["Resource"]) == {"arn:aws:events:*:<acct>:rule/fsi-governance-hold-sweep",
                                      "arn:aws:events:*:<acct>:rule/fsi-breaker-alarm-recheck"}
    assert sched["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": DEPLOY_PRINCIPALS}}
    floor = statements["DenyAcceptedRegistryFloorChangesExceptDeployRole"]
    assert set(floor["Action"]) == {"ssm:PutParameter", "ssm:DeleteParameter", "ssm:DeleteParameters",
                                    "ssm:LabelParameterVersion"}
    assert floor["Resource"] == "arn:aws:ssm:*:<acct>:parameter/fsi/governance/*"
    assert floor["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::<acct>:role/<ci deploy role>"]}}
    # The pre-existing step 3 statements are still there.
    assert {"DenyRuntimeChangesExceptDeployRole", "DenyCodeBucketWritesExceptDeployRole"} <= set(statements)


def test_scp_function_and_rule_names_exist_in_the_stack():
    """Every function / rule / role the step 3, 5 and 6 statements name is a
    physical name in the default synth (the SCPs match on names)."""
    templates = synth(DEFAULT_CONTEXT)
    t = templates["agents"]
    functions = {r["Properties"].get("FunctionName") for tpl in templates.values()
                 for r in resources(tpl, "AWS::Lambda::Function").values()}
    rules = {r["Properties"].get("Name") for r in resources(t, "AWS::Events::Rule").values()}
    roles = {r["Properties"].get("RoleName") for r in resources(t, "AWS::IAM::Role").values()}
    text = json.dumps([_policies(_steps()[n]) for n in (3, 5, 6, 10)])
    named_functions = set(re.findall(r":function:([a-z0-9-]+?)(?:\*|:\*|\")", text))
    named_rules = set(re.findall(r":rule/([a-z0-9-]+)", text))
    assert named_functions >= {"fsi-circuit-breaker", "fsi-circuit-breaker-human", "fsi-pan-filter",
                               "fsi-governance-hold-sweep", "fsi-drift-metric-publisher"}
    assert named_functions <= functions, named_functions - functions
    assert named_rules == {"fsi-governance-hold-sweep", "fsi-breaker-alarm-recheck"} and named_rules <= rules
    for role in ("fsi-drift-metric-publisher-role", "governance-hold-sweep-role"):
        assert role in roles and f"role/{role}" in text


# ─── Step 10: immutable audit archive ────────────────────────────────────────
CFN_EXEC = ["arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"]


def test_step10_statements():
    statements = _statements(10)
    invoke = statements["DenyAuditArchiverDirectInvoke"]
    assert set(invoke["Action"]) == {"lambda:InvokeFunction", "lambda:InvokeFunctionUrl", "lambda:InvokeAsync"}
    assert set(invoke["Resource"]) == {"arn:aws:lambda:*:<acct>:function:fsi-audit-archiver",
                                       "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver:*"}
    # Exactly one replay role: the deploy role; break-glass is not excepted.
    assert invoke["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": [DEPLOY_ROLE]}}
    esm = statements["DenyAuditArchiverStreamChangesExceptDeployRole"]
    assert sorted(esm["Action"]) == ["lambda:CreateEventSourceMapping", "lambda:DeleteEventSourceMapping",
                                     "lambda:UpdateEventSourceMapping"]
    assert esm["Condition"]["ArnLike"] == {
        "lambda:FunctionArn": "arn:aws:lambda:*:<acct>:function:fsi-audit-archiver*"}
    tables = statements["DenyAuditTableStreamChangesExceptDeployRole"]
    assert tables["Action"] == ["dynamodb:UpdateTable"]
    assert sorted(tables["Resource"]) == sorted(
        f"arn:aws:dynamodb:*:<acct>:table/{t}" for t in AUDIT_TABLES if t != "compliance-decisions")
    policy = statements["DenyAuditArchiveBucketPolicyChangesExceptDeployRole"]
    assert sorted(policy["Action"]) == ["s3:DeleteBucketPolicy", "s3:PutBucketPolicy"]
    assert policy["Resource"] == "arn:aws:s3:::<archive-bucket>"
    for s in (esm, tables, policy):
        assert s["Condition"]["ArnNotLike"]["aws:PrincipalArn"] == CFN_EXEC
    assert "break-glass" not in json.dumps(_policies(_steps()[10]))


def test_step10_text():
    text = _steps()[10]
    flat = " ".join(text.split())
    assert ("Demo retention only. For production set retention per the applicable regulation (e.g. SEC "
            "17a-4 / FINRA 4511: 6 years, BSA/FinCEN SAR records: 5 years, SOX audit records: 7 years) "
            "— confirm with your compliance team.") in flat
    for needle in ("audit_archive_retention_days", "get-object-retention", "get-object-attributes",
                   "content-sha256", "item_sha256", "DDBStreamBatchInfo", "<ci deploy role>",
                   "break-glass roles are not excepted", "make destroy"):
        assert needle in flat, needle


def test_step3_governance_state_statement():
    s = _statements(3)["DenyGovernanceStateWritesExceptBreaker"]
    assert set(s["Action"]) == {
        "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem",
        "dynamodb:PartiQLInsert", "dynamodb:PartiQLUpdate", "dynamodb:PartiQLDelete",
        "dynamodb:DeleteTable", "dynamodb:RestoreTableToPointInTime"}
    assert len(s["Action"]) == 9
    assert s["Resource"] == "arn:aws:dynamodb:*:<acct>:table/governance-state"
    assert s["Condition"] == {"ArnNotLike": {"aws:PrincipalArn": [
        "arn:aws:iam::<acct>:role/circuit-breaker-role",
        "arn:aws:iam::<acct>:role/fsi-breaker/fsi-breaker-break-glass",
        DEPLOY_ROLE,
        "arn:aws:iam::<acct>:role/cdk-hnb659fds-cfn-exec-role-<acct>-<region>"]}}
