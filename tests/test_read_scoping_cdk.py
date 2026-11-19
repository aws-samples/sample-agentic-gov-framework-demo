"""
Test: read scoping in the synthesized CDK.

- SAR filings: SSE-KMS with a dedicated CMK whose policy gives the root key
  administration only; per-role use via aws:PrincipalArn + kms:ViaService;
  a bucket-policy Deny on filings reads for everyone but fsi-compliance-reader;
  Block Public Access stays all-true and TLS-only stays.
- fsi-compliance-reader: MFA trust, GetItem/BatchGetItem on the five audit
  tables, Query on their keyed indexes only, no Scan and no write.
- fsi-console-operator: DynamoDB limited to PutItem on operator-audit and
  Query on executor-audit/index/by_day_ts.
- GSIs and the operator-audit table, one new GSI per existing table.
"""
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

from _cdk_synth import (
    DEFAULT_CONTEXT, FULL_CONTEXT, as_list, is_account_root, logical_id, render, resources,
    role_props, role_statements, synth,
)

AUDIT_TABLES = ("detection-results", "compliance-decisions", "executor-audit", "governance-audit",
                "operator-audit")
WRITE_PREFIXES = ("dynamodb:Put", "dynamodb:Update", "dynamodb:Delete", "dynamodb:BatchWrite",
                  "dynamodb:TransactWrite", "s3:Put", "s3:Delete")
READER_ARN = "arn:aws:iam::${AWS::AccountId}:role/fsi-compliance-reader"
EXECUTOR_ARN = "arn:aws:iam::${AWS::AccountId}:role/executor-agent-role"


@pytest.fixture(scope="module")
def templates():
    return synth(DEFAULT_CONTEXT)


@pytest.fixture(scope="module")
def ctx_templates():
    return synth(FULL_CONTEXT)


@pytest.fixture(scope="module")
def data(templates):
    return templates["data"]


@pytest.fixture(scope="module")
def agents(templates):
    return templates["agents"]


def _table(data, name):
    return data["Resources"][logical_id(data, "AWS::DynamoDB::Table", "TableName", name)]


def _logical_id_in(rendered: str, data, table_name) -> bool:
    return logical_id(data, "AWS::DynamoDB::Table", "TableName", table_name) in rendered


# ─── SAR filings key and bucket ──────────────────────────────────────────────

def _sar_key(data):
    (alias,) = [a for a in resources(data, "AWS::KMS::Alias").values()
                if a["Properties"]["AliasName"] == "alias/fsi-sar-filings"]
    target = alias["Properties"]["TargetKeyId"]
    key_id = target["Fn::GetAtt"][0] if "Fn::GetAtt" in target else target["Ref"]
    return key_id, data["Resources"][key_id]


def test_sar_key_rotates_is_retained_and_root_cannot_use_it(data):
    _, key = _sar_key(data)
    assert key["Properties"]["EnableKeyRotation"] is True
    assert key["DeletionPolicy"] == "Retain"
    for s in key["Properties"]["KeyPolicy"]["Statement"]:
        if is_account_root(s["Principal"]) and "Condition" not in s:
            actions = as_list(s["Action"])
            assert "kms:*" not in actions
            for forbidden in ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt"):
                assert not any(a == forbidden or a.startswith(forbidden) for a in actions), s


def test_no_key_lets_the_root_create_grants(templates):
    # kms:CreateGrant (also inside kms:Create*) would let any account principal
    # with an IAM CreateGrant allowance grant itself Sign or Decrypt without a
    # key-policy change; the root keeps administration only.
    keys = [k for t in templates.values() for k in resources(t, "AWS::KMS::Key").values()]
    assert len(keys) >= 3  # SAR CMK + registry and gate signing keys
    for key in keys:
        for s in key["Properties"]["KeyPolicy"]["Statement"]:
            if s["Effect"] == "Allow" and is_account_root(s["Principal"]):
                actions = as_list(s["Action"])
                assert not {"kms:*", "kms:Create*", "kms:CreateGrant"} & set(actions), s


def test_sar_key_use_delegated_to_one_role_each_via_s3(data):
    _, key = _sar_key(data)
    uses = {}
    for s in key["Properties"]["KeyPolicy"]["Statement"]:
        if "Condition" in s:
            assert is_account_root(s["Principal"])
            arns = [render(a) for a in as_list(s["Condition"]["ArnEquals"]["aws:PrincipalArn"])]
            via = render(s["Condition"]["StringEquals"]["kms:ViaService"])
            assert via == "s3.${AWS::Region}.amazonaws.com"
            uses[tuple(arns)] = sorted(as_list(s["Action"]))
    assert uses == {
        (EXECUTOR_ARN,): ["kms:Encrypt", "kms:GenerateDataKey"],
        (READER_ARN,): ["kms:Decrypt"],
    }


def _sar_bucket(data):
    key_id, _ = _sar_key(data)
    (bucket_id,) = [
        lid for lid, r in resources(data, "AWS::S3::Bucket").items()
        if any(rule["ServerSideEncryptionByDefault"].get("KMSMasterKeyID") == {"Fn::GetAtt": [key_id, "Arn"]}
               for rule in r["Properties"].get("BucketEncryption", {}).get("ServerSideEncryptionConfiguration", []))]
    return bucket_id, data["Resources"][bucket_id]


def test_sar_bucket_uses_the_cmk_with_bucket_key(data):
    key_id, _ = _sar_key(data)
    _, bucket = _sar_bucket(data)
    (rule,) = bucket["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"]
    assert rule["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    assert rule["ServerSideEncryptionByDefault"]["KMSMasterKeyID"] == {"Fn::GetAtt": [key_id, "Arn"]}
    assert rule["BucketKeyEnabled"] is True
    assert bucket["Properties"]["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }
    assert bucket["DeletionPolicy"] == "Retain"


def test_sar_bucket_denies_filing_reads_except_reader(data):
    bucket_id, _ = _sar_bucket(data)
    (policy,) = [r for r in resources(data, "AWS::S3::BucketPolicy").values()
                 if r["Properties"]["Bucket"] == {"Ref": bucket_id}]
    statements = policy["Properties"]["PolicyDocument"]["Statement"]
    deny = [s for s in statements if s.get("Sid") == "DenyFilingReadsExceptComplianceReader"]
    assert len(deny) == 1
    s = deny[0]
    assert s["Effect"] == "Deny" and s["Principal"] == {"AWS": "*"}
    assert sorted(as_list(s["Action"])) == ["s3:GetObject", "s3:GetObjectVersion"]
    assert [render(r) for r in as_list(s["Resource"])] == ["${" + bucket_id + ".Arn}/filings/*"]
    assert [render(a) for a in as_list(s["Condition"]["ArnNotEquals"]["aws:PrincipalArn"])] == [READER_ARN]
    # TLS-only stays, and no statement grants anything to everyone.
    assert any(st["Effect"] == "Deny" and st.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}
               for st in statements)
    assert not [st for st in statements if st["Effect"] == "Allow" and st.get("Principal") in ("*", {"AWS": "*"})]


def test_sar_key_output(data):
    assert "SarFilingsKeyArn" in data["Outputs"]


# ─── Reader role ─────────────────────────────────────────────────────────────

def test_reader_role_shape(agents, data):
    props = role_props(agents, "fsi-compliance-reader")
    assert props.get("Path", "/") == "/"
    assert props["MaxSessionDuration"] == 3600
    assert not props.get("ManagedPolicyArns")
    (trust,) = props["AssumeRolePolicyDocument"]["Statement"]
    assert is_account_root(trust["Principal"])
    assert trust["Condition"] == {"Bool": {"aws:MultiFactorAuthPresent": "true"},
                                  "StringEquals": {"sts:RoleSessionName": "${aws:username}"}}

    statements = role_statements(agents, "fsi-compliance-reader")
    actions = {a for s in statements for a in as_list(s["Action"])}
    assert actions == {"dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "s3:GetObject",
                       "kms:Decrypt",
                       # immutable audit archive (examiner path)
                       "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectAttributes",
                       "s3:ListBucket", "s3:ListBucketVersions"}
    assert "dynamodb:Scan" not in actions
    assert not any(a.startswith(WRITE_PREFIXES) for a in actions)

    (get_stmt,) = [s for s in statements if "dynamodb:BatchGetItem" in as_list(s["Action"])]
    rendered = [render(r) for r in as_list(get_stmt["Resource"])]
    assert len(rendered) == len(AUDIT_TABLES)
    for name in AUDIT_TABLES:
        assert any(_logical_id_in(r, data, name) and "/index/" not in r for r in rendered), name

    (query_stmt,) = [s for s in statements if "dynamodb:Query" in as_list(s["Action"])]
    query_resources = [render(r) for r in as_list(query_stmt["Resource"])]
    assert all("/index/by_day_ts" in r or "/index/by_event_type" in r for r in query_resources)
    assert len(query_resources) == len(AUDIT_TABLES)

    s3_get = [s for s in statements if "s3:GetObject" in as_list(s["Action"])]
    (sar_stmt,) = [s for s in s3_get if as_list(s["Action"]) == ["s3:GetObject"]]
    assert [render(r).endswith("/filings/*") for r in as_list(sar_stmt["Resource"])] == [True]
    sar_bucket_id, _ = _sar_bucket(data)
    assert sar_bucket_id in render(as_list(sar_stmt["Resource"])[0]) or "SarFilings" in render(
        as_list(sar_stmt["Resource"])[0])
    (archive_stmt,) = [s for s in s3_get if s is not sar_stmt]
    (archive_resource,) = [render(r) for r in as_list(archive_stmt["Resource"])]
    assert "AuditArchive" in archive_resource and archive_resource.endswith("/*")
    assert "filings" not in archive_resource
    decrypt = [s for s in statements if as_list(s["Action"]) == ["kms:Decrypt"]]
    assert len(decrypt) == 2
    assert {("SarFilingsKey" in render(s["Resource"]), "AuditArchiveKey" in render(s["Resource"]))
            for s in decrypt} == {(True, False), (False, True)}


def test_reader_host_trust_only_with_context(ctx_templates):
    trust = role_props(ctx_templates["agents"], "fsi-compliance-reader")["AssumeRolePolicyDocument"]["Statement"]
    (host,) = [s for s in trust if s["Principal"] == {"AWS": "arn:aws:iam::123456789012:role/console-host"}]
    assert host["Action"] == ["sts:AssumeRole", "sts:SetSourceIdentity"]
    assert host["Condition"] == {"StringLike": {"sts:RoleSessionName": "cognito-*",
                                                "sts:SourceIdentity": "cognito-*"}}


# ─── Console operator DynamoDB scope ─────────────────────────────────────────

@pytest.mark.parametrize("role_name,which", [("fsi-console-operator", "default"),
                                             ("fsi-console-operator", "ctx"),
                                             ("fsi-console-operator-hosted", "ctx")])
def test_console_operator_dynamodb_actions(templates, ctx_templates, role_name, which):
    t = templates if which == "default" else ctx_templates
    agents_t, data_t = t["agents"], t["data"]
    ddb = [(a, render(r)) for s in role_statements(agents_t, role_name)
           for a in as_list(s["Action"]) if a.startswith("dynamodb:") for r in as_list(s["Resource"])]
    assert len(ddb) == 2
    by_action = dict(ddb)
    assert set(by_action) == {"dynamodb:PutItem", "dynamodb:Query"}
    assert _logical_id_in(by_action["dynamodb:PutItem"], data_t, "operator-audit")
    assert "/index/" not in by_action["dynamodb:PutItem"]
    assert _logical_id_in(by_action["dynamodb:Query"], data_t, "executor-audit")
    assert by_action["dynamodb:Query"].endswith("/index/by_day_ts")


# ─── GSIs and the operator-audit table ───────────────────────────────────────

def _gsis(data, name):
    return {g["IndexName"]: g for g in _table(data, name)["Properties"].get("GlobalSecondaryIndexes", [])}


def _keys(gsi):
    return [(k["AttributeName"], k["KeyType"]) for k in gsi["KeySchema"]]


def test_each_existing_table_gains_exactly_one_gsi(data):
    # CloudFormation/DynamoDB allow only one GSI creation per table update.
    for name in ("detection-results", "compliance-decisions", "executor-audit", "governance-audit"):
        assert len(_gsis(data, name)) == 1, name


def test_by_day_ts_indexes(data):
    expected = {
        "detection-results": {"ProjectionType": "KEYS_ONLY"},
        "compliance-decisions": {"ProjectionType": "INCLUDE",
                                 "NonKeyAttributes": ["drift_counts", "provenance_status"]},
        "executor-audit": {"ProjectionType": "INCLUDE",
                           "NonKeyAttributes": ["action_taken", "event_hash", "violation_type"]},
        "operator-audit": {"ProjectionType": "ALL"},
    }
    for name, projection in expected.items():
        gsi = _gsis(data, name)["by_day_ts"]
        assert _keys(gsi) == [("record_day", "HASH"), ("timestamp", "RANGE")], name
        assert gsi["Projection"] == projection, name


def test_governance_by_event_type_index(data):
    gsi = _gsis(data, "governance-audit")["by_event_type"]
    assert _keys(gsi) == [("event_type", "HASH"), ("timestamp", "RANGE")]
    assert gsi["Projection"] == {"ProjectionType": "ALL"}


def _statements_on_table(template, data, role_name, table_name):
    lid = logical_id(data, "AWS::DynamoDB::Table", "TableName", table_name)
    return [s for s in role_statements(template, role_name)
            if s["Effect"] == "Allow" and lid in render(s.get("Resource"))]


def test_executor_compliance_table_is_get_item_plus_conditioned_update(agents, data):
    """grant_read_data (Scan/Query/BatchGet) replaced by GetItem;
    the existing attribute-conditioned UpdateItem is unchanged."""
    statements = _statements_on_table(agents, data, "executor-agent-role", "compliance-decisions")
    by_actions = {tuple(sorted(as_list(s["Action"]))): s for s in statements}
    assert set(by_actions) == {("dynamodb:GetItem",), ("dynamodb:UpdateItem",)}
    assert "Condition" not in by_actions[("dynamodb:GetItem",)]
    assert "dynamodb:Attributes" in json.dumps(by_actions[("dynamodb:UpdateItem",)]["Condition"])


@pytest.mark.parametrize("role", ["detection-agent-role", "compliance-agent-role", "executor-agent-role"])
def test_no_agent_role_can_scan_query_or_batch_read(agents, role):
    actions = {a for s in role_statements(agents, role) if s["Effect"] == "Allow"
               for a in as_list(s["Action"])}
    assert not actions & {"dynamodb:Scan", "dynamodb:Query", "dynamodb:BatchGetItem", "dynamodb:*"}


def test_operator_audit_table_durability(data):
    table = _table(data, "operator-audit")
    props = table["Properties"]
    assert props["KeySchema"] == [{"AttributeName": "event_id", "KeyType": "HASH"}]
    assert props["DeletionProtectionEnabled"] is True
    assert props["PointInTimeRecoverySpecification"]["PointInTimeRecoveryEnabled"] is True
    assert props["BillingMode"] == "PAY_PER_REQUEST"
    assert table["DeletionPolicy"] == "Retain" and table["UpdateReplacePolicy"] == "Retain"


# ─── Executor SAR put: SSE-KMS with the SAR CMK ─────────────
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555"


@pytest.fixture
def ex():
    import lambdas.executor_agent.handler as executor_handler
    return executor_handler


def test_sar_put_uses_sse_kms_with_configured_key(ex, monkeypatch):
    s3 = MagicMock()
    monkeypatch.setattr(ex.boto3, "client", lambda *a, **k: s3)
    monkeypatch.setattr(ex, "_account_id", lambda: "123456789012")
    monkeypatch.setattr(ex, "SAR_BUCKET", "sar-bucket")
    monkeypatch.setattr(ex, "SAR_KMS_KEY_ARN", KEY_ARN)
    result = ex.execute_file_sar({"cluster_id": "c1", "sar_narrative": "n"}, "live")
    assert result["status"] == "filed"
    kwargs = s3.put_object.call_args.kwargs
    assert kwargs["ServerSideEncryption"] == "aws:kms"
    assert kwargs["SSEKMSKeyId"] == KEY_ARN
    assert kwargs["ExpectedBucketOwner"] == "123456789012"


def test_unset_sar_kms_key_fails_fast_in_deployed_runtime(ex, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no AWS call before the destination check")

    monkeypatch.setattr(ex.boto3, "client", boom)
    monkeypatch.setattr(ex.boto3, "resource", boom)
    monkeypatch.setattr(ex, "SAR_BUCKET", "sar-bucket")
    monkeypatch.setattr(ex, "ANALYST_QUEUE_URL", "https://sqs.example/q")
    monkeypatch.setattr(ex, "SAR_KMS_KEY_ARN", "")
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda p: True if p == "/var/task" else real_isdir(p))
    with pytest.raises(RuntimeError) as excinfo:
        ex.handler({"mode": "live", "compliance_output": {
            "compliance_id": "comp-1", "detection_id": "det-1", "clusters_assessed": []}})
    assert "SAR_KMS_KEY_ARN" in str(excinfo.value)
    assert "SAR_BUCKET" not in str(excinfo.value)


def test_deploy_script_sets_sar_kms_key_from_data_stack_output(monkeypatch, tmp_path):
    import importlib.util
    path = os.path.join(_PROJECT_ROOT, "cdk", "deploy_agentcore_runtimes.py")
    spec = importlib.util.spec_from_file_location("_deploy_sar_kms", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    deployed = {}
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "get_account_id", lambda: "123456789012")
    monkeypatch.setattr(deploy, "get_code_bucket_name", lambda account_id, explicit_bucket=None: "b")
    monkeypatch.setattr(deploy, "get_agents_stack_outputs", lambda: {
        "GuardrailId": "gr", "GuardrailVersion": "1",
        "TxnRefHmacSecretArn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:x"})
    monkeypatch.setattr(deploy, "get_data_stack_outputs", lambda: {
        "SarBucketName": "s", "AnalystQueueUrl": "https://sqs.example/q", "SarFilingsKeyArn": KEY_ARN})
    monkeypatch.setattr(deploy, "package_agent", lambda cfg, build_dir: tmp_path / "x.zip")
    # Prebuilt bundles + gate-artifact verification are covered
    # by tests/test_deploy_requires_gate_artifact.py; stubbed here.
    monkeypatch.setattr(deploy, "verify_gate_artifact", lambda build_dir: None)
    # Runtime-ARN pinning is covered by tests/test_runtime_pins.py.
    monkeypatch.setattr(deploy, "pin_runtime_arns", lambda results, account_id: True)
    monkeypatch.setattr(deploy, "_load_prebuilt_bundle", lambda cfg, build_dir: tmp_path / f"{cfg['name']}.zip")
    monkeypatch.setattr(deploy, "deploy_agent", lambda cfg, *a: deployed.update(
        {cfg["name"]: dict(cfg["env_vars"])}) or "arn")
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py"])
    deploy.main()
    assert deployed["ExecutorAgent"]["SAR_KMS_KEY_ARN"] == KEY_ARN
    assert "SAR_KMS_KEY_ARN" not in deployed["ComplianceAgent"]
    assert "SAR_KMS_KEY_ARN" not in deployed["DetectionAgent"]


def test_deploy_requires_sar_kms_key_output(monkeypatch):
    import importlib.util
    path = os.path.join(_PROJECT_ROOT, "cdk", "deploy_agentcore_runtimes.py")
    spec = importlib.util.spec_from_file_location("_deploy_sar_kms_outputs", path)
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    cfn = MagicMock()
    cfn.describe_stacks.return_value = {"Stacks": [{"Outputs": [
        {"OutputKey": "SarBucketName", "OutputValue": "b"},
        {"OutputKey": "AnalystQueueUrl", "OutputValue": "q"}]}]}
    monkeypatch.setattr(deploy.boto3, "client", lambda *a, **k: cfn)
    with pytest.raises(RuntimeError, match="SarFilingsKeyArn"):
        deploy.get_data_stack_outputs()
