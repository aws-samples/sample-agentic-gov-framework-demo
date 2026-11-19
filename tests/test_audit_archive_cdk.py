"""
Immutable audit archive (WORM) — synthesized CDK templates. Local synth only;
nothing is deployed.

Object Lock COMPLIANCE with the configured retention (cdk.json, default 90,
synth refuses < 90), dedicated rotating CMK, Block Public Access, TLS-only,
deny-only bucket policy, only the archiver may PutObject, RETAIN everywhere,
five tables streamed to the archiver, the drift publisher's ESM untouched,
DLQ and nine alarms.
"""
import json
import os
import subprocess
import sys

import pytest

from _cdk_synth import (  # noqa: E402
    CDK_ROOT, DEFAULT_CONTEXT, FULL_CONTEXT, as_list, is_account_root, logical_id, render, resources,
    role_statements, synth,
)

sys.path.insert(0, CDK_ROOT)
from audit_archive import (  # noqa: E402
    ALARM_NAMES, BUCKET_PROTECTION_ACTIONS, EMF_ALARMS, OBJECT_LOCKDOWN_ACTIONS, context_retention_days,
)

PROJECT_ROOT = os.path.dirname(CDK_ROOT)
TABLES = {
    "DetectionResults": ("detection-results", "detection_id"),
    "ComplianceDecisions": ("compliance-decisions", "compliance_id"),
    "ExecutorAudit": ("executor-audit", "action_id"),
    "GovernanceAudit": ("governance-audit", "event_id"),
    "OperatorAudit": ("operator-audit", "event_id"),
}
ARCHIVER = "fsi-audit-archiver"
ARCHIVER_ROLE = "fsi-audit-archiver-role"


@pytest.fixture(scope="module")
def default():
    return synth(DEFAULT_CONTEXT)


@pytest.fixture(scope="module")
def data(default):
    return default["data"]


def _archive_bucket(data):
    (lid,) = [lid for lid, r in resources(data, "AWS::S3::Bucket").items()
              if r["Properties"].get("ObjectLockEnabled") is True]
    return lid, data["Resources"][lid]


def _archive_key(data):
    (alias,) = [a for a in resources(data, "AWS::KMS::Alias").values()
                if a["Properties"]["AliasName"] == "alias/fsi-audit-archive"]
    key_id = alias["Properties"]["TargetKeyId"]["Fn::GetAtt"][0]
    return key_id, data["Resources"][key_id]


def _bucket_policy(data):
    bucket_id, _ = _archive_bucket(data)
    (lid,) = [lid for lid, r in resources(data, "AWS::S3::BucketPolicy").items()
              if r["Properties"]["Bucket"] == {"Ref": bucket_id}]
    return data["Resources"][lid]


def _statements_by_sid(data):
    return {s.get("Sid", "_tls"): s for s in _bucket_policy(data)["Properties"]["PolicyDocument"]["Statement"]}


# ─── Bucket ──────────────────────────────────────────────────────────────────
def test_object_lock_compliance_default_90_days(data):
    _, bucket = _archive_bucket(data)
    props = bucket["Properties"]
    assert props["ObjectLockEnabled"] is True
    assert props["ObjectLockConfiguration"] == {
        "ObjectLockEnabled": "Enabled",
        "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 90}},
    }


def test_retention_default_lives_in_cdk_json():
    with open(os.path.join(CDK_ROOT, "cdk.json"), encoding="utf-8") as f:
        assert json.load(f)["context"]["audit_archive_retention_days"] == 90
    assert context_retention_days(None) == 90


def test_retention_context_override():
    _, bucket = _archive_bucket(synth({"audit_archive_retention_days": "2190"})["data"])
    assert bucket["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"] == {
        "Mode": "COMPLIANCE", "Days": 2190}


@pytest.mark.parametrize("value", ["89", "0", "x", True, "36501", -5, 90.5, "9 0"])
def test_retention_out_of_range_fails_synth(value):
    with pytest.raises(ValueError):
        context_retention_days(value)


@pytest.mark.parametrize("value,expected", [("90", 90), (90, 90), ("2190", 2190), (36500, 36500)])
def test_retention_valid_values(value, expected):
    assert context_retention_days(value) == expected


def test_low_retention_cannot_synthesize():
    script = ("import json; from aws_cdk import App; from data_stack import DataStack; "
              "DataStack(App(context={'audit_archive_retention_days': '30'}), 'X')")
    result = subprocess.run(  # nosec B603 -- static argv, list form, no shell
        [sys.executable, "-c", script], cwd=CDK_ROOT, capture_output=True, text=True, timeout=240)
    assert result.returncode != 0
    assert "audit_archive_retention_days" in result.stderr


def test_bucket_versioning_bpa_ownership_retain(data):
    _, bucket = _archive_bucket(data)
    props = bucket["Properties"]
    assert props["VersioningConfiguration"] == {"Status": "Enabled"}
    assert props["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }
    assert props["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    assert "BucketName" not in props
    assert bucket["DeletionPolicy"] == "Retain" and bucket["UpdateReplacePolicy"] == "Retain"
    assert _bucket_policy(data)["DeletionPolicy"] == "Retain"


def test_no_auto_delete_custom_resource(data):
    # The retained data layer never empties a bucket (the agents stack's
    # code bucket is unrelated and still auto-deletes its bundles).
    assert not [r for r in data["Resources"].values() if r["Type"] == "Custom::S3AutoDeleteObjects"]


def test_bucket_uses_dedicated_cmk(data):
    key_id, key = _archive_key(data)
    _, bucket = _archive_bucket(data)
    (rule,) = bucket["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"]
    assert rule["ServerSideEncryptionByDefault"] == {
        "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": {"Fn::GetAtt": [key_id, "Arn"]}}
    assert rule["BucketKeyEnabled"] is True
    (sar_alias,) = [a for a in resources(data, "AWS::KMS::Alias").values()
                    if a["Properties"]["AliasName"] == "alias/fsi-sar-filings"]
    assert sar_alias["Properties"]["TargetKeyId"]["Fn::GetAtt"][0] != key_id
    assert key["Properties"]["EnableKeyRotation"] is True
    assert key["DeletionPolicy"] == "Retain"


def test_key_policy_shape(data):
    _, key = _archive_key(data)
    statements = {s["Sid"]: s for s in key["Properties"]["KeyPolicy"]["Statement"]}
    assert set(statements) == {"KeyAdministration", "ArchiverUsesKeyViaS3", "ComplianceReaderDecryptsViaS3"}
    admin = statements["KeyAdministration"]
    assert is_account_root(admin["Principal"]) and "Condition" not in admin
    for action in as_list(admin["Action"]):
        assert action != "kms:*" and action != "kms:CreateGrant"
        assert not action.startswith(("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt"))
    for sid, role, actions in (("ArchiverUsesKeyViaS3", ARCHIVER_ROLE, ["kms:GenerateDataKey", "kms:Decrypt"]),
                               ("ComplianceReaderDecryptsViaS3", "fsi-compliance-reader", ["kms:Decrypt"])):
        s = statements[sid]
        assert as_list(s["Action"]) == actions
        (arn,) = s["Condition"]["ArnEquals"]["aws:PrincipalArn"]
        assert render(arn).endswith(f":role/{role}")
        assert render(s["Condition"]["StringEquals"]["kms:ViaService"]) == "s3.${AWS::Region}.amazonaws.com"


# ─── Bucket policy ───────────────────────────────────────────────────────────
def test_bucket_policy_is_deny_only_and_tls(data):
    statements = _statements_by_sid(data)
    assert all(s["Effect"] == "Deny" and s["Principal"] == {"AWS": "*"} for s in statements.values())
    tls = statements["_tls"]
    assert tls["Action"] == "s3:*" and tls["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}


def test_delete_and_lock_change_deny(data):
    s = _statements_by_sid(data)["DenyObjectDeleteAndLockChanges"]
    assert s["Action"] == OBJECT_LOCKDOWN_ACTIONS
    assert set(OBJECT_LOCKDOWN_ACTIONS) == {
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
        "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:BypassGovernanceRetention"}
    assert "Condition" not in s
    assert render(s["Resource"]).endswith(".Arn}/*")


def test_bucket_protection_deny_excepts_only_cfn(data):
    s = _statements_by_sid(data)["DenyBucketProtectionChangesExceptCfn"]
    assert s["Action"] == BUCKET_PROTECTION_ACTIONS
    assert {"s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketObjectLockConfiguration"} <= set(s["Action"])
    (arn,) = s["Condition"]["ArnNotLike"]["aws:PrincipalArn"]
    assert render(arn) == "arn:aws:iam::${AWS::AccountId}:role/cdk-*-cfn-exec-role-${AWS::AccountId}-${AWS::Region}"


def test_put_and_read_denies(data):
    statements = _statements_by_sid(data)
    put = statements["DenyPutExceptArchiver"]
    assert put["Action"] == "s3:PutObject"
    assert [render(a) for a in put["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]] == [
        "arn:aws:iam::${AWS::AccountId}:role/fsi-audit-archiver-role"]
    read = statements["DenyReadsExceptArchiverAndReader"]
    assert read["Action"] == ["s3:GetObject", "s3:GetObjectVersion"]
    assert [render(a) for a in read["Condition"]["ArnNotEquals"]["aws:PrincipalArn"]] == [
        "arn:aws:iam::${AWS::AccountId}:role/fsi-audit-archiver-role",
        "arn:aws:iam::${AWS::AccountId}:role/fsi-compliance-reader"]


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_only_the_archiver_role_may_put_objects(context):
    templates = synth(context)
    bucket_id, _ = _archive_bucket(templates["data"])
    writers = set()
    for t in templates.values():
        roles = {lid: r["Properties"].get("RoleName", lid) for lid, r in resources(t, "AWS::IAM::Role").items()}
        for policy in resources(t, "AWS::IAM::Policy").values():
            for s in policy["Properties"]["PolicyDocument"]["Statement"]:
                actions = as_list(s["Action"])
                if s["Effect"] != "Allow" or not any(a in ("s3:PutObject", "s3:Put*", "s3:*", "*")
                                                     for a in actions):
                    continue
                if any(bucket_id in render(r) or "AuditArchive" in render(r) or render(r) == "*"
                       for r in as_list(s["Resource"])):
                    writers |= {roles.get(ref["Ref"], ref["Ref"]) for ref in policy["Properties"]["Roles"]}
    assert writers == {ARCHIVER_ROLE}


# ─── Archiver role, function, ESMs, DLQ, alarms ──────────────────────────────
def test_archiver_role_statements(data):
    by_action = {}
    for s in role_statements(data, ARCHIVER_ROLE):
        assert s["Effect"] == "Allow"
        for a in as_list(s["Action"]):
            by_action.setdefault(a, []).extend(render(r) for r in as_list(s["Resource"]))
    assert set(by_action) == {
        "s3:PutObject", "s3:GetObject", "kms:GenerateDataKey", "kms:Decrypt", "dynamodb:GetItem",
        "sqs:SendMessage", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "dynamodb:ListStreams",
        "dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
        "logs:CreateLogStream", "logs:PutLogEvents"}
    # Logs only into its own group (no AWSLambdaBasicExecutionRole).
    assert by_action["logs:PutLogEvents"] == by_action["logs:CreateLogStream"] == [
        "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/fsi/lambda/fsi-audit-archiver:*"]
    role = data["Resources"][logical_id(data, "AWS::IAM::Role", "RoleName", ARCHIVER_ROLE)]
    assert not role["Properties"].get("ManagedPolicyArns")
    bucket_id, _ = _archive_bucket(data)
    key_id, _ = _archive_key(data)
    assert by_action["s3:PutObject"] == [f"${{{bucket_id}.Arn}}/*"]
    assert by_action["kms:GenerateDataKey"] == [f"${{{key_id}.Arn}}"]
    # Source of truth: GetItem on exactly the five audit tables' ARNs (no wildcard,
    # no index ARN, no Query/Scan/BatchGetItem or any write action).
    table_arns = sorted(f"${{{logical_id(data, 'AWS::DynamoDB::Table', 'TableName', name)}.Arn}}"
                        for name, _ in TABLES.values())
    assert sorted(by_action["dynamodb:GetItem"]) == table_arns and len(table_arns) == 5
    assert not [a for a in by_action if a.startswith("dynamodb:") and a not in (
        "dynamodb:GetItem", "dynamodb:ListStreams", "dynamodb:DescribeStream", "dynamodb:GetRecords",
        "dynamodb:GetShardIterator")]
    assert len(by_action["dynamodb:GetRecords"]) == 5
    assert all(r.endswith(".StreamArn}") for r in by_action["dynamodb:GetRecords"])


def test_archiver_function(data):
    fn = data["Resources"][logical_id(data, "AWS::Lambda::Function", "FunctionName", ARCHIVER)]
    props = fn["Properties"]
    assert props["Runtime"] == "python3.13" and props["Handler"] == "handler.handler"
    assert props["MemorySize"] == 256 and props["Timeout"] == 60
    assert "DeadLetterConfig" not in props
    assert "ReservedConcurrentExecutions" not in props
    log_group = data["Resources"][props["LoggingConfig"]["LogGroup"]["Ref"]]["Properties"]
    assert log_group == {"LogGroupName": "/fsi/lambda/fsi-audit-archiver", "RetentionInDays": 30}
    env = props["Environment"]["Variables"]
    assert set(env) == {"ARCHIVE_BUCKET", "ARCHIVE_KMS_KEY_ARN", "ARCHIVE_TABLES", "EXPECTED_STREAM_ARNS"}
    stream_arns = render(env["EXPECTED_STREAM_ARNS"]).split(",")
    assert sorted(stream_arns) == sorted(
        f"${{{logical_id(data, 'AWS::DynamoDB::Table', 'TableName', name)}.StreamArn}}" for name, _ in TABLES.values())
    assert not resources(data, "AWS::Lambda::Permission")


def test_tables_unchanged_and_streamed(data):
    tables = resources(data, "AWS::DynamoDB::Table")
    assert len(tables) == 6
    for lid, (name, key) in TABLES.items():
        (props,) = [r["Properties"] for tid, r in tables.items() if tid.startswith(lid)]
        assert props["TableName"] == name
        assert props["KeySchema"] == [{"AttributeName": key, "KeyType": "HASH"}]
        expected = "KEYS_ONLY" if name == "compliance-decisions" else "NEW_IMAGE"
        assert props["StreamSpecification"] == {"StreamViewType": expected}
        assert tables[[t for t in tables if t.startswith(lid)][0]]["DeletionPolicy"] == "Retain"
    # The sixth table is the mutable governance-state item: unstreamed, not archived.
    (state,) = [r for tid, r in tables.items() if tid.startswith("GovernanceState")]
    assert state["Properties"]["TableName"] == "governance-state"
    assert "StreamSpecification" not in state["Properties"]
    state_id = logical_id(data, "AWS::DynamoDB::Table", "TableName", "governance-state")
    assert state_id not in json.dumps(resources(data, "AWS::Lambda::EventSourceMapping"))


def test_five_archiver_esms(data):
    fn = logical_id(data, "AWS::Lambda::Function", "FunctionName", ARCHIVER)
    dlq = logical_id(data, "AWS::SQS::Queue", "QueueName", "fsi-audit-archiver-dlq")
    esms = list(resources(data, "AWS::Lambda::EventSourceMapping").values())
    assert len(esms) == 5
    sources = set()
    for esm in esms:
        p = dict(esm["Properties"])
        sources.add(p.pop("EventSourceArn")["Fn::GetAtt"][0])
        assert p == {
            "BatchSize": 10, "BisectBatchOnFunctionError": True,
            "DestinationConfig": {"OnFailure": {"Destination": {"Fn::GetAtt": [dlq, "Arn"]}}},
            "FunctionName": {"Ref": fn}, "FunctionResponseTypes": ["ReportBatchItemFailures"],
            "MaximumRecordAgeInSeconds": 21600, "MaximumRetryAttempts": 10, "StartingPosition": "TRIM_HORIZON",
        }
    assert {s.rstrip("0123456789ABCDEF") for s in sources} == set(TABLES)


def test_drift_publisher_esm_unchanged(default):
    agents = default["agents"]
    (esm,) = resources(agents, "AWS::Lambda::EventSourceMapping").values()
    p = esm["Properties"]
    assert p["FunctionName"] == {"Ref": logical_id(agents, "AWS::Lambda::Function", "FunctionName",
                                                   "fsi-drift-metric-publisher")}
    assert "ComplianceDecisions" in render(p["EventSourceArn"]) and "StreamArn" in render(p["EventSourceArn"])
    assert p["StartingPosition"] == "LATEST" and p["BatchSize"] == 100
    assert p["MaximumRetryAttempts"] == 3 and p["MaximumRecordAgeInSeconds"] == 3600
    assert p["BisectBatchOnFunctionError"] is True
    assert p["FilterCriteria"] == {"Filters": [{"Pattern": '{"eventName":["INSERT"]}'}]}


def test_dlq(data):
    q = data["Resources"][logical_id(data, "AWS::SQS::Queue", "QueueName", "fsi-audit-archiver-dlq")]
    assert q["Properties"]["SqsManagedSseEnabled"] is True
    assert q["Properties"]["MessageRetentionPeriod"] == 1209600


def test_nine_alarms(data):
    topic = logical_id(data, "AWS::SNS::Topic", "TopicName", "fsi-governance-alarms")
    alarms = {r["Properties"]["AlarmName"]: r["Properties"] for r in resources(data, "AWS::CloudWatch::Alarm").values()}
    assert set(alarms) == set(ALARM_NAMES) and len(ALARM_NAMES) == 9
    for name, props in alarms.items():
        assert props["TreatMissingData"] == "notBreaching"
        assert props["ComparisonOperator"] == "GreaterThanThreshold"
        # Only action: notify on-call (never the breaker).
        assert props["AlarmActions"] == [{"Ref": topic}], name
        assert not props.get("OKActions") and not props.get("InsufficientDataActions")
    for name, metric in EMF_ALARMS.items():
        assert alarms[name]["Namespace"] == "FSI/AuditArchive" and alarms[name]["MetricName"] == metric
        assert "Dimensions" not in alarms[name] and alarms[name]["Threshold"] == 0
    assert alarms["fsi-audit-archiver-dlq-not-empty"]["MetricName"] == "ApproximateNumberOfMessagesVisible"
    assert alarms["fsi-audit-archiver-errors"]["MetricName"] == "Errors"
    assert alarms["fsi-audit-archiver-iterator-age"]["MetricName"] == "IteratorAge"
    assert alarms["fsi-audit-archiver-iterator-age"]["Threshold"] == 900000


def test_examiner_reader_grants(default):
    agents = default["agents"]
    statements = role_statements(agents, "fsi-compliance-reader")
    archive = [s for s in statements if "AuditArchive" in json.dumps(s["Resource"])]
    by_actions = {tuple(as_list(s["Action"])): s for s in archive}
    assert set(by_actions) == {
        ("s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention", "s3:GetObjectAttributes"),
        ("s3:ListBucket", "s3:ListBucketVersions"),
        ("kms:Decrypt",),
    }
    assert render(by_actions[("kms:Decrypt",)]["Condition"]["StringEquals"]["kms:ViaService"]) == \
        "s3.${AWS::Region}.amazonaws.com"


def test_destroy_script_has_no_s3_usage():
    with open(os.path.join(CDK_ROOT, "destroy_agentcore_runtimes.py"), encoding="utf-8") as f:
        source = f.read()
    assert '"s3"' not in source and "'s3'" not in source and "delete_bucket" not in source
    with open(os.path.join(PROJECT_ROOT, "Makefile"), encoding="utf-8") as f:
        makefile = f.read()
    destroy = makefile.split("\ndestroy:", 1)[1].split("\nsynth:", 1)[0]
    assert "cdk destroy --all --force" in destroy
    assert "s3 rm" not in destroy and "rb " not in destroy
    assert "audit archive bucket" in destroy.lower()
