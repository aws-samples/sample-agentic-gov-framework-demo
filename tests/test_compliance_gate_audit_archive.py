"""
Compliance gate: the immutable audit archive can't be silently dropped or
weakened. The pure assertions pass on the real synthesized templates and
fail on every mutated copy; synth problems fail closed. Local synth only.
"""
import copy
import json
import os
import subprocess
import sys

import pytest

from _cdk_synth import DEFAULT_CONTEXT, FULL_CONTEXT, logical_id, resources, synth

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
import compliance_gate  # noqa: E402
from compliance_gate import (  # noqa: E402
    ARCHIVE_ALARMS, ComplianceGate, SynthUnavailable, audit_archive_assertions,
)


@pytest.fixture(scope="module")
def real():
    t = synth(DEFAULT_CONTEXT)
    return t["data"], t["agents"]


def _failures(data, agents, min_days=90):
    return [d for ok, d in audit_archive_assertions(data, agents, min_days) if not ok]


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_assertions_pass_on_real_templates(context):
    t = synth(context)
    results = audit_archive_assertions(t["data"], t["agents"], 90)
    assert len(results) > 50
    assert [d for ok, d in results if not ok] == []


def test_override_retention_passes_its_own_floor():
    t = synth({"audit_archive_retention_days": "2190"})
    assert _failures(t["data"], t["agents"], 2190) == []


def test_floor_above_template_retention_fails(real):
    assert any("default retention >=" in d for d in _failures(*real, min_days=2190))


def test_floor_never_below_90(real):
    data, agents = copy.deepcopy(real)
    _bucket(data)["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Days"] = 30
    assert any("default retention >= 90" in d for d in _failures(data, agents, min_days=1))


# ─── helpers ─────────────────────────────────────────────────────────────────
def _bucket_id(data):
    (lid,) = [lid for lid, r in resources(data, "AWS::S3::Bucket").items()
              if r["Properties"].get("ObjectLockEnabled") is True]
    return lid


def _bucket(data):
    return data["Resources"][_bucket_id(data)]


def _policy_statements(data):
    bid = _bucket_id(data)
    (p,) = [r for r in resources(data, "AWS::S3::BucketPolicy").values() if r["Properties"]["Bucket"] == {"Ref": bid}]
    return p["Properties"]["PolicyDocument"]["Statement"]


def _drop_sid(data, sid):
    stmts = _policy_statements(data)
    stmts[:] = [s for s in stmts if s.get("Sid") != sid]


def _sid(data, sid):
    (s,) = [s for s in _policy_statements(data) if s.get("Sid") == sid]
    return s


def _archive_key(data):
    (a,) = [a for a in resources(data, "AWS::KMS::Alias").values()
            if a["Properties"]["AliasName"] == "alias/fsi-audit-archive"]
    return data["Resources"][a["Properties"]["TargetKeyId"]["Fn::GetAtt"][0]]


def _sar_key_id(data):
    (a,) = [a for a in resources(data, "AWS::KMS::Alias").values()
            if a["Properties"]["AliasName"] == "alias/fsi-sar-filings"]
    return a["Properties"]["TargetKeyId"]["Fn::GetAtt"][0]


def _table_id(data, name):
    return logical_id(data, "AWS::DynamoDB::Table", "TableName", name)


def _archiver_esm(data, table="executor-audit"):
    tid = _table_id(data, table)
    (e,) = [e for e in resources(data, "AWS::Lambda::EventSourceMapping").values()
            if e["Properties"]["EventSourceArn"] == {"Fn::GetAtt": [tid, "StreamArn"]}]
    return e["Properties"]


def _archiver_esm_ids(data, table):
    tid = _table_id(data, table)
    return [lid for lid, e in resources(data, "AWS::Lambda::EventSourceMapping").items()
            if e["Properties"]["EventSourceArn"] == {"Fn::GetAtt": [tid, "StreamArn"]}]


def _archiver_fn(data):
    return data["Resources"][logical_id(data, "AWS::Lambda::Function", "FunctionName", "fsi-audit-archiver")]


def _drift_esm(agents):
    (e,) = resources(agents, "AWS::Lambda::EventSourceMapping").values()
    return e["Properties"]


def _set_retention(mode=None, days=None):
    def f(data, agents):
        r = _bucket(data)["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
        if mode:
            r["Mode"] = mode
        if days is not None:
            r["Days"] = days
    return f


def _root_decrypt(data, agents):
    _archive_key(data)["Properties"]["KeyPolicy"]["Statement"][0]["Action"].append("kms:Decrypt")


def _second_writer(data, agents):
    bid = _bucket_id(data)
    (p,) = [p for p in resources(agents, "AWS::IAM::Policy").values()
            if p["Properties"].get("Roles")][:1]
    p["Properties"]["PolicyDocument"]["Statement"].append({
        "Effect": "Allow", "Action": "s3:PutObject",
        "Resource": {"Fn::Join": ["", [{"Fn::GetAtt": [bid, "Arn"]}, "/*"]]}})


def _third_consumer(data, agents):
    esm = copy.deepcopy(_archiver_esm(data, "compliance-decisions"))
    data["Resources"]["ExtraConsumer"] = {"Type": "AWS::Lambda::EventSourceMapping", "Properties": esm}


def _archiver_policy_statements(data):
    role = logical_id(data, "AWS::IAM::Role", "RoleName", "fsi-audit-archiver-role")
    return [st for p in resources(data, "AWS::IAM::Policy").values()
            if {"Ref": role} in p["Properties"].get("Roles", [])
            for st in p["Properties"]["PolicyDocument"]["Statement"]]
def _get_item_statements(data):
    return [st for st in _archiver_policy_statements(data) if st["Action"] == "dynamodb:GetItem"]
def _getitem_drop_table(data, agents):
    first, second = _get_item_statements(data)[:2]
    first["Resource"] = second["Resource"]  # one table lost its GetItem, another doubled
def _getitem_wildcard(data, agents):
    _get_item_statements(data)[0]["Resource"] = "*"
def _archiver_scan(data, agents):
    (p,) = [p for p in resources(data, "AWS::IAM::Policy").values()
            if {"Ref": logical_id(data, "AWS::IAM::Role", "RoleName", "fsi-audit-archiver-role")}
            in p["Properties"].get("Roles", [])]
    p["Properties"]["PolicyDocument"]["Statement"].append(
        {"Effect": "Allow", "Action": "dynamodb:Query", "Resource": "*"})
def _env_drop(name):
    def f(data, agents):
        _archiver_fn(data)["Properties"]["Environment"]["Variables"].pop(name)
    return f
def _env_one_stream_less(data, agents):
    v = _archiver_fn(data)["Properties"]["Environment"]["Variables"]
    v["EXPECTED_STREAM_ARNS"] = {"Fn::Join": [",", v["EXPECTED_STREAM_ARNS"]["Fn::Join"][1][:-2]]}
def _remove_alarm(name):
    def f(data, agents):
        (lid,) = [lid for lid, r in resources(data, "AWS::CloudWatch::Alarm").items()
                  if r["Properties"]["AlarmName"] == name]
        del data["Resources"][lid]
    return f


def _drop_action(sid, action):
    def f(data, agents):
        s = _sid(data, sid)
        s["Action"] = [a for a in s["Action"] if a != action]
    return f


MUTATIONS = {
    # 1. Object Lock
    "no_object_lock_bucket": lambda d, a: _bucket(d)["Properties"].pop("ObjectLockEnabled"),
    "lock_config_disabled": lambda d, a: _bucket(d)["Properties"]["ObjectLockConfiguration"].pop("ObjectLockEnabled"),
    "governance_mode": _set_retention(mode="GOVERNANCE"),
    "thirty_days": _set_retention(days=30),
    "no_default_retention": lambda d, a: _bucket(d)["Properties"]["ObjectLockConfiguration"].pop("Rule"),
    # 2. versioning / ownership
    "versioning_off": lambda d, a: _bucket(d)["Properties"].update(VersioningConfiguration={"Status": "Suspended"}),
    "ownership_changed": lambda d, a: _bucket(d)["Properties"].update(
        OwnershipControls={"Rules": [{"ObjectOwnership": "ObjectWriter"}]}),
    # 3. KMS
    "sse_s3": lambda d, a: _bucket(d)["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
    .update(ServerSideEncryptionByDefault={"SSEAlgorithm": "AES256"}),
    "sar_key_instead": lambda d, a: _bucket(d)["Properties"]["BucketEncryption"]
    ["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"]
    .update(KMSMasterKeyID={"Fn::GetAtt": [_sar_key_id(d), "Arn"]}),
    "key_rotation_off": lambda d, a: _archive_key(d)["Properties"].update(EnableKeyRotation=False),
    "key_not_retained": lambda d, a: _archive_key(d).update(DeletionPolicy="Delete"),
    "root_can_decrypt": _root_decrypt,
    "extra_key_user": lambda d, a: _archive_key(d)["Properties"]["KeyPolicy"]["Statement"].append(
        {**copy.deepcopy(_archive_key(d)["Properties"]["KeyPolicy"]["Statement"][2]), "Sid": "Extra",
         "Condition": {"ArnEquals": {"aws:PrincipalArn": ["arn:aws:iam::1:role/other"]},
                       "StringEquals": {"kms:ViaService": "s3.us-east-1.amazonaws.com"}}}),
    # 4. BPA
    "bpa_flag_false": lambda d, a: _bucket(d)["Properties"]["PublicAccessBlockConfiguration"].update(
        RestrictPublicBuckets=False),
    # 5. bucket policy
    "tls_deny_removed": lambda d, a: _policy_statements(d).pop(0),
    "delete_deny_removed": lambda d, a: _drop_sid(d, "DenyObjectDeleteAndLockChanges"),
    "delete_tagging_not_denied": _drop_action("DenyObjectDeleteAndLockChanges", "s3:DeleteObjectTagging"),
    "delete_deny_conditioned": lambda d, a: _sid(d, "DenyObjectDeleteAndLockChanges").update(
        Condition={"ArnNotLike": {"aws:PrincipalArn": "*admin*"}}),
    "protection_deny_removed": lambda d, a: _drop_sid(d, "DenyBucketProtectionChangesExceptCfn"),
    "policy_change_not_denied": _drop_action("DenyBucketProtectionChangesExceptCfn", "s3:PutBucketPolicy"),
    "put_deny_removed": lambda d, a: _drop_sid(d, "DenyPutExceptArchiver"),
    "read_deny_removed": lambda d, a: _drop_sid(d, "DenyReadsExceptArchiverAndReader"),
    "public_allow_added": lambda d, a: _policy_statements(d).append(
        {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "*"}),
    "second_writer_role": _second_writer,
    # 6. RETAIN
    "bucket_not_retained": lambda d, a: _bucket(d).update(DeletionPolicy="Delete"),
    "auto_delete_added": lambda d, a: d["Resources"].update(
        AutoDel={"Type": "Custom::S3AutoDeleteObjects", "Properties": {}}),
    # 7. ESMs
    "one_table_esm_removed": lambda d, a: d["Resources"].pop(_archiver_esm_ids(d, "governance-audit")[0]),
    "stream_removed": lambda d, a: d["Resources"][_table_id(d, "operator-audit")]["Properties"].pop(
        "StreamSpecification"),
    "esm_disabled": lambda d, a: _archiver_esm(d).update(Enabled=False),
    "esm_insert_filter": lambda d, a: _archiver_esm(d).update(
        FilterCriteria={"Filters": [{"Pattern": '{"eventName":["INSERT"]}'}]}),
    "esm_latest": lambda d, a: _archiver_esm(d).update(StartingPosition="LATEST"),
    "esm_max_age_infinite": lambda d, a: _archiver_esm(d).update(MaximumRecordAgeInSeconds=-1),
    "esm_max_age_missing": lambda d, a: _archiver_esm(d).pop("MaximumRecordAgeInSeconds"),
    "esm_max_age_too_long": lambda d, a: _archiver_esm(d).update(MaximumRecordAgeInSeconds=86401),
    "esm_no_bisect": lambda d, a: _archiver_esm(d).update(BisectBatchOnFunctionError=False),
    "esm_unbounded_retries": lambda d, a: _archiver_esm(d).update(MaximumRetryAttempts=-1),
    "esm_no_item_failures": lambda d, a: _archiver_esm(d).pop("FunctionResponseTypes"),
    "esm_no_dlq": lambda d, a: _archiver_esm(d).pop("DestinationConfig"),
    "reserved_concurrency_zero": lambda d, a: _archiver_fn(d)["Properties"].update(ReservedConcurrentExecutions=0),
    # 8. compliance-decisions stream consumers
    "third_consumer": _third_consumer,
    "drift_esm_removed": lambda d, a: a["Resources"].pop(next(iter(resources(a, "AWS::Lambda::EventSourceMapping")))),
    "drift_filter_removed": lambda d, a: _drift_esm(a).pop("FilterCriteria"),
    "drift_dlq_removed": lambda d, a: _drift_esm(a).pop("DestinationConfig"),
    "drift_starting_position": lambda d, a: _drift_esm(a).update(StartingPosition="TRIM_HORIZON"),
    # 9. DLQ / function DLQ / alarms
    "function_dlq_added": lambda d, a: _archiver_fn(d)["Properties"].update(
        DeadLetterConfig={"TargetArn": "arn:aws:sqs:us-east-1:1:x"}),
    "dlq_unencrypted": lambda d, a: d["Resources"][logical_id(
        d, "AWS::SQS::Queue", "QueueName", "fsi-audit-archiver-dlq")]["Properties"].pop("SqsManagedSseEnabled"),
    # The archiver re-reads from exactly the five tables
    "getitem_table_dropped": _getitem_drop_table,
    "getitem_wildcard": _getitem_wildcard,
    "archiver_query_added": _archiver_scan,
    "expected_stream_arns_missing": _env_drop("EXPECTED_STREAM_ARNS"),
    "expected_stream_arns_short": _env_one_stream_less,
    **{f"alarm_removed_{name}": _remove_alarm(name) for name in ARCHIVE_ALARMS},
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_each_mutation_fails_the_gate(real, name):
    data, agents = copy.deepcopy(real)
    MUTATIONS[name](data, agents)
    assert _failures(data, agents), f"mutation {name} passed the gate"


def test_archive_removed_entirely_fails(real):
    data, agents = copy.deepcopy(real)
    for lid in [lid for lid, r in data["Resources"].items() if lid.startswith("AuditArchiveLayer")]:
        del data["Resources"][lid]
    failures = _failures(data, agents)
    assert len(failures) > 30


# ─── check_audit_archive: wiring, fail-closed synth, cache ───────────────────
def _audit_results(gate):
    return [a for a in gate.domain_results["Audit"]["assertions"] if a["description"].startswith("Audit archive:")]


def test_check_records_under_audit_domain(monkeypatch, real):
    monkeypatch.setattr(compliance_gate, "synth_cdk_templates", lambda use_cache=True: real)
    gate = ComplianceGate()
    gate.check_audit_archive()
    results = _audit_results(gate)
    assert results and all(a["passed"] for a in results)


def test_run_all_includes_the_archive_check(monkeypatch):
    called = []
    for name in ("check_boundary", "check_model_governance", "check_audit", "check_access_control",
                 "check_model_assurance", "check_supply_chain"):
        monkeypatch.setattr(ComplianceGate, name, lambda self: None)
    monkeypatch.setattr(ComplianceGate, "check_audit_archive", lambda self: called.append(True))
    ComplianceGate().run_all()
    assert called == [True]


def test_synth_unavailable_fails_closed(monkeypatch):
    def boom(use_cache=True):
        raise SynthUnavailable("cdk synth exited 1")
    monkeypatch.setattr(compliance_gate, "synth_cdk_templates", boom)
    gate = ComplianceGate()
    gate.check_audit_archive()
    (a,) = _audit_results(gate)
    assert not a["passed"] and a["description"] == "Audit archive: CDK app synthesizes (cdk synth exited 1)"


def test_missing_node_is_explicit(monkeypatch):
    monkeypatch.setattr(compliance_gate.shutil, "which", lambda name: None)
    gate = ComplianceGate()
    gate.check_audit_archive()
    (a,) = _audit_results(gate)
    assert not a["passed"] and "Node.js not found" in a["description"]


def test_missing_aws_cdk_is_explicit(monkeypatch):
    real_find = compliance_gate.importlib.util.find_spec
    monkeypatch.setattr(compliance_gate.importlib.util, "find_spec",
                        lambda name: None if name == "aws_cdk" else real_find(name))
    with pytest.raises(SynthUnavailable, match="aws_cdk not installed"):
        compliance_gate.synth_cdk_templates(use_cache=False)


@pytest.fixture
def fake_synth(monkeypatch, tmp_path, real):
    """_run_cdk_synth replaced by one that writes the real templates."""
    calls = []
    monkeypatch.setattr(compliance_gate, "SYNTH_CACHE_DIR", str(tmp_path / "cache"))

    def run(outdir, context):
        calls.append({"outdir": outdir, "context": context})
        for name, tpl in ((compliance_gate.DATA_STACK_TEMPLATE, real[0]),
                          (compliance_gate.AGENTS_STACK_TEMPLATE, real[1])):
            with open(os.path.join(outdir, name), "w", encoding="utf-8") as f:
                json.dump(tpl, f)
        return subprocess.CompletedProcess(["x"], 0)
    monkeypatch.setattr(compliance_gate, "_run_cdk_synth", run)
    return calls


def test_synth_uses_cdk_json_context_and_removes_tempdir(fake_synth):
    data, agents = compliance_gate.synth_cdk_templates(use_cache=False)
    assert data["Resources"] and agents["Resources"]
    (call,) = fake_synth
    with open(os.path.join(PROJECT_ROOT, "cdk", "cdk.json"), encoding="utf-8") as f:
        assert call["context"] == json.load(f)["context"]
    assert not os.path.exists(call["outdir"])


def test_cache_reused_for_plain_runs_but_not_for_sign(fake_synth):
    compliance_gate.synth_cdk_templates(use_cache=True)
    compliance_gate.synth_cdk_templates(use_cache=True)
    assert len(fake_synth) == 1
    compliance_gate.synth_cdk_templates(use_cache=False)
    assert len(fake_synth) == 2


def test_sign_mode_never_reads_the_cache(monkeypatch, real):
    seen = []
    monkeypatch.setattr(compliance_gate, "synth_cdk_templates",
                        lambda use_cache=True: seen.append(use_cache) or real)
    ComplianceGate().check_audit_archive()
    ComplianceGate(sign_mode=compliance_gate.SIGN_MODE_LOCAL_DEV).check_audit_archive()
    ComplianceGate(sign_mode=compliance_gate.SIGN_MODE_KMS).check_audit_archive()
    assert seen == [True, False, False]


def test_planted_cache_is_ignored_by_sign(fake_synth, real):
    compliance_gate.synth_cdk_templates(use_cache=True)
    (path,) = [os.path.join(compliance_gate.SYNTH_CACHE_DIR, p) for p in os.listdir(compliance_gate.SYNTH_CACHE_DIR)]
    weakened = copy.deepcopy(real[0])
    _bucket(weakened)["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Mode"] = "GOVERNANCE"
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"data": weakened, "agents": real[1]}, f)
    data, _ = compliance_gate.synth_cdk_templates(use_cache=False)
    assert _bucket(data)["Properties"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Mode"] == "COMPLIANCE"


def test_failed_synth_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(compliance_gate, "SYNTH_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(compliance_gate, "_run_cdk_synth", lambda outdir, context: subprocess.CompletedProcess(["x"], 1))
    with pytest.raises(SynthUnavailable, match="exited 1"):
        compliance_gate.synth_cdk_templates(use_cache=False)


def test_synth_timeout_raises(monkeypatch, tmp_path):
    def slow(outdir, context):
        raise subprocess.TimeoutExpired(["x"], 300)
    monkeypatch.setattr(compliance_gate, "_run_cdk_synth", slow)
    with pytest.raises(SynthUnavailable, match="timed out"):
        compliance_gate.synth_cdk_templates(use_cache=False)


def test_cache_key_changes_with_cdk_and_context(monkeypatch):
    base = compliance_gate.synth_cache_key({"a": 1})
    assert compliance_gate.synth_cache_key({"a": 2}) != base
    monkeypatch.setattr(compliance_gate, "_aws_cdk_version", lambda: "0.0.0-test")
    assert compliance_gate.synth_cache_key({"a": 1}) != base


def test_min_retention_reads_cdk_json(monkeypatch, tmp_path):
    cdk_json = tmp_path / "cdk.json"
    monkeypatch.setattr(compliance_gate, "CDK_JSON", str(cdk_json))
    cdk_json.write_text(json.dumps({"context": {"audit_archive_retention_days": 2190}}))
    assert compliance_gate.audit_archive_min_retention_days() == 2190
    cdk_json.write_text(json.dumps({"context": {"audit_archive_retention_days": 30}}))
    assert compliance_gate.audit_archive_min_retention_days() == 90
    cdk_json.write_text(json.dumps({"context": {}}))
    assert compliance_gate.audit_archive_min_retention_days() == 90


def test_real_gate_synth_end_to_end(monkeypatch, tmp_path):
    """The gate's own synth of the real app (Node.js + aws_cdk available here)."""
    monkeypatch.setattr(compliance_gate, "SYNTH_CACHE_DIR", str(tmp_path / "cache"))
    gate = ComplianceGate(sign_mode=compliance_gate.SIGN_MODE_LOCAL_DEV)
    gate.check_audit_archive()
    results = _audit_results(gate)
    assert len(results) > 50
    assert [a["description"] for a in results if not a["passed"]] == []
    assert not os.path.exists(tmp_path / "cache")  # sign mode writes no cache
