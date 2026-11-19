"""
Detection -> compliance provenance (compliance side).
A durable compliance run assesses only the STORED
detection clusters: a mismatch or absent record is a 409 before any Bedrock
client exists, a lookup error a 503, and input_quality / evidence_flags come
from the stored item, never from the caller.
"""
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import (  # noqa: E402
    FakeAws, cluster, detection_output, load_compliance_shim, post,
)
from _cdk_synth import DEFAULT_CONTEXT, as_list, logical_id, render, role_statements, synth  # noqa: E402


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.delenv("ALLOW_UNVERIFIED_EVALUATION", raising=False)
    return FakeAws().install(monkeypatch, ch)


def _run(det):
    return ch.handler({"mode": "live", "detection_output": det})


def _guarded_text(fake_bedrock):
    return "".join(b["guardContent"]["text"]["text"]
                   for call in fake_bedrock.calls
                   for b in call["messages"][0]["content"] if "guardContent" in b)


# ─── VERIFIED: stored values drive the assessment ────────────────────────────

def test_durable_match_assesses_stored_clusters(aws):
    det = detection_output()
    aws.store_detection(det, record_day="2026-01-01")
    # Caller numbers in a different JSON form (int vs float) still match;
    # caller-only extra keys are not compared and never reach the prompt.
    caller = detection_output([dict(cluster(), total_amount_usd=27000, analyst_notes="ZZNOTEZZ")])
    out = _run(caller)
    assert out["provenance_status"] == "VERIFIED"
    get = [e for e in aws.events if e[0] == "get_item" and e[1] == "detection-results"]
    assert get == [("get_item", "detection-results", {"detection_id": "det-0001"}, True)]
    assert [c["decision"] for c in out["clusters_assessed"]] == ["FILE_SAR"]
    text = _guarded_text(aws.bedrock)
    assert "circular_structuring" in text and "ZZNOTEZZ" not in text


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(typology="layering_shell"),
    lambda c: c.update(cluster_id="other-id"),
    lambda c: c.update(total_amount_usd=1.0),
    lambda c: c.update(accounts=["acc-a", "acc-b", "acc-x"]),
    lambda c: c["confidence_factors"].update(circular_ratio=0.5),
], ids=["typology", "cluster_id", "amount", "accounts", "confidence_factors"])
def test_durable_mismatch_is_409_without_bedrock(aws, mutate):
    aws.store_detection(detection_output())
    caller = detection_output()
    mutate(caller["flagged_clusters"][0])
    out = _run(caller)
    assert out == {"error": "PROVENANCE_CHECK_FAILED",
                   "message": "detection_output does not match the recorded detection"}
    assert "bedrock-runtime" not in aws.clients_built
    assert aws.transactions == [] and aws.puts == [] and aws.metrics == []


def test_extra_or_missing_cluster_is_409(aws):
    aws.store_detection(detection_output([cluster("c1"), cluster("c2")]))
    assert _run(detection_output([cluster("c1")]))["error"] == "PROVENANCE_CHECK_FAILED"
    assert _run(detection_output([cluster("c1"), cluster("c2"), cluster("c3")]))["error"] \
        == "PROVENANCE_CHECK_FAILED"
    assert "bedrock-runtime" not in aws.clients_built


def test_record_absent_flag_off_is_409(aws):
    out = _run(detection_output())
    assert out["error"] == "PROVENANCE_CHECK_FAILED"
    assert "bedrock-runtime" not in aws.clients_built


def test_record_absent_flag_on_is_unverified_evaluation_only(aws, monkeypatch):
    monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    out = _run(detection_output([cluster("c1"), cluster("c2")]))
    assert out["provenance_status"] == "UNVERIFIED"
    assert {c["decision"] for c in out["clusters_assessed"]} == {"NEEDS_REVIEW"}
    assert all(c["model_metadata"]["provenance_gate"] == "UNVERIFIED" for c in out["clusters_assessed"])
    assert "dispatch_token" not in out
    assert "put_metric_data" not in aws.kinds()
    # No single-decision marker: a plain conditional put, no transaction.
    assert aws.transactions == []
    assert [e for e in aws.events if e[0] == "put_item"] == [
        ("put_item", "compliance-decisions", "attribute_not_exists(compliance_id)")]
    assert aws.puts[0]["provenance_status"] == "UNVERIFIED"
    assert "dispatch_token_sha256" not in aws.puts[0]


def test_lookup_error_is_503_without_bedrock(aws, monkeypatch):
    aws.get_item_error = RuntimeError("ddb down arn:aws:iam::123456789012:role/x")
    shim = load_compliance_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    status, body = post(shim, {"detection_output": detection_output()})
    assert status == 503
    assert body["error"] == "PROVENANCE_UNAVAILABLE" and "error_id" in body
    assert "123456789012" not in str(body)
    assert "bedrock-runtime" not in aws.clients_built


def test_shim_maps_mismatch_to_409(aws, monkeypatch):
    shim = load_compliance_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    status, body = post(shim, {"detection_output": detection_output()})
    assert status == 409 and body["error"] == "PROVENANCE_CHECK_FAILED"


@pytest.mark.parametrize("detection_id", ["", "has space", "x" * 129, 7, None, "a#b"])
def test_invalid_detection_id_rejected_before_lookup(aws, detection_id):
    det = detection_output()
    det["detection_id"] = detection_id
    with pytest.raises(ValueError, match="detection_id is invalid"):
        _run(det)
    assert aws.events == []


def test_non_durable_is_not_checked(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch, durable=False)
    out = _run(detection_output())
    assert out["provenance_status"] == "NOT_CHECKED"
    assert [c["decision"] for c in out["clusters_assessed"]] == ["FILE_SAR"]
    assert "resource:dynamodb" not in aws.clients_built and "dynamodb" not in aws.clients_built
    assert aws.metrics == [] and "dispatch_token" not in out


# ─── input_quality / evidence_flags from the STORED item ─────────────

def test_degraded_input_forces_needs_review(aws):
    det = detection_output([cluster("c1"), cluster("c2")])
    aws.store_detection(det, input_quality={"transactions_in": 100, "transactions_used": 85,
                                            "schema_rejected": 15, "duplicates_rejected": 0,
                                            "fields_dropped": 0})
    out = _run(det)
    assert {c["decision"] for c in out["clusters_assessed"]} == {"NEEDS_REVIEW"}
    assert all(c["model_metadata"]["input_quality_gate"] == "DEGRADED_INPUT"
               for c in out["clusters_assessed"])


def test_low_schema_rejection_share_does_not_gate(aws):
    det = detection_output()
    aws.store_detection(det, input_quality={"transactions_in": 100, "schema_rejected": 10})
    out = _run(det)
    assert out["clusters_assessed"][0]["decision"] == "FILE_SAR"
    assert "input_quality_gate" not in out["clusters_assessed"][0]["model_metadata"]


def test_caller_input_quality_is_ignored(aws):
    det = detection_output()
    aws.store_detection(det)
    caller = dict(det, input_quality={"transactions_in": 1, "schema_rejected": 1})
    assert _run(caller)["clusters_assessed"][0]["decision"] == "FILE_SAR"


def test_stored_evidence_flags_force_needs_review(aws):
    det = detection_output([cluster("c1"), cluster("c2")])
    stored = detection_output([cluster("c1", evidence_flags=["AMOUNT_MISMATCH"]), cluster("c2")])
    aws.store_detection(stored)
    out = _run(det)  # the caller omits the flags; the stored copy carries them
    by_id = {c["cluster_id"]: c for c in out["clusters_assessed"]}
    assert by_id["c1"]["decision"] == "NEEDS_REVIEW"
    assert by_id["c1"]["model_metadata"]["evidence_gate"] == "EVIDENCE_FLAGGED"
    assert by_id["c2"]["decision"] == "FILE_SAR"


def test_caller_evidence_flags_cannot_clear_stored_flags_or_add_any(aws):
    aws.store_detection(detection_output())
    caller = detection_output([cluster(evidence_flags=["OVERLAPPING_ACCOUNT"])])
    assert _run(caller)["clusters_assessed"][0]["decision"] == "FILE_SAR"


def test_evidence_flags_never_reach_the_prompt(aws):
    stored = detection_output([cluster(evidence_flags=["AMOUNT_MISMATCH"])])
    aws.store_detection(stored, input_quality={"transactions_in": 10, "schema_rejected": 0})
    _run(detection_output())
    text = _guarded_text(aws.bedrock)
    assert "AMOUNT_MISMATCH" not in text and "schema_rejected" not in text


# ─── IaC ─────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def templates():
    return synth(DEFAULT_CONTEXT)


def test_compliance_role_reads_detection_results_by_getitem_only(templates):
    agents, data = templates["agents"], templates["data"]
    table_id = logical_id(data, "AWS::DynamoDB::Table", "TableName", "detection-results")
    on_detection = [s for s in role_statements(agents, "compliance-agent-role")
                    if table_id in render(s["Resource"]) or
                    any(table_id in render(r) for r in as_list(s["Resource"]))]
    assert on_detection, "compliance role must have a detection-results statement"
    for statement in on_detection:
        assert as_list(statement["Action"]) == ["dynamodb:GetItem"], statement


def _load_deploy():
    import importlib.util
    cdk_dir = os.path.join(PROJECT_ROOT, "cdk")
    sys.path.insert(0, cdk_dir)
    try:
        spec = importlib.util.spec_from_file_location(
            "_deploy_provenance_test", os.path.join(cdk_dir, "deploy_agentcore_runtimes.py"))
        deploy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(deploy)
    finally:
        sys.path.remove(cdk_dir)
    return deploy


@pytest.mark.parametrize("argv, expected", [([], "false"),
                                             (["--allow-unverified-evaluation"], "true")])
def test_deploy_sets_detection_table_and_unverified_flag(monkeypatch, tmp_path, argv, expected):
    deploy = _load_deploy()
    deployed = {}
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "get_account_id", lambda: "123456789012")
    monkeypatch.setattr(deploy, "get_code_bucket_name", lambda account_id, explicit_bucket=None: "b")
    monkeypatch.setattr(deploy, "get_agents_stack_outputs", lambda: {
        "GuardrailId": "gr", "GuardrailVersion": "1",
        "TxnRefHmacSecretArn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:x"})
    monkeypatch.setattr(deploy, "get_data_stack_outputs",
                        lambda: {"SarBucketName": "s", "AnalystQueueUrl": "https://sqs.example/q"})
    monkeypatch.setattr(deploy, "package_agent", lambda cfg, build_dir: tmp_path / "x.zip")
    # Prebuilt bundles + gate-artifact verification are covered
    # by tests/test_deploy_requires_gate_artifact.py; stubbed here.
    monkeypatch.setattr(deploy, "verify_gate_artifact", lambda build_dir: None)
    # Runtime-ARN pinning is covered by tests/test_runtime_pins.py.
    monkeypatch.setattr(deploy, "pin_runtime_arns", lambda results, account_id: True)
    monkeypatch.setattr(deploy, "_load_prebuilt_bundle", lambda cfg, build_dir: tmp_path / f"{cfg['name']}.zip")
    monkeypatch.setattr(deploy, "deploy_agent", lambda cfg, *a: deployed.update(
        {cfg["name"]: dict(cfg["env_vars"])}) or "arn")
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py", *argv])
    deploy.main()
    env = deployed["ComplianceAgent"]
    assert env["DETECTION_TABLE"] == "detection-results"
    assert env["ALLOW_UNVERIFIED_EVALUATION"] == expected
    assert "ALLOW_UNVERIFIED_EVALUATION" not in deployed["DetectionAgent"]
