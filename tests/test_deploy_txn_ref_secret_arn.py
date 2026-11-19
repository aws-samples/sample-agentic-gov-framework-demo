"""
Test: the deploy script wires the txn_ref secret ARN, never a plaintext key.

cdk/deploy_agentcore_runtimes.py must:
  - carry no TXN_REF_HMAC_KEY in any AGENTS env_vars, and TXN_REF_HMAC_SECRET_ARN
    on the DetectionAgent only;
  - abort (exit 1) before any deploy when the stack lacks TxnRefHmacSecretArn;
  - ignore (with a notice) a TXN_REF_HMAC_KEY in the deploy environment;
  - refuse, in deploy_agent(), any env_vars holding TXN_REF_HMAC_KEY before
    touching boto3.
No AWS call is made: every boto3 entry point is monkeypatched.
"""
import copy
import importlib.util
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")

_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:txn-ref-AbCdEf"


@pytest.fixture
def deploy(monkeypatch):
    """Fresh import of the deploy script, with a private copy of AGENTS."""
    sys.path.insert(0, CDK_ROOT)
    try:
        spec = importlib.util.spec_from_file_location(
            "_deploy_agentcore_runtimes_under_test",
            os.path.join(CDK_ROOT, "deploy_agentcore_runtimes.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(CDK_ROOT)
    monkeypatch.setattr(mod, "AGENTS", copy.deepcopy(mod.AGENTS))
    return mod


def _env(mod, name):
    return next(a for a in mod.AGENTS if a["name"] == name)["env_vars"]


def _drive_main(mod, monkeypatch, tmp_path, agents_outputs, deployed=None):
    """Run main() with every AWS-touching helper replaced; return deploy log."""
    deployed = [] if deployed is None else deployed
    monkeypatch.setattr(mod, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(mod, "get_account_id", lambda: "123456789012")
    monkeypatch.setattr(mod, "get_code_bucket_name", lambda account_id, explicit_bucket=None: "bucket")
    monkeypatch.setattr(mod, "get_agents_stack_outputs", lambda: dict(agents_outputs))
    monkeypatch.setattr(
        mod, "get_data_stack_outputs",
        lambda: {"SarBucketName": "sar", "AnalystQueueUrl": "https://sqs.example/q"},
    )
    monkeypatch.setattr(mod, "package_agent", lambda cfg, build_dir: tmp_path / "x.zip")
    # The default deploy loads prebuilt bundles and verifies the signed gate
    # artifact first; both are covered by
    # tests/test_deploy_requires_gate_artifact.py, so stub them here.
    monkeypatch.setattr(mod, "verify_gate_artifact", lambda build_dir: None)
    # Runtime-ARN pinning is covered by tests/test_runtime_pins.py.
    monkeypatch.setattr(mod, "pin_runtime_arns", lambda results, account_id: True)
    monkeypatch.setattr(mod, "_load_prebuilt_bundle", lambda cfg, build_dir: tmp_path / f"{cfg['name']}.zip")

    def record(cfg, zip_path, bucket, account_id):
        deployed.append((cfg["name"], dict(cfg["env_vars"])))
        return "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/" + cfg["name"]

    monkeypatch.setattr(mod, "deploy_agent", record)
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py"])
    mod.main()
    return deployed


_GOOD_OUTPUTS = {"GuardrailId": "gr-123", "GuardrailVersion": "3", "TxnRefHmacSecretArn": _ARN}


def test_agents_env_vars_have_no_plaintext_key_and_arn_only_on_detection(deploy):
    for agent in deploy.AGENTS:
        assert "TXN_REF_HMAC_KEY" not in agent["env_vars"], agent["name"]
    with_arn = [a["name"] for a in deploy.AGENTS if "TXN_REF_HMAC_SECRET_ARN" in a["env_vars"]]
    assert with_arn == ["DetectionAgent"]


def test_source_has_no_plaintext_key_env_assignment():
    with open(os.path.join(CDK_ROOT, "deploy_agentcore_runtimes.py"), encoding="utf-8") as f:
        code = f.read()
    assert '["TXN_REF_HMAC_KEY"] =' not in code
    assert '"TXN_REF_HMAC_KEY": ' not in code


@pytest.mark.parametrize("outputs", [
    {"GuardrailId": "gr-123", "GuardrailVersion": "3"},
    {"GuardrailId": "gr-123", "GuardrailVersion": "3", "TxnRefHmacSecretArn": ""},
], ids=["missing", "empty"])
def test_missing_secret_arn_output_exits_before_any_deploy(deploy, monkeypatch, tmp_path, outputs):
    deployed = []
    with pytest.raises(SystemExit) as info:
        _drive_main(deploy, monkeypatch, tmp_path, outputs, deployed)
    assert info.value.code == 1
    assert deployed == []


def test_present_secret_arn_goes_to_detection_agent_only(deploy, monkeypatch, tmp_path):
    deployed = _drive_main(deploy, monkeypatch, tmp_path, _GOOD_OUTPUTS)
    envs = dict(deployed)
    assert set(envs) == {"DetectionAgent", "ComplianceAgent", "ExecutorAgent"}
    assert envs["DetectionAgent"]["TXN_REF_HMAC_SECRET_ARN"] == _ARN
    assert "TXN_REF_HMAC_SECRET_ARN" not in envs["ComplianceAgent"]
    assert "TXN_REF_HMAC_SECRET_ARN" not in envs["ExecutorAgent"]
    for name, env in envs.items():
        assert "TXN_REF_HMAC_KEY" not in env, name


def test_guardrail_fail_closed_exit_unchanged(deploy, monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as info:
        _drive_main(deploy, monkeypatch, tmp_path, {"TxnRefHmacSecretArn": _ARN})
    assert info.value.code == 1


def test_plaintext_key_in_deploy_environment_is_ignored(deploy, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("TXN_REF_HMAC_KEY", "super-secret-plaintext-key-value")
    deployed = _drive_main(deploy, monkeypatch, tmp_path, _GOOD_OUTPUTS)
    out = capsys.readouterr().out
    assert "TXN_REF_HMAC_KEY" in out and "ignored" in out
    assert "super-secret-plaintext-key-value" not in out
    for name, env in deployed:
        assert "TXN_REF_HMAC_KEY" not in env
        assert "super-secret-plaintext-key-value" not in env.values()


def test_deploy_agent_tripwire_exits_before_any_boto3_call(deploy, monkeypatch, tmp_path):
    boto3_calls = []

    def forbidden_client(*args, **kwargs):
        boto3_calls.append(args)
        raise AssertionError("boto3.client must not be called")

    monkeypatch.setattr(deploy.boto3, "client", forbidden_client)
    config = copy.deepcopy(deploy.AGENTS[0])
    config["env_vars"]["TXN_REF_HMAC_KEY"] = "anything"
    with pytest.raises(SystemExit) as info:
        deploy.deploy_agent(config, tmp_path / "x.zip", "bucket", "123456789012")
    assert info.value.code == 1
    assert boto3_calls == []
