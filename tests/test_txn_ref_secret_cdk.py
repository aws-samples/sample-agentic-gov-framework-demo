"""
Test: txn_ref HMAC key lives in a CDK-generated Secrets Manager secret.

Synthesizes the real AgentsStack (same subprocess approach as
tests/test_iam_executor_lease_grant.py, since Lambda assets resolve relative
to cwd=cdk/) and asserts:
  - exactly one generated secret and no SecretString in the template;
  - exactly one GetSecretValue statement, scoped to that secret, on
    detection-agent-role and pan-filter-role only;
  - fsi-pan-filter runs python3.13 with TXN_REF_HMAC_SECRET_ARN as a Ref;
  - no plaintext TXN_REF_HMAC_KEY environment variable anywhere;
  - the TxnRefHmacSecretArn output exists;
  - the circuit breaker runtime is python3.13 (cdk_nag AwsSolutions-L1).
"""
import json
import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")

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


def _secretsmanager_statements(statements):
    return [
        s for s in statements
        if any(a.lower().startswith("secretsmanager:") or a == "*" for a in _as_list(s["Action"]))
    ]


@pytest.fixture(scope="module")
def secret_id(template):
    secrets = _resources(template, "AWS::SecretsManager::Secret")
    assert len(secrets) == 1, list(secrets)
    return next(iter(secrets))


def test_exactly_one_generated_secret_without_a_value(template, secret_id):
    props = template["Resources"][secret_id]["Properties"]
    assert "GenerateSecretString" in props
    assert "SecretString" not in props
    gen = props["GenerateSecretString"]
    assert gen["PasswordLength"] == 64
    assert gen["ExcludePunctuation"] is True
    assert gen["IncludeSpace"] is False
    assert "Name" not in props  # no fixed name: destroy + redeploy cannot collide
    assert "txn_ref HMAC key" in props["Description"]
    assert "KmsKeyId" not in props  # default aws/secretsmanager key
    assert template["Resources"][secret_id]["DeletionPolicy"] == "Retain"


@pytest.mark.parametrize("role_name", ["detection-agent-role", "pan-filter-role"])
def test_pan_filter_importing_roles_have_one_scoped_get_secret_value(template, secret_id, role_name):
    sm = [
        s for s in _role_statements(template, role_name)
        if s.get("Effect") == "Allow"
        and any(a.lower().startswith("secretsmanager:") for a in _as_list(s["Action"]))
    ]
    assert len(sm) == 1, sm
    assert _as_list(sm[0]["Action"]) == ["secretsmanager:GetSecretValue"]
    assert _as_list(sm[0]["Resource"]) == [{"Ref": secret_id}]
    assert "Condition" not in sm[0]


@pytest.mark.parametrize(
    "role_name", ["compliance-agent-role", "executor-agent-role", "circuit-breaker-role"]
)
def test_other_roles_have_no_secretsmanager_access(template, role_name):
    statements = _role_statements(template, role_name)
    assert statements, f"{role_name} has no statements — role lookup broken"
    assert _secretsmanager_statements(statements) == []


def test_no_secret_resource_policy_widens_access(template):
    assert _resources(template, "AWS::SecretsManager::ResourcePolicy") == {}


def test_pan_filter_function_runtime_and_secret_arn_env(template, secret_id):
    fn_id = _logical_id(template, "AWS::Lambda::Function", "FunctionName", "fsi-pan-filter")
    props = template["Resources"][fn_id]["Properties"]
    assert props["Runtime"] == "python3.13"
    assert props["Environment"]["Variables"] == {"TXN_REF_HMAC_SECRET_ARN": {"Ref": secret_id}}


def test_circuit_breaker_runtime_python313(template):
    fn_id = _logical_id(template, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    assert template["Resources"][fn_id]["Properties"]["Runtime"] == "python3.13"
    variables = template["Resources"][fn_id]["Properties"]["Environment"]["Variables"]
    assert "TXN_REF_HMAC_SECRET_ARN" not in variables


def test_no_plaintext_txn_ref_key_env_var_anywhere(template, secret_id):
    for lid, res in _resources(template, "AWS::Lambda::Function").items():
        variables = res["Properties"].get("Environment", {}).get("Variables", {})
        assert "TXN_REF_HMAC_KEY" not in variables, lid
        for name, value in variables.items():
            if name == "TXN_REF_HMAC_SECRET_ARN":
                assert value == {"Ref": secret_id}
    assert "TXN_REF_HMAC_KEY" not in json.dumps(template)


def test_secret_arn_output_exists(template, secret_id):
    outputs = template["Outputs"]
    assert outputs["TxnRefHmacSecretArn"]["Value"] == {"Ref": secret_id}
