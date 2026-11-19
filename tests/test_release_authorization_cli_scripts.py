"""
Test: release authorization in the CLI/teardown scripts.

scripts/ensure_agents_enabled.py and cdk/destroy_agentcore_runtimes.py must
NEVER call iam.detach_role_policy themselves. A release is a two-person
request/approve against the human breaker entry point
(fsi-circuit-breaker-human), each step carrying the caller's own presigned
sts:GetCallerIdentity proof, which the Lambda verifies and classifies
server-side. Teardown never releases a hold at all: it aborts while one is
active. A rejection always aborts.
"""
import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock

import pytest
from botocore.credentials import Credentials

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

AUTHORIZED_ARN = "arn:aws:sts::123456789012:assumed-role/fsi-breaker-approver/bob"
REQUEST_ID = "0" * 8 + "-0000-4000-8000-" + "0" * 12


def _load_module(relative_path, module_name):
    path = os.path.join(PROJECT_ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def ensure_module():
    return _load_module("scripts/ensure_agents_enabled.py", "ensure_agents_enabled")


@pytest.fixture
def destroy_module():
    return _load_module("cdk/destroy_agentcore_runtimes.py", "destroy_agentcore_runtimes")


def _fake_iam_with_held_roles(deny_policy_arn, roles):
    iam = MagicMock()

    class _NoSuchEntity(Exception):
        pass

    iam.exceptions.NoSuchEntityException = _NoSuchEntity

    def fake_list_attached(RoleName):
        if RoleName in roles:
            return {"AttachedPolicies": [{"PolicyArn": deny_policy_arn}]}
        return {"AttachedPolicies": []}

    iam.list_attached_role_policies.side_effect = fake_list_attached
    return iam


def _fake_sts(account="123456789012"):
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Account": account}
    return sts


# Governance-target overrides the scripts used to honor; setting them must
# have no effect.
TARGET_OVERRIDES = {
    "DENY_POLICY_ARN": "arn:aws:iam::123456789012:policy/attacker-chosen",
    "DETECTION_ROLE": "decoy-role", "COMPLIANCE_ROLE": "decoy-role", "EXECUTOR_ROLE": "decoy-role",
    "CIRCUIT_BREAKER_HUMAN_FUNCTION": "decoy-function",
}


def _fake_lambda_invoke_returning(result_dict):
    lambda_client = MagicMock()
    payload_mock = MagicMock()
    payload_mock.read.return_value = json.dumps(result_dict).encode("utf-8")
    lambda_client.invoke.return_value = {"Payload": payload_mock}
    return lambda_client


class _FakeSession:
    """boto3.Session stand-in: real static credentials for presign_identity
    (no network), a fake lambda client for the invoke."""

    def __init__(self, lambda_client, iam=None):
        self.lambda_client, self.iam = lambda_client, iam or MagicMock()

    def get_credentials(self):
        return Credentials("AKIDEXAMPLE", "secret")

    def client(self, service, **kwargs):
        return {"lambda": self.lambda_client, "iam": self.iam}[service]


def _run_ensure(ensure_module, monkeypatch, argv, lambda_result):
    fake_iam = MagicMock()
    fake_lambda = _fake_lambda_invoke_returning(lambda_result)
    monkeypatch.setattr(ensure_module.boto3, "Session", lambda: _FakeSession(fake_lambda, fake_iam))
    monkeypatch.setattr(ensure_module.boto3, "client", lambda *a, **k: fake_iam)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    for name, value in TARGET_OVERRIDES.items():  # ignored
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["ensure_agents_enabled.py", *argv])
    return ensure_module.main(), fake_iam, fake_lambda


class TestEnsureAgentsEnabledNeverCallsIamDetachDirectly:
    """Release must go through the circuit breaker Lambda, not
    a direct detach_role_policy call from this script's own process."""

    def test_rejected_release_never_calls_iam_detach(self, ensure_module, monkeypatch):
        result, fake_iam, fake_lambda = _run_ensure(
            ensure_module, monkeypatch, ["--approve-release", REQUEST_ID],
            {"status": "REJECTED", "http_status": 403, "code": "SECOND_APPROVER_REQUIRED"})
        assert result != 0
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_called_once()
        kwargs = fake_lambda.invoke.call_args.kwargs
        assert kwargs["FunctionName"] == "fsi-circuit-breaker-human"
        payload = json.loads(kwargs["Payload"])
        assert payload["action"] == "approve_release" and payload["release_request_id"] == REQUEST_ID
        assert payload["caller_identity_nonce"].startswith(f"v1:approve_release:{REQUEST_ID}:")
        assert "X-Amz-SignedHeaders=host%3Bx-fsi-breaker-nonce" in payload["caller_identity_presigned_url"]

    def test_approved_release_never_calls_iam_detach_directly_either(self, ensure_module, monkeypatch):
        """Even on a SUCCESSFUL release, this script itself must never call
        iam.detach_role_policy — only the circuit breaker Lambda does."""
        result, fake_iam, fake_lambda = _run_ensure(
            ensure_module, monkeypatch, ["--approve-release", REQUEST_ID],
            {"status": "ACTIVE", "message": "All agents re-enabled", "released_by": AUTHORIZED_ARN})
        assert result == 0
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_called_once()

    @pytest.mark.parametrize("failures, expected", [
        ({}, "A newer hold superseded this release; the hold was restored."),
        ({"executor-agent-role": {"error_id": "e", "error_class": "Throttling"}},
         "A newer hold superseded this release; re-attach FAILED on executor-agent-role; re-trip now")])
    def test_superseded_release_exits_3(self, ensure_module, monkeypatch, capsys, failures, expected):
        result, fake_iam, _ = _run_ensure(
            ensure_module, monkeypatch, ["--approve-release", REQUEST_ID],
            {"status": "GOVERNANCE_HOLD", "code": "RELEASE_SUPERSEDED", "http_status": 409,
             "newer_hold_detected": True, "reattach_failures": failures})
        assert result == 3 and expected in capsys.readouterr().out
        fake_iam.detach_role_policy.assert_not_called()

    def test_superseded_before_detach_exits_1_with_the_code(self, ensure_module, monkeypatch, capsys):
        result, _, _ = _run_ensure(
            ensure_module, monkeypatch, ["--approve-release", REQUEST_ID],
            {"status": "GOVERNANCE_HOLD", "code": "RELEASE_SUPERSEDED", "http_status": 409,
             "message": "A newer hold superseded this release; nothing was detached."})
        assert result == 1 and "NOT released: RELEASE_SUPERSEDED" in capsys.readouterr().out

    def test_request_release_prints_id_and_never_detaches(self, ensure_module, monkeypatch, capsys):
        result, fake_iam, fake_lambda = _run_ensure(
            ensure_module, monkeypatch, ["--request-release"],
            {"status": "RELEASE_PENDING", "release_request_id": REQUEST_ID, "http_status": 202})
        assert result == 0 and REQUEST_ID in capsys.readouterr().out
        payload = json.loads(fake_lambda.invoke.call_args.kwargs["Payload"])
        assert payload["action"] == "request_release"
        assert payload["caller_identity_nonce"].startswith("v1:request_release:active-hold:")
        fake_iam.detach_role_policy.assert_not_called()

    @pytest.mark.parametrize("argv", [["--approve-release", "not-a-request-id"],
                                      ["--request-release", "--approve-release", REQUEST_ID],
                                      ["--force-release"]])
    def test_bad_arguments_abort_without_invoking(self, ensure_module, monkeypatch, argv):
        result, fake_iam, fake_lambda = _run_ensure(ensure_module, monkeypatch, argv, {"status": "ACTIVE"})
        assert result == 2
        fake_lambda.invoke.assert_not_called()
        fake_iam.detach_role_policy.assert_not_called()

    def test_no_hold_detected_skips_release_entirely(self, ensure_module, monkeypatch):
        """When no role carries the deny policy, the script must not even
        attempt a circuit breaker invocation."""
        deny_policy_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
        fake_iam = _fake_iam_with_held_roles(deny_policy_arn, [])  # nothing held
        fake_lambda = MagicMock()

        def fake_boto3_client(service_name, region_name=None):
            return {"iam": fake_iam, "lambda": fake_lambda, "sts": _fake_sts()}[service_name]

        monkeypatch.setattr(ensure_module.boto3, "client", fake_boto3_client)
        monkeypatch.setattr(sys, "argv", ["ensure_agents_enabled.py"])

        result = ensure_module.main()

        assert result == 0
        fake_lambda.invoke.assert_not_called()

    def test_detected_hold_is_not_released_by_default(self, ensure_module, monkeypatch):
        deny_policy_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
        fake_iam = _fake_iam_with_held_roles(deny_policy_arn, ensure_module.AGENT_ROLES)
        fake_lambda = MagicMock()
        monkeypatch.setattr(ensure_module.boto3, "client",
                            lambda service_name, region_name=None: {
                                "iam": fake_iam, "lambda": fake_lambda, "sts": _fake_sts()}[service_name])
        monkeypatch.setattr(sys, "argv", ["ensure_agents_enabled.py"])
        assert ensure_module.main() == 1
        fake_lambda.invoke.assert_not_called()
        fake_iam.detach_role_policy.assert_not_called()

    def test_target_env_overrides_have_no_effect(self, ensure_module, monkeypatch):
        """DENY_POLICY_ARN / role-name env vars cannot hide a hold: the deny
        ARN comes from the caller's account plus the fixed name, and the
        roles are the fixed agent roles."""
        deny_policy_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
        fake_iam = _fake_iam_with_held_roles(deny_policy_arn, ["executor-agent-role"])
        monkeypatch.setattr(ensure_module.boto3, "client",
                            lambda service_name, region_name=None: {
                                "iam": fake_iam, "lambda": MagicMock(), "sts": _fake_sts()}[service_name])
        for name, value in TARGET_OVERRIDES.items():
            monkeypatch.setenv(name, value)
        monkeypatch.setattr(sys, "argv", ["ensure_agents_enabled.py"])
        assert ensure_module.main() == 1  # the real hold is still detected
        checked = [c.kwargs["RoleName"] for c in fake_iam.list_attached_role_policies.call_args_list]
        assert set(checked) == {"detection-agent-role", "compliance-agent-role", "executor-agent-role"}
        assert ensure_module.AGENT_ROLES == [
            "detection-agent-role", "compliance-agent-role", "executor-agent-role"]


class TestDestroyAgentcoreRuntimesNeverCallsIamDetachDirectly:
    """Teardown never releases (or detaches) anything; a hold aborts it."""

    def _clients(self, destroy_module, monkeypatch, held):
        deny_policy_arn = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"
        fake_iam = _fake_iam_with_held_roles(deny_policy_arn, held)
        fake_agentcore = MagicMock()
        fake_agentcore.list_agent_runtimes.return_value = {"agentRuntimes": []}
        fake_lambda = MagicMock()
        monkeypatch.setattr(destroy_module.boto3, "client", lambda service_name, region_name=None: {
            "iam": fake_iam, "bedrock-agentcore-control": fake_agentcore, "lambda": fake_lambda,
            "sts": _fake_sts(),
        }[service_name])
        for name, value in TARGET_OVERRIDES.items():  # ignored
            monkeypatch.setenv(name, value)
        return fake_iam, fake_agentcore, fake_lambda

    def test_active_hold_aborts_without_detach_or_release(self, destroy_module, monkeypatch, capsys):
        fake_iam, fake_agentcore, fake_lambda = self._clients(
            destroy_module, monkeypatch, destroy_module.AGENT_ROLES[:1])
        with pytest.raises(SystemExit) as exc_info:
            destroy_module.main()
        assert exc_info.value.code != 0
        assert "make release-request" in capsys.readouterr().out
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_not_called()
        fake_agentcore.list_agent_runtimes.assert_not_called()

    def test_no_hold_proceeds_without_detach_or_release(self, destroy_module, monkeypatch):
        fake_iam, fake_agentcore, fake_lambda = self._clients(destroy_module, monkeypatch, [])
        destroy_module.main()
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_not_called()
        fake_agentcore.list_agent_runtimes.assert_called()
