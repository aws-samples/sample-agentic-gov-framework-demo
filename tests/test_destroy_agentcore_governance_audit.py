"""
Test: cdk/destroy_agentcore_runtimes.py — teardown never silently clears a
governance hold.

`make destroy` checks the hold BEFORE any runtime teardown. A hold is never
released here (release needs two verified people, or the out-of-band
runbook): an active hold, or a hold state that can't be read, aborts before
any runtime is listed or deleted, and the script never touches IAM policy
attachments or the breaker Lambda.
"""
import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def _load_destroy_script_module():
    """Load cdk/destroy_agentcore_runtimes.py by explicit file path, the
    same way the script itself loads other modules by path — avoids any
    sys.path/package-name friction for a script outside a package."""
    path = os.path.join(PROJECT_ROOT, "cdk", "destroy_agentcore_runtimes.py")
    spec = importlib.util.spec_from_file_location("destroy_agentcore_runtimes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def destroy_module():
    return _load_destroy_script_module()


DENY_ARN = "arn:aws:iam::123456789012:policy/governance-hold-deny-all"


def _fake_iam(held, error=None):
    iam = MagicMock()

    def list_attached(RoleName):
        if error is not None:
            raise error
        return {"AttachedPolicies": [{"PolicyArn": DENY_ARN}] if RoleName in held else []}

    iam.list_attached_role_policies.side_effect = list_attached
    return iam


class TestGovernanceHoldCheckedBeforeTeardown:
    def _install(self, destroy_module, monkeypatch, fake_iam, call_order):
        fake_agentcore = MagicMock()

        def fake_list_runtimes(**kwargs):
            call_order.append("list_runtimes")
            return {"agentRuntimes": []}

        fake_agentcore.list_agent_runtimes.side_effect = fake_list_runtimes
        original = fake_iam.list_attached_role_policies.side_effect

        def recording(RoleName):
            call_order.append("hold_check")
            return original(RoleName)

        fake_iam.list_attached_role_policies.side_effect = recording
        fake_lambda = MagicMock()
        fake_sts = MagicMock()
        fake_sts.get_caller_identity.return_value = {"Account": "123456789012"}
        monkeypatch.setattr(destroy_module.boto3, "client", lambda service_name, region_name=None: {
            "lambda": fake_lambda, "bedrock-agentcore-control": fake_agentcore, "iam": fake_iam,
            "sts": fake_sts,
        }[service_name])
        # Ignored: the deny ARN is derived from the caller's account.
        monkeypatch.setenv("DENY_POLICY_ARN", "arn:aws:iam::123456789012:policy/attacker-chosen")
        return fake_agentcore, fake_lambda

    def test_hold_check_happens_before_runtime_listing(self, destroy_module, monkeypatch):
        call_order = []
        fake_iam = _fake_iam([])
        fake_agentcore, fake_lambda = self._install(destroy_module, monkeypatch, fake_iam, call_order)
        destroy_module.main()
        assert call_order == ["hold_check"] * 3 + ["list_runtimes"]
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_not_called()

    def test_active_hold_aborts_before_runtime_teardown(self, destroy_module, monkeypatch):
        call_order = []
        fake_iam = _fake_iam(["compliance-agent-role"])
        fake_agentcore, fake_lambda = self._install(destroy_module, monkeypatch, fake_iam, call_order)
        with pytest.raises(SystemExit) as exc_info:
            destroy_module.main()
        assert exc_info.value.code != 0
        fake_agentcore.list_agent_runtimes.assert_not_called()
        fake_agentcore.delete_agent_runtime.assert_not_called()
        fake_iam.detach_role_policy.assert_not_called()
        fake_lambda.invoke.assert_not_called()

    def test_unreadable_hold_state_aborts_without_detaching(self, destroy_module, monkeypatch):
        call_order = []
        fake_iam = _fake_iam([], error=RuntimeError("no network"))
        fake_agentcore, fake_lambda = self._install(destroy_module, monkeypatch, fake_iam, call_order)
        with pytest.raises(SystemExit) as exc_info:
            destroy_module.main()
        assert exc_info.value.code != 0
        fake_agentcore.list_agent_runtimes.assert_not_called()
        fake_iam.detach_role_policy.assert_not_called()
