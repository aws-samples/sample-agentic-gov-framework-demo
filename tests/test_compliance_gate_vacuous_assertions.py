"""
Test: Compliance Gate — vacuous/tautological assertions replaced with
checks against real deployed/published state.

Two sub-findings:
1. check_access_control's role-distinctness assertion used to compute
   len(set(roles)) == 3 over three local string literals — always true,
   never inspecting deployed IAM. It must now resolve the three agents'
   real IAM role ARNs and assert distinctness over those, failing closed
   if any role cannot be resolved.
2. check_model_governance's guardrail assertion used to only check
   bool(guardrail_id) from the deployed runtime — never comparing it
   against what the FsiComplianceAgents stack itself published. It must
   now also assert the deployed (guardrail_id, guardrail_version) pair
   matches the stack's own GuardrailId/GuardrailVersion outputs.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import compliance_gate as gate_module


class TestRoleDistinctnessUsesLiveIam:
    def test_aws_unreachable_fails_closed_not_vacuously_true(self, monkeypatch):
        """If IAM cannot be reached at all, the assertion must FAIL — not
        fall back to the old literal-string distinctness check."""
        import boto3 as real_boto3_module
        fake_iam = MagicMock()
        fake_iam.get_role.side_effect = RuntimeError("no credentials")
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_iam)

        role_arns, source = gate_module.resolve_deployed_agent_role_arns()
        assert role_arns == {}

        gate = gate_module.ComplianceGate()
        gate.check_access_control()
        matches = [r for r in gate.results if "distinct deployed IAM role ARNs" in r["description"]]
        assert len(matches) == 1
        assert matches[0]["passed"] is False

    def test_role_not_found_fails_closed(self, monkeypatch):
        """A role missing from IAM (not yet deployed) must FAIL, not be
        silently excluded from the distinctness set."""
        import boto3 as real_boto3_module

        class _NoSuchEntity(Exception):
            pass

        fake_iam = MagicMock()
        fake_iam.exceptions.NoSuchEntityException = _NoSuchEntity

        def fake_get_role(RoleName):
            if RoleName == "executor-agent-role":
                raise _NoSuchEntity()
            return {"Role": {"Arn": f"arn:aws:iam::123456789012:role/{RoleName}"}}

        fake_iam.get_role.side_effect = fake_get_role
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_iam)

        role_arns, source = gate_module.resolve_deployed_agent_role_arns()
        assert "executor-agent-role" not in role_arns
        assert len(role_arns) == 2

    def test_three_distinct_deployed_roles_pass(self, monkeypatch):
        """When all three roles resolve to distinct ARNs, the assertion
        passes based on the real resolved ARNs."""
        import boto3 as real_boto3_module

        class _NoSuchEntity(Exception):
            pass

        fake_iam = MagicMock()
        fake_iam.exceptions.NoSuchEntityException = _NoSuchEntity
        fake_iam.get_role.side_effect = lambda RoleName: {
            "Role": {"Arn": f"arn:aws:iam::123456789012:role/{RoleName}"}
        }
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_iam)

        role_arns, source = gate_module.resolve_deployed_agent_role_arns()
        assert len(role_arns) == 3
        assert len(set(role_arns.values())) == 3

    def test_duplicate_role_arns_would_fail(self, monkeypatch):
        """Regression guard: if two of the three agents somehow resolved
        to the SAME underlying role ARN, the distinctness assertion must
        catch it — the old literal-string check could never have caught
        this because it never inspected deployed IAM at all."""
        import boto3 as real_boto3_module

        shared_arn = "arn:aws:iam::123456789012:role/shared-role"
        fake_iam = MagicMock()
        fake_iam.get_role.side_effect = lambda RoleName: {
            "Role": {"Arn": shared_arn if RoleName != "executor-agent-role" else "arn:aws:iam::123456789012:role/executor-agent-role"}
        }
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_iam)

        role_arns, source = gate_module.resolve_deployed_agent_role_arns()
        assert len(role_arns) == 3
        assert len(set(role_arns.values())) == 2  # two roles collapsed onto one ARN

        gate = gate_module.ComplianceGate()
        gate.check_access_control()
        matches = [r for r in gate.results if "distinct deployed IAM role ARNs" in r["description"]]
        assert len(matches) == 1
        assert matches[0]["passed"] is False


class TestGuardrailMatchesPublishedStackOutput:
    def test_resolve_published_guardrail_reads_stack_outputs(self, monkeypatch):
        import boto3 as real_boto3_module
        fake_cfn = MagicMock()
        fake_cfn.describe_stacks.return_value = {
            "Stacks": [{"Outputs": [
                {"OutputKey": "GuardrailId", "OutputValue": "gr-published"},
                {"OutputKey": "GuardrailVersion", "OutputValue": "3"},
            ]}]
        }
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_cfn)

        guardrail_id, guardrail_version, source = gate_module.resolve_published_guardrail()
        assert guardrail_id == "gr-published"
        assert guardrail_version == "3"

    def test_stack_unreachable_fails_closed(self, monkeypatch):
        import boto3 as real_boto3_module
        fake_cfn = MagicMock()
        fake_cfn.describe_stacks.side_effect = RuntimeError("stack not found")
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_cfn)

        guardrail_id, guardrail_version, source = gate_module.resolve_published_guardrail()
        assert guardrail_id == ""
        assert guardrail_version == ""

    def test_mismatched_deployed_and_published_guardrail_fails(self, monkeypatch):
        """Core regression test: a deployed runtime configured with a
        non-empty but DIFFERENT guardrail than the stack published must
        FAIL — the old bool()-only check would have passed this."""
        import boto3 as real_boto3_module

        fake_agentcore = MagicMock()
        fake_agentcore.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeName": "ComplianceAgent", "agentRuntimeId": "rt-1"}]
        }
        fake_agentcore.get_agent_runtime.return_value = {
            "environmentVariables": {"GUARDRAIL_ID": "gr-stale", "GUARDRAIL_VERSION": "1"}
        }

        fake_cfn = MagicMock()
        fake_cfn.describe_stacks.return_value = {
            "Stacks": [{"Outputs": [
                {"OutputKey": "GuardrailId", "OutputValue": "gr-current"},
                {"OutputKey": "GuardrailVersion", "OutputValue": "2"},
            ]}]
        }

        def fake_client(service_name, region_name=None):
            return {
                "bedrock-agentcore-control": fake_agentcore,
                "cloudformation": fake_cfn,
            }[service_name]

        monkeypatch.setattr(real_boto3_module, "client", fake_client)

        gate = gate_module.ComplianceGate()
        gate.check_model_governance()

        matches = [r for r in gate.results if "matches the" in r["description"] and "Guardrail" in r["description"]]
        assert len(matches) == 1
        assert matches[0]["passed"] is False

    def test_matching_deployed_and_published_guardrail_passes(self, monkeypatch):
        import boto3 as real_boto3_module

        fake_agentcore = MagicMock()
        fake_agentcore.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeName": "ComplianceAgent", "agentRuntimeId": "rt-1"}]
        }
        fake_agentcore.get_agent_runtime.return_value = {
            "environmentVariables": {"GUARDRAIL_ID": "gr-current", "GUARDRAIL_VERSION": "2"}
        }

        fake_cfn = MagicMock()
        fake_cfn.describe_stacks.return_value = {
            "Stacks": [{"Outputs": [
                {"OutputKey": "GuardrailId", "OutputValue": "gr-current"},
                {"OutputKey": "GuardrailVersion", "OutputValue": "2"},
            ]}]
        }

        def fake_client(service_name, region_name=None):
            return {
                "bedrock-agentcore-control": fake_agentcore,
                "cloudformation": fake_cfn,
            }[service_name]

        monkeypatch.setattr(real_boto3_module, "client", fake_client)

        gate = gate_module.ComplianceGate()
        gate.check_model_governance()

        matches = [r for r in gate.results if "matches the" in r["description"] and "Guardrail" in r["description"]]
        assert len(matches) == 1
        assert matches[0]["passed"] is True
