"""
Test: Compliance Gate — resolve_deployed_guardrail_id().

The gate's guardrail-attachment assertion must only ever pass based on a
value read from the deployed AgentCore Runtime. An earlier fix that stopped
grepping handler source for guardrail strings was supposed to close the vacuous-pass gap entirely, but left a
fallback to this process's own GUARDRAIL_ID environment variable on any AWS
lookup failure — so `GUARDRAIL_ID=anything make gate` satisfied the
assertion without the gate ever contacting AWS. These tests are
adversarial: they assert the env var is never consulted, under every
failure mode (no credentials, API error, runtime not found).
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import compliance_gate as gate_module


class TestResolveDeployedGuardrailIdNoEnvFallback:
    def test_aws_lookup_failure_does_not_fall_back_to_env(self, monkeypatch):
        """If boto3.client() raises (no credentials / no AWS access), the
        function must return an empty guardrail_id — NOT fall back to
        reading GUARDRAIL_ID from os.environ."""
        monkeypatch.setenv("GUARDRAIL_ID", "attacker-supplied-value")

        fake_boto3 = MagicMock()
        fake_boto3.client.side_effect = RuntimeError("no credentials")
        monkeypatch.setattr(gate_module, "boto3", fake_boto3, raising=False)
        # resolve_deployed_guardrail_id does `import boto3` inline — patch
        # the module actually imported.
        import boto3 as real_boto3_module
        monkeypatch.setattr(real_boto3_module, "client", fake_boto3.client)

        guardrail_id, source = gate_module.resolve_deployed_guardrail_id()
        assert guardrail_id == ""
        assert "attacker-supplied-value" not in guardrail_id

    def test_runtime_not_found_does_not_fall_back_to_env(self, monkeypatch):
        """If the ComplianceAgent runtime simply isn't in the list, the
        function must return "" — not substitute the env var."""
        monkeypatch.setenv("GUARDRAIL_ID", "attacker-supplied-value")

        fake_client = MagicMock()
        fake_client.list_agent_runtimes.return_value = {"agentRuntimes": []}
        import boto3 as real_boto3_module
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_client)

        guardrail_id, source = gate_module.resolve_deployed_guardrail_id()
        assert guardrail_id == ""

    def test_deployed_runtime_value_is_used_when_reachable(self, monkeypatch):
        """When the deployed runtime IS reachable, its own configured
        GUARDRAIL_ID is used — confirming the happy path still works after
        removing the fallback."""
        fake_client = MagicMock()
        fake_client.list_agent_runtimes.return_value = {
            "agentRuntimes": [{"agentRuntimeName": "ComplianceAgent", "agentRuntimeId": "rt-123"}]
        }
        fake_client.get_agent_runtime.return_value = {
            "environmentVariables": {"GUARDRAIL_ID": "gr-real-deployed-id"}
        }
        import boto3 as real_boto3_module
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_client)

        guardrail_id, source = gate_module.resolve_deployed_guardrail_id()
        assert guardrail_id == "gr-real-deployed-id"
        assert source == "deployed AgentCore Runtime"

    def test_gate_assertion_fails_closed_despite_env_var_set(self, monkeypatch):
        """Full adversarial repro: GUARDRAIL_ID=anything must
        NOT satisfy the compliance gate's assertion when AWS is unreachable."""
        monkeypatch.setenv("GUARDRAIL_ID", "anything")

        import boto3 as real_boto3_module
        fake_client = MagicMock()
        fake_client.list_agent_runtimes.side_effect = RuntimeError("no AWS access in this env")
        monkeypatch.setattr(real_boto3_module, "client", lambda *a, **k: fake_client)

        gate = gate_module.ComplianceGate()
        gate.check_model_governance()

        governance_results = [
            r for r in gate.results
            if "GUARDRAIL_ID configured" in r["description"]
        ]
        assert len(governance_results) == 1
        assert governance_results[0]["passed"] is False
