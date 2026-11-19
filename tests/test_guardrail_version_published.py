"""
Test: AgentsStack publishes a real CfnGuardrailVersion.

Before this fix, cdk/deploy_agentcore_runtimes.py always pinned the
deployed runtime's GUARDRAIL_VERSION env var to the hardcoded string "1",
but cdk/agents_stack.py never created a CfnGuardrailVersion resource — no
version "1" (or any version) of the guardrail ever actually existed.
Guardrailed Bedrock Converse calls (lambdas/compliance_agent/handler.py,
which now sends guardrailConfig on every call) either failed closed
outright against a nonexistent version, or silently fell back to the
mutable DRAFT guardrail — so version pinning was never actually enforced
either way.

These tests synthesize the real AgentsStack (same subprocess pattern as
test_alarm_metric_math_floor.py, since AgentsStack resolves Lambda code
assets relative to cwd=cdk/) and assert a CfnGuardrailVersion resource
exists, referencing the guardrail, with its version exported as a stack
output for deploy_agentcore_runtimes.py to consume.
"""
import json
import os
import subprocess
import sys

import pytest
from aws_cdk.assertions import Template

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
        cwd=CDK_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"AgentsStack failed to synthesize:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    template_json = json.loads(result.stdout.strip().splitlines()[-1])
    return Template.from_json(template_json)


class TestGuardrailVersionPublished:
    def test_guardrail_resource_exists(self, template):
        template.resource_count_is("AWS::Bedrock::Guardrail", 1)

    def test_guardrail_version_resource_exists(self, template):
        """A CfnGuardrailVersion must actually exist now — this is the
        resource the prior code never created."""
        template.resource_count_is("AWS::Bedrock::GuardrailVersion", 1)

    def test_guardrail_version_references_the_guardrail(self, template):
        versions = template.find_resources("AWS::Bedrock::GuardrailVersion")
        assert len(versions) == 1
        (resource,) = versions.values()
        guardrail_identifier = resource["Properties"]["GuardrailIdentifier"]
        # Must be a CFN intrinsic reference to the guardrail resource (its
        # GuardrailId attribute), not a literal string — i.e. it's actually
        # wired to the real guardrail, not independently hardcoded.
        assert isinstance(guardrail_identifier, dict)

    def test_guardrail_version_exported_as_stack_output(self, template):
        """deploy_agentcore_runtimes.py reads GuardrailVersion from the
        stack outputs — it must be exported, and its value must come from
        the GuardrailVersion resource's real Version attribute, not a
        literal "1"."""
        outputs = template.to_json().get("Outputs", {})
        assert "GuardrailVersion" in outputs
        value = outputs["GuardrailVersion"]["Value"]
        assert value != "1"
        assert isinstance(value, dict)  # an Fn::GetAtt / Ref intrinsic


class TestDeployScriptNoLongerHardcodesVersion:
    def test_deploy_script_does_not_hardcode_guardrail_version_1(self):
        deploy_script_path = os.path.join(CDK_ROOT, "deploy_agentcore_runtimes.py")
        with open(deploy_script_path, encoding="utf-8") as f:
            code = f.read()
        assert 'os.environ.get("GUARDRAIL_VERSION", "1")' not in code

    def test_deploy_script_reads_guardrail_version_from_stack_outputs(self):
        deploy_script_path = os.path.join(CDK_ROOT, "deploy_agentcore_runtimes.py")
        with open(deploy_script_path, encoding="utf-8") as f:
            code = f.read()
        assert 'agents_outputs.get("GuardrailVersion"' in code
