"""
Shared CDK synth helper for the governance CDK tests.

Same subprocess pattern as tests/test_cdk_nag_fixes.py (Lambda assets
resolve relative to cwd=cdk/), cached per context set for the whole test
session so test_read_scoping_cdk.py and test_governance_iam_cdk.py share
one synth per context variant. Local synth only; nothing is deployed.
"""
import functools
import json
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")

DEFAULT_CONTEXT = {}
FULL_CONTEXT = {
    "allow_console_drift_injection": "true",
    "console_host_role_arn": "arn:aws:iam::123456789012:role/console-host",
    "ci_role_arn": "arn:aws:iam::123456789012:role/ci",
}

_SYNTH_SCRIPT = """
import json, sys
from aws_cdk import App
from aws_cdk.assertions import Template
from agents_stack import AgentsStack
from data_stack import DataStack
app = App(context=json.loads(sys.argv[1]))
data = DataStack(app, "TestFsiComplianceData")
agents = AgentsStack(app, "TestFsiComplianceAgents", data_stack=data)
print(json.dumps({"agents": Template.from_stack(agents).to_json(),
                  "data": Template.from_stack(data).to_json()}))
"""


@functools.lru_cache(maxsize=None)
def _synth(context_json: str) -> str:
    result = subprocess.run(  # nosec B603 -- static argv, list form, no shell
        [sys.executable, "-c", _SYNTH_SCRIPT, context_json],
        cwd=CDK_ROOT, capture_output=True, text=True, timeout=240, check=False,
    )
    assert result.returncode == 0, f"synth failed:\n{result.stderr}"
    return result.stdout.strip().splitlines()[-1]


def synth(context: dict) -> dict:
    """{"agents": template, "data": template}; a fresh copy per call."""
    return json.loads(_synth(json.dumps(context, sort_keys=True)))


def resources(template, resource_type):
    return {lid: r for lid, r in template["Resources"].items() if r["Type"] == resource_type}


def logical_id(template, resource_type, prop, value):
    for lid, res in resources(template, resource_type).items():
        if res.get("Properties", {}).get(prop) == value:
            return lid
    raise AssertionError(f"{resource_type} with {prop}={value} not found")


def as_list(value):
    return value if isinstance(value, list) else [value]


def render(value) -> str:
    """Flatten Fn::Join / Ref / GetAtt / ImportValue into a comparable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(render(p) for p in parts)
    if isinstance(value, dict) and "Ref" in value:
        return "${" + value["Ref"] + "}"
    if isinstance(value, dict) and "Fn::GetAtt" in value:
        return "${" + ".".join(value["Fn::GetAtt"]) + "}"
    if isinstance(value, dict) and "Fn::ImportValue" in value:
        return "${Import:" + render(value["Fn::ImportValue"]) + "}"
    return json.dumps(value, sort_keys=True)


def role_id(template, role_name):
    return logical_id(template, "AWS::IAM::Role", "RoleName", role_name)


def role_props(template, role_name):
    return template["Resources"][role_id(template, role_name)]["Properties"]


def role_statements(template, role_name):
    rid = role_id(template, role_name)
    statements = []
    for res in resources(template, "AWS::IAM::Policy").values():
        if {"Ref": rid} in res["Properties"].get("Roles", []):
            statements.extend(res["Properties"]["PolicyDocument"]["Statement"])
    return statements


def role_actions(template, role_name):
    return {a for s in role_statements(template, role_name) if s["Effect"] == "Allow"
            for a in as_list(s["Action"])}


def statements_with_action(template, role_name, action):
    return [s for s in role_statements(template, role_name) if action in as_list(s["Action"])]


def is_account_root(principal) -> bool:
    if not isinstance(principal, dict) or "AWS" not in principal:
        return False
    return any(render(p).endswith(":root") for p in as_list(principal["AWS"]))


def notifies_on_call_only(alarm_props) -> bool:
    """The alarm's only action is the fsi-governance-alarms topic (a Ref in
    the data stack, an Fn::ImportValue of it in the agents stack): it can't
    invoke the breaker or any Lambda."""
    actions = alarm_props.get("AlarmActions") or []
    return (len(actions) == 1 and "GovernanceAlarmsAlarmTopic" in render(actions[0])
            and not alarm_props.get("OKActions") and not alarm_props.get("InsufficientDataActions"))
