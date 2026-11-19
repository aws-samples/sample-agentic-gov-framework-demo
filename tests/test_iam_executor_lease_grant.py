"""
Test: Executor role can UpdateItem the compliance-decisions table for the
replay lease, and nothing broader.

The lease claim/finalize are conditional UpdateItem calls, but the executor
role only held grant_read_data on the table, so every live request would hit
AccessDenied. Synthesizes the real stack (same subprocess approach as
tests/test_alarm_metric_math_floor.py) and inspects the executor role's
policy statements.
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
print(json.dumps({
    "agents": Template.from_stack(agents).to_json(),
    "data": Template.from_stack(data).to_json(),
}))
"""

@pytest.fixture(scope="module")
def templates():
    result = subprocess.run(
        [sys.executable, "-c", _SYNTH_SCRIPT],
        cwd=CDK_ROOT, capture_output=True, text=True, timeout=180,
    )
    assert result.returncode == 0, f"synth failed:\n{result.stderr}"
    return json.loads(result.stdout.strip().splitlines()[-1])


def _logical_id(template, resource_type, prop, value):
    for lid, res in template["Resources"].items():
        if res["Type"] == resource_type and res.get("Properties", {}).get(prop) == value:
            return lid
    raise AssertionError(f"{resource_type} with {prop}={value} not found")


def _executor_statements(agents):
    role_id = _logical_id(agents, "AWS::IAM::Role", "RoleName", "executor-agent-role")
    statements = []
    for res in agents["Resources"].values():
        if res["Type"] != "AWS::IAM::Policy":
            continue
        roles = res["Properties"].get("Roles", [])
        if {"Ref": role_id} in roles:
            statements.extend(res["Properties"]["PolicyDocument"]["Statement"])
    return statements


def _as_list(v):
    return v if isinstance(v, list) else [v]


def test_executor_has_update_item_on_compliance_table_only(templates):
    agents, data = templates["agents"], templates["data"]
    compliance_id = _logical_id(data, "AWS::DynamoDB::Table", "TableName", "compliance-decisions")
    statements = _executor_statements(agents)

    update_stmts = [
        s for s in statements
        if s.get("Effect") == "Allow" and "dynamodb:UpdateItem" in _as_list(s["Action"])
    ]
    assert len(update_stmts) == 1, update_stmts
    stmt = update_stmts[0]
    assert _as_list(stmt["Action"]) == ["dynamodb:UpdateItem"]
    resources = _as_list(stmt["Resource"])
    assert len(resources) == 1
    assert resources[0] != "*"
    serialized = json.dumps(resources[0])
    assert compliance_id in serialized
    assert "index" not in serialized
    assert "*" not in serialized


_EXPECTED_ATTRIBUTES = [
    "compliance_id", "completed_clusters", "executor_processed", "lease_expires_at",
]


def _update_item_statement(agents):
    stmts = [
        s for s in _executor_statements(agents)
        if s.get("Effect") == "Allow" and "dynamodb:UpdateItem" in _as_list(s["Action"])
    ]
    assert len(stmts) == 1, stmts
    return stmts[0]


def test_executor_update_item_restricted_to_lease_and_completion_attributes(templates):
    """UpdateItem is limited to the lease + completion
    attributes via ForAllValues:StringEquals on dynamodb:Attributes."""
    stmt = _update_item_statement(templates["agents"])
    condition = stmt.get("Condition")
    assert condition == {
        "ForAllValues:StringEquals": {"dynamodb:Attributes": _EXPECTED_ATTRIBUTES},
    }, condition
    attrs = _as_list(condition["ForAllValues:StringEquals"]["dynamodb:Attributes"])
    assert not any("*" in a or "?" in a for a in attrs)


def test_cdk_attribute_list_matches_handler_constant(templates):
    sys.path.insert(0, PROJECT_ROOT)
    from lambdas.executor_agent.handler import COMPLIANCE_TABLE_WRITE_ATTRIBUTES

    stmt = _update_item_statement(templates["agents"])
    attrs = _as_list(stmt["Condition"]["ForAllValues:StringEquals"]["dynamodb:Attributes"])
    assert set(attrs) == set(COMPLIANCE_TABLE_WRITE_ATTRIBUTES)
    assert len(attrs) == len(COMPLIANCE_TABLE_WRITE_ATTRIBUTES)


def test_executor_has_no_delete_or_broad_write_on_dynamodb(templates):
    statements = _executor_statements(templates["agents"])
    for s in statements:
        if s.get("Effect") != "Allow":
            continue
        actions = set(_as_list(s["Action"]))
        assert "dynamodb:DeleteItem" not in actions
        assert "dynamodb:BatchWriteItem" not in actions
        assert "dynamodb:*" not in actions
        assert "*" not in actions
        if actions & {"dynamodb:UpdateItem", "dynamodb:PutItem"}:
            for r in _as_list(s["Resource"]):
                assert r != "*"
