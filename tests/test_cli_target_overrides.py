"""
Test: governance targets cannot be redirected through environment variables.

The CLIs, the console and the teardown script used to honor overrides of the
deny-policy ARN, audit/state table names, agent role names and function names.
Those targets are now fixed (the names the CDK stacks create) or derived from
the caller's account (the deny-all ARN). Only harmless settings remain
configurable: AWS_REGION and AWS_PROFILE.
"""
import importlib.util
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

OVERRIDES = {
    "DENY_POLICY_ARN": "arn:aws:iam::123456789012:policy/attacker-chosen",
    "DETECTION_ROLE": "decoy-role", "COMPLIANCE_ROLE": "decoy-role", "EXECUTOR_ROLE": "decoy-role",
    "AUDIT_TABLE": "decoy-table", "GOVERNANCE_STATE_TABLE": "decoy-table",
    "EXECUTOR_AUDIT_TABLE": "decoy-table", "OPERATOR_AUDIT_TABLE": "decoy-table",
    "CIRCUIT_BREAKER_HUMAN_FUNCTION": "decoy-function", "CIRCUIT_BREAKER_HUMAN_LAMBDA": "decoy-function",
    "PAN_FILTER_LAMBDA": "decoy-function",
    "DETECTION_AGENT": "DecoyAgent", "COMPLIANCE_AGENT": "DecoyAgent", "EXECUTOR_AGENT": "DecoyAgent",
}
AGENT_ROLES = ["detection-agent-role", "compliance-agent-role", "executor-agent-role"]


def _load(rel_path, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(PROJECT_ROOT, rel_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def overridden(monkeypatch):
    for key, value in OVERRIDES.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize("rel_path", [
    "scripts/ensure_agents_enabled.py", "scripts/break_glass_release.py",
    "cdk/destroy_agentcore_runtimes.py",
])
def test_cli_role_names_are_fixed(overridden, rel_path):
    assert _load(rel_path, "_cli_" + os.path.basename(rel_path)[:-3]).AGENT_ROLES == AGENT_ROLES


def test_break_glass_tables_are_fixed(overridden):
    module = _load("scripts/break_glass_release.py", "_cli_break_glass")
    assert (module.AUDIT_TABLE, module.STATE_TABLE) == ("governance-audit", "governance-state")


def test_console_targets_are_fixed(overridden):
    import importlib

    import app.invoke_live as invoke_live
    import app.operator_audit as operator_audit
    try:
        il = importlib.reload(invoke_live)
        oa = importlib.reload(operator_audit)
        assert il.AGENT_ROLES == AGENT_ROLES
        assert (il.PAN_FILTER_LAMBDA, il.CIRCUIT_BREAKER_HUMAN_LAMBDA) == (
            "fsi-pan-filter", "fsi-circuit-breaker-human")
        assert il.EXECUTOR_AUDIT_TABLE == "executor-audit"
        assert (il.DETECTION_AGENT, il.COMPLIANCE_AGENT, il.EXECUTOR_AGENT) == (
            "DetectionAgent", "ComplianceAgent", "ExecutorAgent")
        assert oa.TABLE_NAME == "operator-audit"
    finally:
        for key in OVERRIDES:
            os.environ.pop(key, None)
        importlib.reload(invoke_live)
        importlib.reload(operator_audit)


def test_demo_pan_function_is_fixed(overridden):
    assert _load("demos/demo_pan_rejection_live.py", "_demo_pan_live").FUNCTION_NAME == "fsi-pan-filter"


def test_no_security_target_env_reads_remain():
    """Grep guard: none of the removed override names is read anywhere in the
    CLIs, the console, the demos or the Makefile."""
    paths = ["Makefile"]
    for directory in ("scripts", "app", "demos", "cdk"):
        for name in sorted(os.listdir(os.path.join(PROJECT_ROOT, directory))):
            if name.endswith(".py"):
                paths.append(os.path.join(directory, name))
    for rel in paths:
        with open(os.path.join(PROJECT_ROOT, rel), encoding="utf-8") as f:
            text = f.read()
        for key in OVERRIDES:
            assert f'environ.get("{key}"' not in text and f"getenv(\"{key}\"" not in text, (rel, key)
