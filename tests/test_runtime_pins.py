"""
Test: AgentCore runtimes are invoked only by the ARNs the deploy pinned.

The console used to list runtimes and pick one by name, so a runtime
registered under a matching name could receive operator evidence and return
a fabricated decision. Now cdk/deploy_agentcore_runtimes.py writes the three
ARNs it created/updated to the SSM parameter
/fsi/governance/agentcore-runtime-arns, and app/invoke_live.py reads only
that parameter (same account and region as the operator's session, each ARN
naming its own agent). No name lookup remains; missing pins fail closed.
"""
import importlib.util
import inspect
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from app import invoke_live  # noqa: E402
from governance_common import runtime_pins  # noqa: E402

ACCOUNT = "123456789012"
REGION = invoke_live.REGION
PREFIX = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/"
PINNED = {name: f"{PREFIX}{name}-abcdEFGH12" for name in runtime_pins.AGENT_NAMES}
DECOY = {name: f"{PREFIX}{name}-decoy00000" for name in runtime_pins.AGENT_NAMES}


class _ParameterNotFound(Exception):
    response = {"Error": {"Code": "ParameterNotFound", "Message": "x"}}


class _Session:
    """Explicit operator session: sts, ssm (the pins) and a control-plane
    client that lists a decoy runtime with every matching name."""

    def __init__(self, value=None, account=ACCOUNT, ssm_error=None):
        self.sts = MagicMock()
        self.sts.get_caller_identity.return_value = {"Account": account}
        self.ssm = MagicMock()
        if ssm_error is not None:
            self.ssm.get_parameter.side_effect = ssm_error
        else:
            self.ssm.get_parameter.return_value = {"Parameter": {"Value": value}}
        self.control = MagicMock()
        self.control.list_agent_runtimes.return_value = {"agentRuntimes": [
            {"agentRuntimeName": n, "agentRuntimeArn": a} for n, a in DECOY.items()]}
        self.data = MagicMock()
        self.data.invoke_agent_runtime.return_value = {"response": MagicMock(read=lambda: b'{"ok": true}')}

    def client(self, service, **kwargs):
        return {"sts": self.sts, "ssm": self.ssm, "bedrock-agentcore-control": self.control,
                "bedrock-agentcore": self.data}[service]


@pytest.fixture(autouse=True)
def _no_ambient_boto3(monkeypatch):
    import boto3

    def refuse(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, refuse)


# ─── Console resolution ─────────────────────────────────────────────────────

def test_name_pattern_resolution_is_gone():
    source = inspect.getsource(invoke_live)
    assert "list_agent_runtimes" not in source and "agentRuntimeName" not in source
    assert not hasattr(invoke_live, "_RUNTIME_ARNS")


@pytest.mark.parametrize("agent", runtime_pins.AGENT_NAMES)
def test_pinned_arn_is_used_and_the_decoy_never_is(agent):
    session = _Session(json.dumps(PINNED))
    assert invoke_live._invoke_agentcore(agent, {"x": 1}, session=session) == {"ok": True}
    assert session.data.invoke_agent_runtime.call_args.kwargs["agentRuntimeArn"] == PINNED[agent]
    session.control.list_agent_runtimes.assert_not_called()
    session.ssm.get_parameter.assert_called_once_with(Name="/fsi/governance/agentcore-runtime-arns")


def test_missing_pins_fail_closed_without_invoking():
    session = _Session(ssm_error=_ParameterNotFound())
    with pytest.raises(runtime_pins.RuntimePinsError):
        invoke_live._invoke_agentcore("DetectionAgent", {}, session=session)
    session.data.invoke_agent_runtime.assert_not_called()
    session.control.list_agent_runtimes.assert_not_called()


@pytest.mark.parametrize("value", [
    json.dumps({**PINNED, "DetectionAgent": PINNED["DetectionAgent"].replace(ACCOUNT, "999999999999")}),
    json.dumps({**PINNED, "DetectionAgent": PINNED["DetectionAgent"].replace(REGION, "eu-west-1")}),
    json.dumps({**PINNED, "DetectionAgent": PINNED["ExecutorAgent"]}),       # another agent's runtime
    json.dumps({k: v for k, v in PINNED.items() if k != "ExecutorAgent"}),   # incomplete
    json.dumps({**PINNED, "Extra": PINNED["ExecutorAgent"]}),
    json.dumps({**PINNED, "DetectionAgent": "arn:aws:lambda:us-east-1:123456789012:function:x"}),
    "not json", "",
], ids=["other-account", "other-region", "swapped", "incomplete", "extra-key", "not-runtime",
        "not-json", "empty"])
def test_invalid_pins_fail_closed(value):
    session = _Session(value)
    with pytest.raises(runtime_pins.RuntimePinsError):
        invoke_live._invoke_agentcore("DetectionAgent", {}, session=session)
    session.data.invoke_agent_runtime.assert_not_called()


def test_pins_are_checked_against_the_sessions_own_account():
    session = _Session(json.dumps(PINNED), account="999999999999")
    with pytest.raises(runtime_pins.RuntimePinsError, match="account"):
        invoke_live._invoke_agentcore("ComplianceAgent", {}, session=session)


@pytest.mark.parametrize("name", ["DETECTION_AGENT", "COMPLIANCE_AGENT", "EXECUTOR_AGENT"])
def test_agent_name_env_overrides_have_no_effect(monkeypatch, name):
    monkeypatch.setenv(name, "DecoyAgent")
    reloaded = importlib.reload(invoke_live)
    try:
        assert getattr(reloaded, name) in runtime_pins.AGENT_NAMES
    finally:
        monkeypatch.delenv(name)
        importlib.reload(invoke_live)


def test_local_mode_makes_no_aws_call(monkeypatch):
    monkeypatch.setenv("ALLOW_LOCAL_DEV_SIGNING", "true")
    result = invoke_live.run_detection_local()
    assert result.get("flagged_clusters") is not None


# ─── Deploy writes the pins ─────────────────────────────────────────────────

@pytest.fixture
def deploy(monkeypatch):
    path = os.path.join(PROJECT_ROOT, "cdk", "deploy_agentcore_runtimes.py")
    spec = importlib.util.spec_from_file_location("_deploy_runtime_pins", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ssm = MagicMock()
    monkeypatch.setattr(module.boto3, "client", lambda name, region_name=None: {"ssm": ssm}[name])
    module._test_ssm = ssm
    return module


def test_deploy_pins_exactly_the_deployed_arns(deploy):
    assert deploy.pin_runtime_arns(dict(PINNED), ACCOUNT) is True
    kwargs = deploy._test_ssm.put_parameter.call_args.kwargs
    assert kwargs["Name"] == "/fsi/governance/agentcore-runtime-arns"
    assert kwargs["Type"] == "String" and kwargs["Overwrite"] is True
    assert json.loads(kwargs["Value"]) == PINNED
    assert runtime_pins.parse_runtime_arns(kwargs["Value"], account=ACCOUNT, region=REGION) == PINNED


@pytest.mark.parametrize("results", [
    {**PINNED, "ExecutorAgent": None},                                   # a failed deploy
    {**PINNED, "DetectionAgent": PINNED["DetectionAgent"].replace(ACCOUNT, "999999999999")},
], ids=["failed-agent", "other-account"])
def test_deploy_refuses_an_incomplete_or_foreign_set(deploy, results):
    assert deploy.pin_runtime_arns(results, ACCOUNT) is False
    deploy._test_ssm.put_parameter.assert_not_called()


def test_cdk_constant_matches_the_module():
    with open(os.path.join(PROJECT_ROOT, "cdk", "agents_stack.py"), encoding="utf-8") as f:
        assert f'RUNTIME_ARNS_PARAMETER = "{runtime_pins.RUNTIME_ARNS_PARAMETER}"' in f.read()
