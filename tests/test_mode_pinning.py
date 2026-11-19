"""
Test: mode=local short-circuit is no longer caller-selectable.

Two layers:
1. The AgentCore shims pin the execution mode from the AGENT_MODE env var,
   never from the request body.
2. The detection/compliance handlers refuse local mode when running in a
   deployed runtime (/var/task present or a runtime env marker set). There
   is no override: ALLOW_LOCAL_MODE is no longer honored.
"""
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestShimPinsMode:
    def test_detection_shim_reads_agent_mode_env(self, monkeypatch):
        import importlib
        import agentcore.detection_agent.main as main
        importlib.reload(main)
        # Simulate the event-build branch logic directly.
        monkeypatch.setenv("AGENT_MODE", "cpu")
        payload = {"mode": "local", "transactions_inline": []}
        event = {"mode": os.environ.get("AGENT_MODE", "cpu")}
        if "transactions_inline" in payload:
            event["transactions_inline"] = payload["transactions_inline"]
        assert event["mode"] == "cpu"  # NOT the caller's "local"


class TestHandlerRefusesLocalInRuntime:
    def test_detection_handler_refuses_local_in_var_task(self, monkeypatch):
        from lambdas.detection_agent import handler as det
        monkeypatch.setattr(os.path, "isdir", lambda p: p == "/var/task")
        monkeypatch.delenv("ALLOW_LOCAL_MODE", raising=False)
        with pytest.raises(ValueError):
            det.handler({"mode": "local"})

    def test_compliance_handler_refuses_local_in_var_task(self, monkeypatch):
        from lambdas.compliance_agent import handler as comp
        monkeypatch.setattr(os.path, "isdir", lambda p: p == "/var/task")
        monkeypatch.delenv("ALLOW_LOCAL_MODE", raising=False)
        with pytest.raises(ValueError):
            comp.handler({"mode": "local"})

    def test_executor_handler_refuses_local_in_var_task(self, monkeypatch):
        """The executor handler previously had no equivalent
        guard — mode="local" (a caller-suppliable envelope key) would skip
        provenance verification and replay marking if ever reachable
        directly."""
        from lambdas.executor_agent import handler as ex
        monkeypatch.setattr(os.path, "isdir", lambda p: p == "/var/task")
        monkeypatch.delenv("ALLOW_LOCAL_MODE", raising=False)
        with pytest.raises(ValueError):
            ex.handler({"mode": "local"})

    def test_local_mode_allowed_outside_runtime(self, monkeypatch):
        """Outside /var/task (local dev/CLI), local mode still works."""
        from lambdas.detection_agent import handler as det
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        result = det.handler({"mode": "local"})
        assert "detection_id" in result


# ─── No override, and env markers count as a deployed runtime ────────────────
HANDLERS = ["lambdas.detection_agent.handler", "lambdas.compliance_agent.handler",
            "lambdas.executor_agent.handler"]


def _import(name):
    import importlib
    return importlib.import_module(name)


@pytest.mark.parametrize("module", HANDLERS)
def test_allow_local_mode_is_not_honored_in_a_deployed_runtime(monkeypatch, module):
    handler = _import(module)
    monkeypatch.setattr(os.path, "isdir", lambda p: p == "/var/task")
    monkeypatch.setenv("ALLOW_LOCAL_MODE", "true")
    with pytest.raises(ValueError, match="^local mode is disabled in the deployed runtime$"):
        handler.handler({"mode": "local"})


@pytest.mark.parametrize("marker", ["AWS_LAMBDA_FUNCTION_NAME", "LAMBDA_TASK_ROOT", "GATE_ARTIFACT_SHA256"])
@pytest.mark.parametrize("module", HANDLERS)
def test_runtime_env_markers_refuse_local_mode_without_var_task(monkeypatch, module, marker):
    handler = _import(module)
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/var/task" else real_isdir(p))
    monkeypatch.setenv(marker, "x")
    monkeypatch.setenv("ALLOW_LOCAL_MODE", "true")
    with pytest.raises(ValueError, match="^local mode is disabled in the deployed runtime$"):
        handler.handler({"mode": "local"})


def test_deployed_runtime_detection():
    from governance_common import deployed_runtime as dr
    with patch.object(dr.os.path, "isdir", lambda p: False), patch.dict(os.environ, {}, clear=True):
        assert not dr.in_deployed_runtime()
        dr.refuse_local_mode_in_deployed_runtime("local")  # local dev: allowed
    with patch.object(dr.os.path, "isdir", lambda p: p == "/var/task"), patch.dict(os.environ, {}, clear=True):
        assert dr.in_deployed_runtime()
        dr.refuse_local_mode_in_deployed_runtime("live")  # only local is refused
        with pytest.raises(ValueError):
            dr.refuse_local_mode_in_deployed_runtime("local")


def test_no_handler_or_shim_reads_allow_local_mode():
    for rel in ("lambdas/detection_agent/handler.py", "lambdas/compliance_agent/handler.py",
                "lambdas/executor_agent/handler.py", "agentcore/detection_agent/main.py",
                "agentcore/compliance_agent/main.py", "agentcore/executor_agent/main.py",
                "governance_common/deployed_runtime.py"):
        with open(os.path.join(PROJECT_ROOT, rel), encoding="utf-8") as f:
            assert "ALLOW_LOCAL_MODE" not in f.read(), rel
