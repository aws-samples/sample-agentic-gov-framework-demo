"""
Test: executor LOCAL_OUTPUT_DIR resolution (bandit B108 hardening).

The /tmp literal was replaced by tempfile.gettempdir(); the resolved path must
be identical to before in every mode: env value wins, AgentCore/Lambda
(/var/task present, repo dir read-only) -> <tmp>/cached_output, local -> the
repo cached_output dir. The deploy script still ships the in-container path
/tmp/cached_output to the ExecutorAgent runtime.
"""
import importlib.util
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.executor_agent.handler as executor_handler  # noqa: E402

REPO_CACHED_OUTPUT = os.path.join(PROJECT_ROOT, "cached_output")


def test_env_value_wins(monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", "/some/explicit/dir")
    assert executor_handler._resolve_local_output_dir() == "/some/explicit/dir"


def test_deployed_runtime_uses_platform_tmp(monkeypatch):
    monkeypatch.delenv("LOCAL_OUTPUT_DIR", raising=False)
    monkeypatch.setattr(executor_handler.os.path, "isdir", lambda p: p == "/var/task")
    monkeypatch.setattr(executor_handler.os, "access", lambda p, mode: False)
    monkeypatch.setattr(executor_handler.tempfile, "gettempdir", lambda: "/tmp")  # nosec B108 -- asserts the Lambda platform's fixed writable path
    assert executor_handler._resolve_local_output_dir() == "/tmp/cached_output"  # nosec B108 -- asserts the Lambda platform's fixed writable path


def test_local_uses_repo_cached_output(monkeypatch):
    monkeypatch.delenv("LOCAL_OUTPUT_DIR", raising=False)
    monkeypatch.setattr(executor_handler.os.path, "isdir", lambda p: False)
    assert executor_handler._resolve_local_output_dir() == REPO_CACHED_OUTPUT


def test_deploy_script_ships_in_container_tmp_path():
    cdk_root = os.path.join(PROJECT_ROOT, "cdk")
    sys.path.insert(0, cdk_root)
    try:
        spec = importlib.util.spec_from_file_location(
            "_deploy_agentcore_runtimes_local_output_dir",
            os.path.join(cdk_root, "deploy_agentcore_runtimes.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(cdk_root)
    executor = next(a for a in mod.AGENTS if a["name"] == "ExecutorAgent")
    assert executor["env_vars"]["LOCAL_OUTPUT_DIR"] == "/tmp/cached_output"  # nosec B108 -- asserts the Lambda platform's fixed writable path
