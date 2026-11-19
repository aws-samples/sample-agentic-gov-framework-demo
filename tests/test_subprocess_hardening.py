"""
Test: subprocess hardening in cdk/deploy_agentcore_runtimes.py (pip installs)
and demos/demo_model_swap.py (gate run, git restore).

Every call uses list-form argv with a static prefix, no shell, and paths that
are resolved and confined under the project (or its build dir) first. No
subprocess is actually run and no AWS call is made.
"""
import importlib.util
import os
import subprocess
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")


def _load(name, path, extra_path=None):
    if extra_path:
        sys.path.insert(0, extra_path)
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        if extra_path:
            sys.path.remove(extra_path)
    return mod


@pytest.fixture
def deploy():
    return _load("_deploy_agentcore_runtimes_subprocess",
                 os.path.join(CDK_ROOT, "deploy_agentcore_runtimes.py"), CDK_ROOT)


@pytest.fixture
def demo():
    return _load("_demo_model_swap_subprocess",
                 os.path.join(PROJECT_ROOT, "demos", "demo_model_swap.py"))


def _agent(tmp_path):
    code_dir = tmp_path / "agent"
    code_dir.mkdir()
    (code_dir / "requirements.txt").write_text("requests==2.34.2\n", encoding="utf-8")
    # package_agent installs from the hash lock only.
    (code_dir / "requirements.lock").write_text(
        "requests==2.34.2 \\\n    --hash=sha256:" + "0" * 64 + "\n", encoding="utf-8")
    (code_dir / "main.py").write_text("print('hi')\n", encoding="utf-8")
    return {"name": "X", "code_dir": code_dir}


def _record_runs(monkeypatch, mod, fail_first=False):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        if fail_first and len(calls) == 1:
            raise subprocess.CalledProcessError(1, argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    return calls


def test_pip_install_argv_is_static_and_confined(deploy, monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = _record_runs(monkeypatch, deploy)
    deploy.package_agent(_agent(tmp_path), tmp_path / "build" / "agentcore")

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[:4] == [sys.executable, "-m", "pip", "install"]
    assert argv == [
        sys.executable, "-m", "pip", "install",
        "--require-hashes", "--no-deps", "--only-binary=:all:",
        "--platform", "manylinux2014_aarch64", "--platform", "manylinux_2_28_aarch64",
        "--implementation", "cp", "--python-version", "3.13",
        "--target", str((tmp_path / "build" / "agentcore" / "X_deps").resolve()),
        "-r", str((tmp_path / "agent" / "requirements.lock").resolve()),
        "--quiet",
    ]
    assert "shell" not in kwargs
    assert kwargs == {"check": True, "capture_output": True, "text": True}


def test_pip_failure_propagates_without_fallback(deploy, monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = _record_runs(monkeypatch, deploy, fail_first=True)
    with pytest.raises(subprocess.CalledProcessError):
        deploy.package_agent(_agent(tmp_path), tmp_path / "build" / "agentcore")

    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert "--require-hashes" in argv and "--only-binary=:all:" in argv
    assert kwargs == {"check": True, "capture_output": True, "text": True}
    assert not (tmp_path / "build" / "agentcore" / "X.zip").exists()


def test_code_dir_outside_project_is_refused(deploy, monkeypatch, tmp_path, tmp_path_factory):
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = _record_runs(monkeypatch, deploy)
    outside = tmp_path_factory.mktemp("outside")
    with pytest.raises(ValueError, match="Refusing path outside"):
        deploy.package_agent(_agent(outside), tmp_path / "build" / "agentcore")
    assert calls == []


def test_build_dir_outside_build_root_is_refused(deploy, monkeypatch, tmp_path):
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = _record_runs(monkeypatch, deploy)
    with pytest.raises(ValueError, match="Refusing path outside"):
        deploy.package_agent(_agent(tmp_path), tmp_path / "elsewhere")
    assert calls == []


def test_confined_rejects_symlink_escape(deploy, tmp_path, tmp_path_factory):
    outside = tmp_path_factory.mktemp("escape-target")
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        deploy._confined(link / "requirements.txt", tmp_path)
    assert deploy._confined(tmp_path / "a" / "b", tmp_path) == (tmp_path / "a" / "b").resolve()


def _no_backup(monkeypatch, demo):
    """Make do_restore() take the git path without touching the real backup."""
    real_exists = os.path.exists
    monkeypatch.setattr(demo.os.path, "exists",
                        lambda p: False if p == demo.BACKUP else real_exists(p))


def test_demo_has_no_subprocess_use():
    """demos/demo_model_swap.py no longer shells out at all: the gate runs
    in-process and the no-backup restore prints the git command instead."""
    import ast
    src_path = os.path.join(PROJECT_ROOT, "demos", "demo_model_swap.py")
    with open(src_path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "subprocess" not in imported
    assert "os.system" not in ast.unparse(tree) and "os.popen" not in ast.unparse(tree)


def test_demo_restore_without_backup_prints_git_command(demo, monkeypatch, capsys):
    _no_backup(monkeypatch, demo)
    assert demo.do_restore() == 1
    out = capsys.readouterr().out
    assert "git checkout -- lambdas/compliance_agent/handler.py" in out


def test_demo_run_gate_returns_the_gates_exit_code(demo, monkeypatch):
    seen = []

    def fake_run_path(path, run_name=None):
        seen.append((path, run_name))
        raise SystemExit(1)

    monkeypatch.setattr(demo.runpy, "run_path", fake_run_path)
    assert demo._run_gate() == 1
    assert seen == [(os.path.realpath(os.path.join(PROJECT_ROOT, "compliance_gate.py")), "__main__")]

    monkeypatch.setattr(demo.runpy, "run_path", lambda *a, **k: (_ for _ in ()).throw(SystemExit(0)))
    assert demo._run_gate() == 0
    monkeypatch.setattr(demo.runpy, "run_path", lambda *a, **k: None)
    assert demo._run_gate() == 0


def test_demo_gate_script_is_confined(demo):
    assert demo._confined(demo.GATE_SCRIPT) == os.path.realpath(
        os.path.join(PROJECT_ROOT, "compliance_gate.py"))
    with pytest.raises(ValueError):
        demo._confined("/etc/hosts")
