"""
Test: exact pins, hash locks and hash-checked installs.

- Every requirements file line is `name==version`; pyproject uses == pins and
  requires-python >= 3.11; fastapi/uvicorn/httpx are gone from them.
- Every requirements file has a committed lock whose entries all carry a
  sha256 hash; host locks are multi-platform.
- The AgentCore CLI install in README.md and docs/AGENTCORE_MIGRATION.md is
  pinned to an exact version.
- package_agent installs with --require-hashes/--only-binary=:all: from the
  agent lock, and a pip failure propagates (no fallback call).
- Makefile pip installs use --require-hashes -r <lock>; every pip/npm install
  command in the dependency files and their docs is exactly pinned.
- The gate's "Supply chain" domain enforces the same rules.
No network access: everything is read from the repo.
"""
import glob
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(\[[a-z,]+\])?==[0-9][A-Za-z0-9.+!-]*$")
HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}(\s|$)")


def _requirement_files():
    return sorted(glob.glob(str(PROJECT_ROOT / "requirements*.txt"))
                  + glob.glob(str(PROJECT_ROOT / "agentcore" / "*" / "requirements.txt")))


def _lines(path):
    with open(path, encoding="utf-8") as f:
        return [ln.split("#", 1)[0].strip() for ln in f]


def _lock_entries(path):
    entries, current = [], ""
    with open(path, encoding="utf-8") as f:
        for raw in f:
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            if text.endswith("\\"):
                current += text[:-1] + " "
                continue
            entries.append((current + text).strip())
            current = ""
    return entries


def _lock_pins(path):
    return {e.split()[0].split("==")[0]: e.split()[0].split("==")[1] for e in _lock_entries(path)}


def _canon(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def test_requirement_files_exist():
    names = {os.path.relpath(p, PROJECT_ROOT) for p in _requirement_files()}
    assert {"requirements.txt", "requirements-dev.txt", "requirements-cdk.txt",
            "agentcore/detection_agent/requirements.txt", "agentcore/compliance_agent/requirements.txt",
            "agentcore/executor_agent/requirements.txt"} <= names


@pytest.mark.parametrize("path", _requirement_files(), ids=lambda p: os.path.relpath(p, PROJECT_ROOT))
def test_every_requirement_line_is_an_exact_pin(path):
    pins = [ln for ln in _lines(path) if ln]
    assert pins, path
    for line in pins:
        assert PIN_RE.match(line), f"{path}: {line!r}"


def test_pyproject_pins_exactly_and_requires_311():
    text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11"' in text
    deps = re.findall(r'^\s*"([^"]+)",?\s*$', text, flags=re.M)
    assert deps
    for dep in deps:
        assert PIN_RE.match(dep), dep
    (build_requires,) = re.findall(r'^requires = \[(.*)\]\s*$', text, flags=re.M)
    build_deps = re.findall(r'"([^"]+)"', build_requires)
    assert build_deps
    for dep in build_deps:
        assert PIN_RE.match(dep), dep


def test_unused_http_frameworks_are_removed():
    # Requirement entries only (the agent files' comments say "no fastapi/uvicorn").
    # streamlit 1.61 itself depends on uvicorn/starlette, so the host lock
    # carries uvicorn transitively; it is no longer a direct requirement.
    for path in _requirement_files():
        for line in filter(None, _lines(path)):
            assert not re.match(r"(fastapi|uvicorn|httpx)\b", line.lower()), f"{path}: {line}"
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    assert not re.search(r"\b(fastapi|uvicorn|httpx)\b", pyproject)
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    assert not re.search(r"pip\) install[^\n]*(fastapi|uvicorn|httpx)", makefile)


@pytest.mark.parametrize("path", _requirement_files(), ids=lambda p: os.path.relpath(p, PROJECT_ROOT))
def test_each_requirements_file_has_a_hashed_lock(path):
    lock = Path(path[:-len(".txt")] + ".lock")
    assert lock.exists(), f"{lock} missing"
    entries = _lock_entries(lock)
    assert entries, lock
    for entry in entries:
        assert PIN_RE.match(entry.split()[0]), f"{lock}: {entry.split()[0]}"
        assert HASH_RE.search(entry), f"{lock}: {entry.split()[0]} has no sha256 hash"
    locked = {_canon(k): v for k, v in _lock_pins(lock).items()}
    for line in filter(None, _lines(path)):
        name, version = line.split("==")
        assert locked.get(_canon(name.split("[")[0])) == version, f"{lock} does not pin {line}"


def test_shared_packages_have_one_version_across_host_locks():
    seen = {}
    for lock in glob.glob(str(PROJECT_ROOT / "requirements*.lock")):
        for name, version in _lock_pins(lock).items():
            assert seen.setdefault(_canon(name), version) == version, name


@pytest.mark.parametrize("package", ["numpy", "pandas"])
def test_host_lock_is_multi_platform(package):
    lock = PROJECT_ROOT / "requirements.lock"
    entry = next(e for e in _lock_entries(lock) if e.startswith(f"{package}=="))
    assert len(HASH_RE.findall(entry)) > 1


def test_agent_locks_pin_one_wheel_per_package():
    for lock in glob.glob(str(PROJECT_ROOT / "agentcore" / "*" / "requirements.lock")):
        for entry in _lock_entries(lock):
            assert len(HASH_RE.findall(entry)) >= 1, entry
        assert "linux aarch64" in Path(lock).read_text(encoding="utf-8")


AGENTCORE_CLI_INSTALL = "npm install -g @aws/agentcore@1.0.3"


@pytest.mark.parametrize("doc", ["README.md", "docs/AGENTCORE_MIGRATION.md"])
def test_agentcore_cli_is_pinned(doc):
    assert AGENTCORE_CLI_INSTALL in (PROJECT_ROOT / doc).read_text(encoding="utf-8")


# ─── package_agent ──────────────────────────────────────────────────────────

def _deploy():
    spec = importlib.util.spec_from_file_location(
        "_deploy_dependency_pinning", PROJECT_ROOT / "cdk" / "deploy_agentcore_runtimes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _agent(tmp_path, with_lock=True):
    code_dir = tmp_path / "agent"
    code_dir.mkdir()
    (code_dir / "requirements.txt").write_text("boto3==1.43.72\n", encoding="utf-8")
    if with_lock:
        (code_dir / "requirements.lock").write_text(
            "boto3==1.43.72 \\\n    --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8")
    (code_dir / "main.py").write_text("print('hi')\n", encoding="utf-8")
    return {"name": "X", "code_dir": code_dir}


def test_package_agent_installs_hash_locked_binary_only(tmp_path, monkeypatch):
    deploy = _deploy()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = []
    monkeypatch.setattr(deploy.subprocess, "run",
                        lambda argv, **kw: calls.append(list(argv)) or subprocess.CompletedProcess(argv, 0))
    deploy.package_agent(_agent(tmp_path), tmp_path / "build" / "agentcore")
    assert len(calls) == 1
    argv = calls[0]
    for flag in ("--require-hashes", "--no-deps", "--only-binary=:all:"):
        assert flag in argv
    assert argv[argv.index("-r") + 1].endswith("requirements.lock")


def test_package_agent_pip_failure_propagates_without_fallback(tmp_path, monkeypatch):
    deploy = _deploy()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    calls = []

    def failing(argv, **kw):
        calls.append(list(argv))
        raise subprocess.CalledProcessError(1, argv, stderr="no matching distribution")

    monkeypatch.setattr(deploy.subprocess, "run", failing)
    with pytest.raises(subprocess.CalledProcessError):
        deploy.package_agent(_agent(tmp_path), tmp_path / "build" / "agentcore")
    assert len(calls) == 1


def test_package_agent_refuses_a_missing_lock(tmp_path, monkeypatch):
    deploy = _deploy()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pip")))
    with pytest.raises(FileNotFoundError, match="Hash lock missing"):
        deploy.package_agent(_agent(tmp_path, with_lock=False), tmp_path / "build" / "agentcore")


# ─── Install commands ───────────────────────────────────────────────────────

def test_makefile_pip_installs_are_hash_locked():
    lines = [ln for ln in (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
             if re.search(r"\bpip\b.*\binstall\b|\$\(PIP\) install", ln)]
    assert lines
    for line in lines:
        assert "--require-hashes" in line and re.search(r"-r \S+\.lock\b", line), line


_PIP_VALUE_OPTIONS = {"-r", "--requirement", "-c", "--constraint", "-i", "--index-url",
                      "--extra-index-url", "--platform", "--target", "--python-version", "--implementation"}


def _check_pip(line, where):
    tokens = line.split("pip install", 1)[1].split()
    skip_next = False
    named = False
    for tok in tokens:
        tok = tok.strip("`\"'")
        if skip_next:
            skip_next = False
            continue
        if tok in ("-r", "--requirement"):
            named = True
            skip_next = True
            continue
        if tok in _PIP_VALUE_OPTIONS:
            skip_next = True
            continue
        if tok.startswith("-") or tok.startswith("#"):
            if tok.startswith("#"):
                break
            continue
        if tok in ("\\", "&&", "|", ";"):
            break
        assert PIN_RE.match(tok), f"{where}: unpinned pip install target {tok!r} in {line.strip()!r}"
        named = True
    assert named, f"{where}: pip install without a pinned package or -r: {line.strip()!r}"


def _check_npm(line, where):
    tokens = line.split("npm install", 1)[1].split()
    named = False
    for tok in tokens:
        tok = tok.strip("`\"'")
        if tok.startswith("#") or tok in ("&&", "|", ";"):
            break
        if tok.startswith("-"):
            continue
        assert re.fullmatch(r"(@[a-z0-9._-]+/)?[a-z0-9._-]+@[0-9][A-Za-z0-9.+-]*", tok), \
            f"{where}: unpinned npm install {tok!r} in {line.strip()!r}"
        named = True
    assert named, f"{where}: npm install without a pinned package: {line.strip()!r}"


def _doc_files():
    return _requirement_files() + [str(PROJECT_ROOT / p) for p in
                                   ("pyproject.toml", "README.md", "docs/AGENTCORE_MIGRATION.md",
                                    "cdk/README.md")]


@pytest.mark.parametrize("path", _doc_files(), ids=lambda p: os.path.relpath(p, PROJECT_ROOT))
def test_install_commands_are_pinned(path):
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if "pip install" in line:
            _check_pip(line, path)
        if "npm install" in line:
            _check_npm(line, path)


def test_requirements_files_contain_no_install_commands():
    for path in _requirement_files() + [str(PROJECT_ROOT / "pyproject.toml")]:
        text = Path(path).read_text(encoding="utf-8")
        assert "pip install" not in text and "npm install" not in text, path


def test_scanner_rejects_unpinned_commands():
    with pytest.raises(AssertionError):
        _check_pip("pip install cudf-cu12 cugraph-cu12 --extra-index-url=https://pypi.nvidia.com", "x")
    with pytest.raises(AssertionError):
        _check_npm("npm install -g @aws/agentcore", "x")
    with pytest.raises(AssertionError):
        _check_npm("npm install -g aws-cdk", "x")
    _check_pip('pip install "cudf-cu12==26.10.2" --extra-index-url=https://pypi.nvidia.com', "x")
    _check_npm("npm install -g aws-cdk@2.1146.0", "x")


# ─── Gate "Supply chain" domain ─────────────────────────────────────────────

def _supply_chain_failures(root=None, monkeypatch=None):
    import compliance_gate
    if root is not None:
        monkeypatch.setattr(compliance_gate, "PROJECT_ROOT", str(root))
    gate = compliance_gate.ComplianceGate()
    gate.check_supply_chain()
    assert gate.results
    return [r["description"] for r in gate.results if not r["passed"]]


def test_gate_supply_chain_passes_on_the_repo():
    assert _supply_chain_failures() == []


def test_gate_supply_chain_fails_on_unpinned_or_unhashed(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("boto3>=1.34.0\n", encoding="utf-8")
    (tmp_path / "requirements.lock").write_text("boto3==1.43.72\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("pytest==9.1.1\n", encoding="utf-8")
    failed = _supply_chain_failures(tmp_path, monkeypatch)
    assert any(d.startswith("requirements.txt: every requirement is an exact pin") for d in failed)
    assert any(d.startswith("requirements.lock: every requirement is pinned with a sha256 hash") for d in failed)
    assert "requirements-dev.lock: hash lock present" in failed
