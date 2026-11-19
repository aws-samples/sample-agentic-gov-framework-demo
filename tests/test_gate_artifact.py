"""
Test: signed gate artifact, HEAD binding and the D5 demo.

- compliance_gate.main(argv=None): no flags = today's run-and-report;
  demo_model_swap._run_gate isolates sys.argv around the in-process gate.
- `--sign [--local-dev]` writes build/gate/gate-artifact.json(.sig) only on a
  full PASS from a clean tree with every packaged source at HEAD; a failing
  gate removes any stale artifact. `--sign --local-dev` runs the same git
  checks; the "working tree not clean" FAIL lists the first 10
  porcelain lines.
- Deploy-time strictness: the registry must be KMS-signed (.kms.sig), the
  bundle must carry exactly that signature, and a LOCAL_DEV_BUILD is refused.
- governance_common.head_binding against a real temp git repo (skipped
  without git), and ARCNAME_RULES coverage of real --package-only zips.

All git calls in gate tests go through the monkeypatched compliance_gate._git
seam; KMS/STS are mocks; no AWS call is made.
"""
import ast
import functools
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import compliance_gate  # noqa: E402
import model_assurance  # noqa: E402
from governance_common import bundle_digest, head_binding, signing  # noqa: E402
from _signing_fixtures import GATE_KEY_ARN, REGISTRY_KEY_ARN, kms_client as _fake_kms, write_pins  # noqa: E402

GIT = shutil.which("git")
KEY_ARN = GATE_KEY_ARN
SIGNER_ARN = "arn:aws:sts::123456789012:assumed-role/fsi-deploy-gate-signer/alice"
HEAD = "a" * 40
EXPECTED_KEYS = {"schema", "git_commit", "tree_clean", "created_at", "expires_at", "assertions_total",
                 "assertions_passed", "results_sha256", "registry_sha256", "registry_version", "bundles",
                 "gate_runner"}


@pytest.fixture(autouse=True)
def _pins(tmp_path_factory, monkeypatch):
    """Pinned signing keys for every KMS sign/verify here."""
    monkeypatch.setattr(signing, "DEFAULT_PINS_PATH",
                        write_pins(tmp_path_factory.mktemp("pins") / "signing_key_pins.json"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _deploy():
    return _load("_deploy_gate_artifact_tests", PROJECT_ROOT / "cdk" / "deploy_agentcore_runtimes.py")


@pytest.fixture
def demo():
    return _load("_demo_model_swap_gate_artifact", PROJECT_ROOT / "demos" / "demo_model_swap.py")


# ─── argv isolation ────────────────────────

def test_a_run_gate_isolates_and_restores_argv(demo, monkeypatch):
    demo_argv = ["demo_model_swap.py", "--break"]
    monkeypatch.setattr(sys, "argv", list(demo_argv))
    seen = []

    def fake_run_path(path, run_name=None):
        seen.append(list(sys.argv))
        raise SystemExit(0)

    monkeypatch.setattr(demo.runpy, "run_path", fake_run_path)
    assert demo._run_gate() == 0
    assert seen == [[os.path.realpath(PROJECT_ROOT / "compliance_gate.py")]]
    assert sys.argv == demo_argv

    def exploding(path, run_name=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(demo.runpy, "run_path", exploding)
    with pytest.raises(RuntimeError):
        demo._run_gate()
    assert sys.argv == demo_argv


def test_b_gate_rejects_the_demos_flags():
    with pytest.raises(SystemExit) as info:
        compliance_gate.main(["--break"])
    assert info.value.code == 2


def test_c_no_flags_exits_with_the_reports_code(monkeypatch):
    ran = []
    monkeypatch.setattr(compliance_gate.ComplianceGate, "run_all", lambda self: ran.append(True))
    monkeypatch.setattr(compliance_gate.ComplianceGate, "report", lambda self: 1)
    with pytest.raises(SystemExit) as info:
        compliance_gate.main([])
    assert info.value.code == 1 and ran == [True]


def test_local_dev_requires_sign():
    with pytest.raises(SystemExit) as info:
        compliance_gate.main(["--local-dev"])
    assert info.value.code == 2


# ─── --sign through the _git seam ───────────────────────────────────────────

class FakeGit:
    """Stands in for compliance_gate._git: clean status + a fixture ls-tree
    built from the bundle entries (blob ids of their bytes)."""

    def __init__(self, status=b"", tree=None):
        self.calls = []
        self.status = status
        self.tree = tree or {}

    def __call__(self, argv):
        argv = list(argv)
        self.calls.append(argv)
        args = argv[1:]
        if args == ["status", "--porcelain", "--untracked-files=all"]:
            out = self.status
        elif args == ["rev-parse", "HEAD"]:
            out = (HEAD + "\n").encode()
        elif args == ["rev-parse", "--show-object-format"]:
            out = b"sha1\n"
        elif args == ["ls-tree", "-r", "-z", "--full-tree", "HEAD"]:
            out = b"".join(f"{mode} blob {oid}\t{path}".encode() + b"\0"
                           for path, (mode, oid) in self.tree.items())
        else:
            raise AssertionError(f"unexpected git argv {argv}")
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr=b"")


def _agents():
    return _deploy().AGENTS


def _write_bundles(bundles_dir, agents, git, *, local_dev, registry_sig_bytes=None, extra=None):
    """One small zip per agent whose entries map through ARCNAME_RULES; the
    fake ls-tree gets each entry's blob id (so the bundle is 'at HEAD')."""
    bundles_dir.mkdir(parents=True, exist_ok=True)
    for cfg in agents:
        entries = {"main.py": f"# {cfg['name']} shim\n".encode()}
        if cfg.get("registry_signature"):
            entries["data/approved_models.json"] = (PROJECT_ROOT / "data" / "approved_models.json").read_bytes()
            entries["data/approved_models.json.sig"] = registry_sig_bytes or (
                PROJECT_ROOT / "data" / "approved_models.json.sig").read_bytes()
        entries.update((extra or {}).get(cfg["name"], {}))
        with zipfile.ZipFile(bundles_dir / f"{cfg['name']}.zip", "w") as zf:
            for arcname, data in entries.items():
                zf.writestr(arcname, data)
                repo_path = head_binding.map_arcname(arcname, cfg, PROJECT_ROOT, local_dev=local_dev)
                git.tree.setdefault(repo_path, ("100644", head_binding.blob_id(data, "sha1")))


@pytest.fixture
def signing_env(tmp_path, monkeypatch):
    gate_dir = tmp_path / "gate"
    bundles = tmp_path / "bundles"
    git = FakeGit()
    agents = _agents()
    monkeypatch.setattr(compliance_gate, "GATE_ARTIFACT_DIR", str(gate_dir))
    monkeypatch.setattr(compliance_gate, "_git", git)
    monkeypatch.setattr(compliance_gate, "_git_path", lambda: "/usr/bin/git")
    monkeypatch.setattr(compliance_gate, "_load_deploy_agents", lambda: agents)
    monkeypatch.setattr(compliance_gate.ComplianceGate, "run_all",
                        lambda self: self.assert_true(True, "Stub", "every domain assertion passes"))
    return {"gate_dir": gate_dir, "bundles": bundles, "git": git, "agents": agents}


def _run_main(argv):
    with pytest.raises(SystemExit) as info:
        compliance_gate.main(argv)
    return info.value.code


def _artifact(gate_dir):
    artifact = gate_dir / "gate-artifact.json"
    return artifact, Path(str(artifact) + ".sig")


def test_sign_local_dev_writes_a_verifiable_artifact(signing_env):
    env = signing_env
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    assert _run_main(["--sign", "--local-dev", "--bundles-dir", str(env["bundles"])]) == 0
    artifact_path, sig_path = _artifact(env["gate_dir"])
    payload = artifact_path.read_bytes()
    artifact = json.loads(payload)
    assert set(artifact) == EXPECTED_KEYS
    assert artifact["schema"] == "fsi-gate-artifact/v2"
    assert artifact["registry_version"] == "2026-Q3"
    assert artifact["git_commit"] == HEAD and artifact["tree_clean"] is True
    assert artifact["assertions_total"] == artifact["assertions_passed"] > 0
    assert artifact["gate_runner"].startswith("local:")
    assert artifact["registry_sha256"] == __import__("hashlib").sha256(
        (PROJECT_ROOT / "data" / "approved_models.json").read_bytes()).hexdigest()
    assert artifact["bundles"] == {
        name: bundle_digest.bundle_digest(env["bundles"] / f"{name}.zip")
        for name in ("DetectionAgent", "ComplianceAgent", "ExecutorAgent")}
    assert payload == signing.canonical_json(artifact)
    envelope = json.loads(sig_path.read_bytes())
    assert envelope["version"] == artifact["registry_version"]
    signing.verify(signing.PURPOSE_GATE, payload, envelope, require_kms=False, expected_version="2026-Q3")
    with pytest.raises(signing.SignatureInvalidError):
        signing.verify(signing.PURPOSE_GATE, payload, envelope, require_kms=True)


def test_git_status_argv_uses_untracked_files_all(signing_env):
    env = signing_env
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    _run_main(["--sign", "--local-dev", "--bundles-dir", str(env["bundles"])])
    assert ["/usr/bin/git", "status", "--porcelain", "--untracked-files=all"] in env["git"].calls
    assert all(isinstance(argv, list) and argv[0] == "/usr/bin/git" for argv in env["git"].calls)


def test_failing_assertion_writes_no_artifact_and_removes_stale(signing_env, monkeypatch):
    env = signing_env
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    env["gate_dir"].mkdir()
    for path in _artifact(env["gate_dir"]):
        path.write_text("stale pass", encoding="utf-8")
    monkeypatch.setattr(compliance_gate.ComplianceGate, "run_all",
                        lambda self: self.assert_true(False, "Stub", "one assertion fails"))
    assert _run_main(["--sign", "--local-dev", "--bundles-dir", str(env["bundles"])]) == 1
    assert not any(path.exists() for path in _artifact(env["gate_dir"]))


def test_dirty_tree_lists_first_ten_porcelain_lines(signing_env, capsys):
    env = signing_env
    lines = [f"?? scratch/draft-{i:02d}.md" for i in range(12)]
    env["git"].status = ("\n".join(lines) + "\n").encode()
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    gate = compliance_gate.ComplianceGate(sign_mode="local-dev", bundles_dir=str(env["bundles"]))
    gate.check_deploy_artifact_preconditions()
    assert gate.tree_clean is False
    failed = [r["description"] for r in gate.results if not r["passed"]]
    message = next(d for d in failed if d.startswith("working tree not clean"))
    for line in lines[:10]:
        assert line in message
    assert lines[10] not in message and lines[11] not in message
    assert "(+2 more)" in message


def test_sign_local_dev_runs_the_same_git_checks(signing_env):
    env = signing_env
    env["git"].status = b" M lambdas/compliance_agent/handler.py\n"
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    assert _run_main(["--sign", "--local-dev", "--bundles-dir", str(env["bundles"])]) == 1
    assert not any(path.exists() for path in _artifact(env["gate_dir"]))

    env["git"].status = b""
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True,
                   extra={"DetectionAgent": {"lambdas/detection_agent/boto3.py": b"shadow = True\n"}})
    env["git"].tree.pop("lambdas/detection_agent/boto3.py")       # not in HEAD
    gate = compliance_gate.ComplianceGate(sign_mode="local-dev", bundles_dir=str(env["bundles"]))
    gate.check_deploy_artifact_preconditions()
    failed = [r["description"] for r in gate.results if not r["passed"]]
    assert "packaged source not at HEAD: lambdas/detection_agent/boto3.py" in failed
    assert _run_main(["--sign", "--local-dev", "--bundles-dir", str(env["bundles"])]) == 1
    assert not any(path.exists() for path in _artifact(env["gate_dir"]))


def test_missing_bundle_fails(signing_env):
    env = signing_env
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=True)
    (env["bundles"] / "ExecutorAgent.zip").unlink()
    gate = compliance_gate.ComplianceGate(sign_mode="local-dev", bundles_dir=str(env["bundles"]))
    gate.check_deploy_artifact_preconditions()
    assert any(not r["passed"] and r["description"].startswith("Bundle present: ExecutorAgent.zip")
               for r in gate.results)


# ─── Deploy-time strictness (kms mode, no --local-dev) ──────────────────────

def _kms(valid=True):
    return _fake_kms(valid)


@pytest.fixture
def registry_copy(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    reg = data_dir / "approved_models.json"
    shutil.copyfile(PROJECT_ROOT / "data" / "approved_models.json", reg)
    shutil.copyfile(PROJECT_ROOT / "data" / "approved_models.json.sig", str(reg) + ".sig")
    monkeypatch.setattr(model_assurance, "DEFAULT_REGISTRY_PATH", str(reg))
    return reg


def _kms_sig(reg, client):
    envelope = signing.sign(signing.PURPOSE_REGISTRY, reg.read_bytes(), kms_client=client,
                            signed_by="arn:aws:sts::123456789012:assumed-role/fsi-model-risk-approver/bob",
                            version=json.loads(reg.read_bytes())["registry_version"])
    Path(str(reg) + ".kms.sig").write_text(json.dumps(envelope), encoding="utf-8")
    return Path(str(reg) + ".kms.sig").read_bytes()


def _failed(gate):
    return [r["description"] for r in gate.results if not r["passed"]]


def test_kms_mode_without_kms_sig_fails_with_the_instruction(registry_copy):
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=_kms())
    gate.check_model_assurance()
    assert any(d.startswith("Approved-models registry is KMS-signed") and
               "run scripts/sign_registry.py --kms and commit data/approved_models.json.kms.sig" in d
               for d in _failed(gate))


def test_kms_mode_refuses_a_local_dev_envelope_in_kms_sig(registry_copy):
    shutil.copyfile(str(registry_copy) + ".sig", str(registry_copy) + ".kms.sig")
    client = _kms()
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=client)
    gate.check_model_assurance()
    assert any(d.startswith("Approved-models registry is KMS-signed") for d in _failed(gate))
    client.verify.assert_not_called()


def test_kms_mode_accepts_a_valid_kms_sig(registry_copy):
    client = _kms()
    _kms_sig(registry_copy, client)
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=client)
    gate.check_model_assurance()
    assert any(r["passed"] and r["description"] == "Approved-models registry is KMS-signed" for r in gate.results)
    assert not any("signature" in d for d in _failed(gate))


def test_main_sign_without_kms_sig_writes_no_artifact(signing_env, registry_copy, monkeypatch):
    env = signing_env
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=False)
    session = MagicMock()
    session.client.side_effect = lambda name, region_name=None: _kms() if name == "kms" else MagicMock()
    monkeypatch.setattr(compliance_gate, "_signer_session", lambda: session)
    monkeypatch.setattr(compliance_gate.ComplianceGate, "run_all", lambda self: self.check_model_assurance())
    assert _run_main(["--sign", "--bundles-dir", str(env["bundles"])]) == 1
    assert not any(path.exists() for path in _artifact(env["gate_dir"]))


def test_bundled_sig_must_equal_the_committed_kms_sig(signing_env, registry_copy):
    env = signing_env
    client = _kms()
    kms_sig_bytes = _kms_sig(registry_copy, client)
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=False,
                   registry_sig_bytes=kms_sig_bytes + b" ")
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=client, bundles_dir=str(env["bundles"]))
    gate.check_deploy_artifact_preconditions()
    assert "bundled registry signature is not the committed KMS signature" in _failed(gate)


def test_kms_mode_refuses_a_local_dev_build(signing_env, registry_copy):
    env = signing_env
    client = _kms()
    kms_sig_bytes = _kms_sig(registry_copy, client)
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=False, registry_sig_bytes=kms_sig_bytes)
    (env["bundles"] / "LOCAL_DEV_BUILD").write_text("local-dev\n", encoding="utf-8")
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=client, bundles_dir=str(env["bundles"]))
    gate.check_deploy_artifact_preconditions()
    assert "local-dev build cannot be signed for deploy" in _failed(gate)


def test_kms_sign_full_pass_writes_a_kms_signed_artifact(signing_env, registry_copy, monkeypatch):
    env = signing_env
    client = _kms()
    kms_sig_bytes = _kms_sig(registry_copy, client)
    _write_bundles(env["bundles"], env["agents"], env["git"], local_dev=False, registry_sig_bytes=kms_sig_bytes)
    sts = MagicMock()
    sts.get_caller_identity.return_value = {"Arn": SIGNER_ARN}
    session = MagicMock()
    session.client.side_effect = lambda name, region_name=None: {"kms": client, "sts": sts}[name]
    monkeypatch.setattr(compliance_gate, "_signer_session", lambda: session)
    monkeypatch.setattr(compliance_gate.ComplianceGate, "run_all", lambda self: self.check_model_assurance())
    assert _run_main(["--sign", "--bundles-dir", str(env["bundles"])]) == 0
    artifact_path, sig_path = _artifact(env["gate_dir"])
    envelope = json.loads(sig_path.read_bytes())
    assert envelope["algorithm"] == signing.ALG_KMS and envelope["key_id"] == KEY_ARN
    assert envelope["version"] == "2026-Q3"
    client.describe_key.assert_not_called()
    assert json.loads(artifact_path.read_bytes())["gate_runner"] == SIGNER_ARN
    signing.verify(signing.PURPOSE_GATE, artifact_path.read_bytes(), envelope,
                   kms_client=client, require_kms=True)


# ─── D5 demo + ALLOW_LOCAL_DEV_SIGNING pair ─────────────────────────────────

def _swapped_handler(tmp_path, demo):
    src = (PROJECT_ROOT / "lambdas" / "compliance_agent" / "handler.py").read_text(encoding="utf-8")
    new_src, count = demo.MODEL_LINE_RE.subn(rf"\g<1>{demo.UNAPPROVED_MODEL}\g<3>", src, count=1)
    assert count == 1, "MODEL_LINE_RE must match handler.py's BEDROCK_MODEL_ID default"
    path = tmp_path / "handler.py"
    path.write_text(new_src, encoding="utf-8")
    return path


@pytest.fixture
def d5_gate(tmp_path, monkeypatch, demo):
    path = _swapped_handler(tmp_path, demo)
    monkeypatch.delenv("BEDROCK_MODEL_ID", raising=False)
    monkeypatch.delenv("CHALLENGER_MODEL_ID", raising=False)
    monkeypatch.setattr(compliance_gate, "configured_model_id",
                        functools.partial(model_assurance.configured_model_id, handler_path=str(path)))
    return path


def test_model_line_re_matches_the_empty_default(demo):
    src = (PROJECT_ROOT / "lambdas" / "compliance_agent" / "handler.py").read_text(encoding="utf-8")
    matches = demo.MODEL_LINE_RE.findall(src)
    assert len(matches) == 1 and matches[0][1] == ""


def test_d5_blocks_on_the_champion_with_the_opt_in(d5_gate):
    gate = compliance_gate.ComplianceGate()
    gate.check_model_assurance()
    failed = _failed(gate)
    assert any(d.startswith("Configured champion model is approved") for d in failed)
    assert not any(d.startswith("Approved-models registry signature verifies") for d in failed)


def test_d5_blocks_on_the_signature_without_the_opt_in(d5_gate, monkeypatch):
    monkeypatch.delenv("ALLOW_LOCAL_DEV_SIGNING")
    gate = compliance_gate.ComplianceGate()
    gate.check_model_assurance()
    failed = _failed(gate)
    assert any(d.startswith("Approved-models registry signature verifies") for d in failed)


# ─── demos/demo_model_assurance.py reads the registry verified ──────────────

def test_demo_model_assurance_uses_the_verified_loader(monkeypatch, capsys):
    path = PROJECT_ROOT / "demos" / "demo_model_assurance.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called = {node.func.id for node in ast.walk(tree)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert "load_verified_registry" in called and "load_registry" not in called
    module = _load("_demo_model_assurance_verified", path)
    monkeypatch.setattr(sys, "argv", ["demo_model_assurance.py", "--local"])
    module.main()                          # returns normally (exit 0)
    assert "BLOCKED" in capsys.readouterr().out


def test_demo_model_assurance_exits_1_without_the_opt_in(monkeypatch, capsys):
    module = _load("_demo_model_assurance_unverified", PROJECT_ROOT / "demos" / "demo_model_assurance.py")
    monkeypatch.delenv("ALLOW_LOCAL_DEV_SIGNING")
    monkeypatch.setattr(sys, "argv", ["demo_model_assurance.py", "--local"])
    with pytest.raises(SystemExit) as info:
        module.main()
    assert info.value.code == 1
    assert "registry signature could not be verified" in capsys.readouterr().out


# ─── HEAD binding against a real temp git repo ──────────────────────────────

needs_git = pytest.mark.skipif(GIT is None, reason="git not installed")


def _git_cmd(repo, *args):
    return subprocess.run(  # nosec B603 -- test helper, list argv, resolved git, no shell
        [GIT, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo, check=True, capture_output=True, timeout=30)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    files = {
        "agentcore/compliance_agent/main.py": "print('shim')\n",
        "lambdas/compliance_agent/handler.py": "def handler(e):\n    return e\n",
        "lambdas/compliance_agent/helper.py": "X = 1\n",
        "governance_common/__init__.py": "",
        "governance_common/signing.py": "S = 1\n",
        "model_assurance.py": "M = 1\n",
        "data/approved_models.json": '{"approved_models": []}\n',
        "data/approved_models.json.sig": '{"local": "dev"}\n',
        ".gitignore": "build/\nlambdas/compliance_agent/extra.py\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _git_cmd(root, "init", "-q")
    _git_cmd(root, "add", "-A")
    _git_cmd(root, "commit", "-q", "-m", "init")
    return root


def _cfg(root):
    return {
        "name": "ComplianceAgent",
        "code_dir": root / "agentcore" / "compliance_agent",
        "extra_dirs": [root / "lambdas" / "compliance_agent"],
        "packages": [root / "governance_common"],
        "root_files": [(root / "model_assurance.py", "model_assurance.py"),
                       (root / "data" / "approved_models.json", "data/approved_models.json")],
        "registry_signature": True,
    }


def _package(root, monkeypatch, *, local_dev=True):
    deploy = _deploy()
    (root / "build" / "agentcore").mkdir(parents=True, exist_ok=True)
    # The fixture has no requirements.txt, so packaging must not run pip;
    # scoped so the later git subprocess calls are unaffected.
    with monkeypatch.context() as m:
        m.setattr(deploy, "PROJECT_ROOT", root)
        m.setattr(deploy.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pip")))
        return deploy.package_agent(_cfg(root), root / "build" / "agentcore", local_dev=local_dev)


def _check(root, zip_path, local_dev=True):
    return head_binding.check_bundle_at_head(zip_path, _cfg(root), git_path=GIT, repo_root=root,
                                             local_dev=local_dev)


@needs_git
def test_clean_tree_passes(repo, monkeypatch):
    zip_path = _package(repo, monkeypatch)
    assert _check(repo, zip_path) == []
    runner = head_binding.default_git_runner(repo)
    assert head_binding.porcelain_status(runner, GIT) == []


@needs_git
def test_untracked_shadow_module_is_dirty_and_offending(repo, monkeypatch):
    (repo / "lambdas" / "compliance_agent" / "boto3.py").write_text("hijack = 1\n", encoding="utf-8")
    zip_path = _package(repo, monkeypatch)
    status = head_binding.porcelain_status(head_binding.default_git_runner(repo), GIT)
    assert any("lambdas/compliance_agent/boto3.py" in line for line in status)
    assert "lambdas/compliance_agent/boto3.py" in _check(repo, zip_path)


@needs_git
def test_gitignored_packaged_source_is_offending(repo, monkeypatch):
    (repo / "lambdas" / "compliance_agent" / "extra.py").write_text("hidden = 1\n", encoding="utf-8")
    status = head_binding.porcelain_status(head_binding.default_git_runner(repo), GIT)
    assert not any("extra.py" in line for line in status)
    assert "lambdas/compliance_agent/extra.py" in _check(repo, _package(repo, monkeypatch))


@needs_git
def test_modified_tracked_file_is_offending(repo, monkeypatch):
    (repo / "lambdas" / "compliance_agent" / "handler.py").write_text("def handler(e):\n    return 1\n")
    assert _check(repo, _package(repo, monkeypatch)) == ["lambdas/compliance_agent/handler.py"]


@needs_git
def test_tracked_file_replaced_by_symlink_is_offending(repo, monkeypatch):
    helper = repo / "lambdas" / "compliance_agent" / "helper.py"
    helper.unlink()
    (repo / "elsewhere.py").write_text("evil = 1\n", encoding="utf-8")
    helper.symlink_to(repo / "elsewhere.py")
    assert "lambdas/compliance_agent/helper.py" in _check(repo, _package(repo, monkeypatch))


@needs_git
def test_committed_symlink_mode_is_offending(repo, monkeypatch):
    link = repo / "governance_common" / "link.py"
    link.symlink_to(repo / "governance_common" / "signing.py")
    _git_cmd(repo, "add", "-A")
    _git_cmd(repo, "commit", "-q", "-m", "symlink")
    assert _check(repo, _package(repo, monkeypatch)) == ["governance_common/link.py"]


@needs_git
def test_deploy_build_maps_the_bundled_sig_to_kms_sig(repo, monkeypatch):
    (repo / "data" / "approved_models.json.kms.sig").write_text('{"kms": 1}\n', encoding="utf-8")
    zip_path = _package(repo, monkeypatch, local_dev=False)
    assert _check(repo, zip_path, local_dev=False) == ["data/approved_models.json.sig"]   # untracked
    _git_cmd(repo, "add", "data/approved_models.json.kms.sig")
    _git_cmd(repo, "commit", "-q", "-m", "kms sig")
    assert _check(repo, zip_path, local_dev=False) == []


@needs_git
def test_unmapped_arcname_is_offending(repo, tmp_path):
    zip_path = tmp_path / "odd.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("etc/passwd", b"x")
        zf.writestr("lib/boto3/__init__.py", b"skipped")
        zf.writestr("governance/gate-artifact.json", b"skipped")
    assert _check(repo, zip_path) == ["etc/passwd"]


@needs_git
def test_blob_id_equals_git_hash_object(repo):
    runner = head_binding.default_git_runner(repo)
    fmt = head_binding.object_format(runner, GIT)
    path = repo / "lambdas" / "compliance_agent" / "handler.py"
    expected = _git_cmd(repo, "hash-object", str(path)).stdout.decode().strip()
    assert head_binding.blob_id(path.read_bytes(), fmt) == expected
    tree = head_binding.head_tree(runner, GIT)
    assert tree["lambdas/compliance_agent/handler.py"] == ("100644", expected)


def test_unknown_object_format_fails_closed():
    with pytest.raises(head_binding.HeadBindingError):
        head_binding.blob_id(b"x", "md5")


# ─── ARCNAME_RULES cover every entry of real --package-only zips ────────────

def _reroot(value, old_root, new_root):
    if isinstance(value, Path):
        return new_root / value.relative_to(old_root)
    if isinstance(value, list):
        return [_reroot(v, old_root, new_root) for v in value]
    if isinstance(value, tuple):
        return tuple(_reroot(v, old_root, new_root) for v in value)
    return value


@pytest.mark.parametrize("local_dev", [True, False])
def test_mapping_covers_real_package_only_zips(tmp_path, monkeypatch, local_dev):
    deploy = _deploy()
    ignore = shutil.ignore_patterns("__pycache__", "lib", "*.pyc")
    for rel in ("agentcore", "lambdas", "governance_common", "data"):
        shutil.copytree(PROJECT_ROOT / rel, tmp_path / rel, ignore=ignore)
    shutil.copy2(PROJECT_ROOT / "model_assurance.py", tmp_path / "model_assurance.py")
    (tmp_path / "data" / "approved_models.json.kms.sig").write_text('{"kms": "fake"}\n', encoding="utf-8")
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "AGENTS", [{k: _reroot(v, PROJECT_ROOT, tmp_path) for k, v in cfg.items()}
                                           for cfg in deploy.AGENTS])
    monkeypatch.setattr(deploy.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0))
    build_dir = tmp_path / "build" / "agentcore"
    zips = deploy.package_only(build_dir, local_dev=local_dev)
    assert (build_dir / "LOCAL_DEV_BUILD").exists() is local_dev
    arcnames_by_agent = {}
    for cfg, zip_path in zip(deploy.AGENTS, zips):
        with zipfile.ZipFile(zip_path) as zf:
            names = [i.filename for i in zf.infolist() if not i.is_dir()]
        arcnames_by_agent[cfg["name"]] = names
        for arcname in names:
            mapped = head_binding.map_arcname(arcname, cfg, tmp_path, local_dev=local_dev)
            if arcname.startswith(("lib/", "governance/")):
                assert mapped is None
            else:
                assert (tmp_path / mapped).is_file(), arcname
    compliance = arcnames_by_agent["ComplianceAgent"]
    for expected in ("main.py", "model_assurance.py", "data/approved_models.json",
                     "data/approved_models.json.sig", "lambdas/compliance_agent/handler.py",
                     "governance_common/signing.py", "governance_common/head_binding.py"):
        assert expected in compliance
    assert "data/transactions_small.jsonl" in arcnames_by_agent["DetectionAgent"]
    sig_target = head_binding.map_arcname("data/approved_models.json.sig",
                                          dict(deploy.AGENTS[1]), tmp_path, local_dev=local_dev)
    assert sig_target == ("data/approved_models.json.sig" if local_dev else "data/approved_models.json.kms.sig")


@needs_git
def test_detection_dataset_is_tracked_at_head():
    out = subprocess.run(  # nosec B603 -- test helper, list argv, resolved git, no shell
        [GIT, "ls-files", "data/transactions_small.jsonl"], cwd=PROJECT_ROOT,
        check=True, capture_output=True, timeout=30).stdout.decode().split()
    assert out == ["data/transactions_small.jsonl"]
