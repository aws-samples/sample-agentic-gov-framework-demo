"""
Test: packaging and deploy require a verified, KMS-signed gate artifact
(and the registry signature in the ComplianceAgent zip).

- `--package-only` (deploy build) needs data/approved_models.json.kms.sig,
  bundles it at arcname data/approved_models.json.sig and clears any
  LOCAL_DEV_BUILD marker; `--local-dev` bundles the committed local-dev
  signature and writes the marker.
- The default deploy never builds: it loads prebuilt zips and runs
  verify_gate_artifact before any S3/AgentCore client exists.
- verify_gate_artifact refuses a missing/expired/local-dev/foreign-commit
  artifact, a changed bundle and a local-dev bundled registry, without
  constructing any boto3 client.
- signatures verify against the PINNED key ARNs (pins file,
  never an alias); the pins must match the deploy region, the deployer's
  account and the stack's key outputs; signed_at freshness and the
  registry_version floor (/fsi/governance/accepted-registry) are enforced,
  and --record-accepted never lowers the floor.
pip, git, KMS, STS, CloudFormation, SSM and every boto3 client are mocks;
no AWS call is made.
"""
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import boto3
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from botocore.exceptions import ClientError  # noqa: E402

from governance_common import bundle_digest, head_binding, signing  # noqa: E402
from _signing_fixtures import (  # noqa: E402
    ACCOUNT, ATTACKER_KEY_ARN, GATE_KEY_ARN, REGISTRY_KEY_ARN, kms_client as _fake_kms, pins as _pins,
    write_pins,
)

HEAD = "b" * 40
VERSION = "2026-Q3"
KMS_SIG_MESSAGE = ("registry not KMS-signed; run scripts/sign_registry.py --kms and commit "
                   "data/approved_models.json.kms.sig")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def deploy(monkeypatch):
    mod = _load("_deploy_requires_gate_artifact", PROJECT_ROOT / "cdk" / "deploy_agentcore_runtimes.py")
    monkeypatch.setattr(mod, "AGENTS", copy.deepcopy(mod.AGENTS))
    return mod


@pytest.fixture
def no_boto3(monkeypatch):
    calls = []

    def refuse(*a, **k):
        calls.append(a)
        raise AssertionError("boto3 must not be reached")

    monkeypatch.setattr(boto3, "client", refuse)
    monkeypatch.setattr(boto3, "Session", refuse)
    monkeypatch.setattr(boto3, "resource", refuse)
    return calls


def _kms(valid=True):
    return _fake_kms(valid)


# ─── Packaging ──────────────────────────────────────────────────────────────

def _reroot(value, old_root, new_root):
    if isinstance(value, Path):
        return new_root / value.relative_to(old_root)
    if isinstance(value, list):
        return [_reroot(v, old_root, new_root) for v in value]
    if isinstance(value, tuple):
        return tuple(_reroot(v, old_root, new_root) for v in value)
    return value


@pytest.fixture
def tree_copy(deploy, tmp_path, monkeypatch):
    """A copy of the packaged tree with PROJECT_ROOT/AGENTS rerooted and pip
    intercepted (nothing is written into the repo)."""
    ignore = shutil.ignore_patterns("__pycache__", "lib", "*.pyc")
    for rel in ("agentcore", "lambdas", "governance_common", "data"):
        shutil.copytree(PROJECT_ROOT / rel, tmp_path / rel, ignore=ignore)
    shutil.copy2(PROJECT_ROOT / "model_assurance.py", tmp_path / "model_assurance.py")
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "AGENTS", [{k: _reroot(v, PROJECT_ROOT, tmp_path) for k, v in cfg.items()}
                                           for cfg in deploy.AGENTS])
    monkeypatch.setattr(deploy.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0))
    return tmp_path


def _run_package_only(deploy, monkeypatch, *flags):
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py", "--package-only", *flags])
    deploy.main()


def test_package_only_without_kms_sig_exits_before_any_zip(deploy, tree_copy, monkeypatch, capsys, no_boto3):
    with pytest.raises(SystemExit) as info:
        _run_package_only(deploy, monkeypatch)
    assert info.value.code == 1
    assert KMS_SIG_MESSAGE in capsys.readouterr().out
    assert list((tree_copy / "build" / "agentcore").glob("*.zip")) == []
    assert no_boto3 == []


def test_package_only_bundles_the_kms_sig_and_clears_the_marker(deploy, tree_copy, monkeypatch, no_boto3):
    kms_sig = b'{"algorithm": "KMS_ECDSA_SHA_256", "fake": true}\n'
    (tree_copy / "data" / "approved_models.json.kms.sig").write_bytes(kms_sig)
    build = tree_copy / "build" / "agentcore"
    build.mkdir(parents=True)
    (build / "LOCAL_DEV_BUILD").write_text("local-dev\n")
    _run_package_only(deploy, monkeypatch)
    with zipfile.ZipFile(build / "ComplianceAgent.zip") as zf:
        assert zf.read("data/approved_models.json.sig") == kms_sig
    assert not (build / "LOCAL_DEV_BUILD").exists()
    assert {p.name for p in build.glob("*.zip")} == {"DetectionAgent.zip", "ComplianceAgent.zip", "ExecutorAgent.zip"}
    assert no_boto3 == []


def test_package_only_local_dev_maps_the_local_sig_and_writes_the_marker(deploy, tree_copy, monkeypatch, no_boto3):
    _run_package_only(deploy, monkeypatch, "--local-dev")
    build = tree_copy / "build" / "agentcore"
    with zipfile.ZipFile(build / "ComplianceAgent.zip") as zf:
        assert zf.read("data/approved_models.json.sig") == (tree_copy / "data" / "approved_models.json.sig").read_bytes()
    assert (build / "LOCAL_DEV_BUILD").read_text() == "local-dev\n"


def test_local_dev_flag_requires_package_only(deploy, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py", "--local-dev"])
    with pytest.raises(SystemExit) as info:
        deploy.main()
    assert info.value.code == 2


def test_local_dev_build_is_refused_by_gate_and_verifier(deploy, tree_copy, monkeypatch, no_boto3):
    _run_package_only(deploy, monkeypatch, "--local-dev")
    build = tree_copy / "build" / "agentcore"
    with pytest.raises(deploy._vga.GateArtifactError, match="local-dev build"):
        deploy._vga.check_gate_artifact(build, agents=deploy.AGENTS, repo_root=tree_copy)
    import compliance_gate
    monkeypatch.setattr(compliance_gate, "_git_path", lambda: "/usr/bin/git")
    monkeypatch.setattr(compliance_gate, "_git", lambda argv: subprocess.CompletedProcess(
        argv, 0, stdout={"status": b"", "rev-parse": (HEAD + "\n").encode()}.get(argv[1], b"")
        if argv[1:] != ["rev-parse", "--show-object-format"] else b"sha1\n"))
    gate = compliance_gate.ComplianceGate(sign_mode="kms", kms_client=_kms(), bundles_dir=str(build))
    gate.check_deploy_artifact_preconditions(agents=[])
    assert "local-dev build cannot be signed for deploy" in [r["description"] for r in gate.results if not r["passed"]]


# ─── verify_gate_artifact ───────────────────────────────────────────────────

class FakeGit:
    def __init__(self):
        self.tree = {}
        self.status = b""
        self.head = HEAD

    def __call__(self, argv):
        args = list(argv)[1:]
        out = {
            ("status", "--porcelain", "--untracked-files=all"): self.status,
            ("rev-parse", "HEAD"): (self.head + "\n").encode(),
            ("rev-parse", "--show-object-format"): b"sha1\n",
            ("ls-tree", "-r", "-z", "--full-tree", "HEAD"): b"".join(
                f"{m} blob {o}\t{p}".encode() + b"\0" for p, (m, o) in self.tree.items()),
        }[tuple(args)]
        return subprocess.CompletedProcess(argv, 0, stdout=out)


def _registry_envelope(registry, *, local_dev=False, now=None, version=VERSION):
    if local_dev:
        return signing.sign(signing.PURPOSE_REGISTRY, registry, local_dev=True, signed_by="local-dev",
                            version=version)
    return signing.sign(signing.PURPOSE_REGISTRY, registry, kms_client=_kms(), signed_by="approver",
                        version=version, pins=_pins(), now=now)


class FakeAccount:
    """STS / CloudFormation / SSM fakes for the deploy-time pin and floor checks."""

    def __init__(self):
        self.account = ACCOUNT
        self.outputs = {"RegistrySigningKeyArn": REGISTRY_KEY_ARN, "GateSigningKeyArn": GATE_KEY_ARN}
        self.floor = None             # parameter value (str) or None -> ParameterNotFound
        self.ssm_error = None
        self.cfn_error = None
        self.puts = []

    def sts(self):
        client = MagicMock()
        client.get_caller_identity.return_value = {"Account": self.account}
        return client

    def cfn(self):
        client = MagicMock()
        if self.cfn_error:
            client.describe_stacks.side_effect = self.cfn_error
        client.describe_stacks.return_value = {"Stacks": [{"Outputs": [
            {"OutputKey": k, "OutputValue": v} for k, v in self.outputs.items()]}]}
        return client

    def ssm(self):
        account = self

        class _Ssm:
            def get_parameter(self, Name):
                assert Name == "/fsi/governance/accepted-registry"
                if account.ssm_error:
                    raise account.ssm_error
                if account.floor is None:
                    raise ClientError({"Error": {"Code": "ParameterNotFound", "Message": "x"}}, "GetParameter")
                return {"Parameter": {"Value": account.floor}}

            def put_parameter(self, **kwargs):
                account.puts.append(kwargs)
                account.floor = kwargs["Value"]
        return _Ssm()

    def factories(self):
        return {"sts_client_factory": self.sts, "cfn_client_factory": self.cfn, "ssm_client_factory": self.ssm}


def _floor(version=VERSION, sha=None, gate_signed_at=None):
    return json.dumps({"registry_version": version,
                       "registry_sha256": sha or hashlib.sha256(
                           (PROJECT_ROOT / "data" / "approved_models.json").read_bytes()).hexdigest(),
                       "gate_signed_at": (gate_signed_at or datetime(2020, 1, 1, tzinfo=timezone.utc)).isoformat(),
                       "recorded_at": "2020-01-01T00:00:00+00:00"})


@pytest.fixture
def signed(deploy, tmp_path, monkeypatch):
    """Bundles at HEAD (fake ls-tree) plus a KMS-signed artifact over them."""
    build = tmp_path / "build" / "agentcore"
    gate_dir = tmp_path / "build" / "gate"
    build.mkdir(parents=True)
    gate_dir.mkdir(parents=True)
    git = FakeGit()
    registry = (PROJECT_ROOT / "data" / "approved_models.json").read_bytes()
    state = {"build": build, "gate_dir": gate_dir, "git": git, "registry": registry,
             "account": FakeAccount(), "pins_path": write_pins(tmp_path / "signing_key_pins.json")}

    def write(*, registry_local_dev=False, artifact_local_dev=False, expires=None, commit=HEAD,
              registry_signed_at=None, gate_signed_at=None, artifact_version=VERSION, gate_key_id=None,
              schema="fsi-gate-artifact/v2"):
        registry_sig = json.dumps(_registry_envelope(registry, local_dev=registry_local_dev,
                                                     now=registry_signed_at)).encode()
        digests = {}
        for cfg in deploy.AGENTS:
            entries = {"main.py": f"# {cfg['name']}\n".encode()}
            if cfg.get("registry_signature"):
                entries["data/approved_models.json"] = registry
                entries["data/approved_models.json.sig"] = registry_sig
            zip_path = build / f"{cfg['name']}.zip"
            with zipfile.ZipFile(zip_path, "w") as zf:
                for arcname, data in entries.items():
                    zf.writestr(arcname, data)
                    git.tree[head_binding.map_arcname(arcname, cfg, PROJECT_ROOT)] = (
                        "100644", head_binding.blob_id(data, "sha1"))
            digests[cfg["name"]] = bundle_digest.bundle_digest(zip_path)
        now = datetime.now(timezone.utc)
        artifact = {
            "schema": schema, "git_commit": commit, "tree_clean": True,
            "created_at": now.isoformat(), "expires_at": (expires or now + timedelta(minutes=60)).isoformat(),
            "assertions_total": 5, "assertions_passed": 5, "results_sha256": "0" * 64,
            "registry_sha256": hashlib.sha256(registry).hexdigest(), "registry_version": artifact_version,
            "bundles": digests,
            "gate_runner": "arn:aws:sts::123456789012:assumed-role/fsi-deploy-gate-signer/ci-1",
        }
        payload = signing.canonical_json(artifact)
        if artifact_local_dev:
            envelope = signing.sign(signing.PURPOSE_GATE, payload, local_dev=True, signed_by="local:x",
                                    version=artifact_version)
        else:
            envelope = signing.sign(signing.PURPOSE_GATE, payload, kms_client=_kms(), signed_by="signer",
                                    version=artifact_version, pins=_pins(), now=gate_signed_at)
        if gate_key_id:
            envelope["key_id"] = gate_key_id
        (gate_dir / "gate-artifact.json").write_bytes(payload)
        (gate_dir / "gate-artifact.json.sig").write_text(json.dumps(envelope))
        return hashlib.sha256(payload).hexdigest()

    state["write"] = write
    return state


def _kwargs(signed, kms=None, factory_calls=None):
    def factory():
        if factory_calls is not None:
            factory_calls.append(True)
        return kms or _kms()
    return dict(repo_root=PROJECT_ROOT, gate_dir=signed["gate_dir"], git=signed["git"], git_path="/usr/bin/git",
                kms_client_factory=factory, pins_path=signed["pins_path"], **signed["account"].factories())


def _verify(deploy, signed, kms=None):
    factory_calls = []
    sha = deploy._vga.verify_gate_artifact(signed["build"], agents=deploy.AGENTS,
                                           **_kwargs(signed, kms, factory_calls))
    return sha, factory_calls


def _refused(deploy, signed, capsys, match):
    with pytest.raises(SystemExit) as info:
        _verify(deploy, signed)
    assert info.value.code == 1
    assert match in capsys.readouterr().out


def test_all_valid_verifies(deploy, signed, no_boto3):
    expected = signed["write"]()
    sha, factory_calls = _verify(deploy, signed)
    assert sha == expected and factory_calls == [True]


def test_missing_artifact_exits_without_any_client(deploy, signed, capsys, no_boto3):
    _refused(deploy, signed, capsys, "gate artifact missing")
    assert no_boto3 == []


def test_expired_artifact_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](expires=datetime.now(timezone.utc) - timedelta(seconds=1))
    _refused(deploy, signed, capsys, "expired")


def test_local_dev_signed_artifact_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](artifact_local_dev=True)
    _refused(deploy, signed, capsys, "not KMS-signed")


def test_commit_mismatch_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](commit="c" * 40)
    _refused(deploy, signed, capsys, "does not match HEAD")


def test_dirty_tree_now_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    signed["git"].status = b"?? lambdas/compliance_agent/boto3.py\n"
    _refused(deploy, signed, capsys, "working tree not clean: ?? lambdas/compliance_agent/boto3.py")


def test_one_changed_bundle_byte_is_a_digest_mismatch(deploy, signed, capsys, no_boto3):
    signed["write"]()
    zip_path = signed["build"] / "ExecutorAgent.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("main.py", b"# ExecutorAgent!\n")
    signed["git"].tree["agentcore/executor_agent/main.py"] = ("100644", head_binding.blob_id(b"# ExecutorAgent!\n", "sha1"))
    _refused(deploy, signed, capsys, "digest does not match")


def test_packaged_source_not_at_head_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    signed["git"].tree.pop("agentcore/detection_agent/main.py")
    _refused(deploy, signed, capsys, "packaged source not at HEAD: main.py")


def test_kms_artifact_with_local_dev_bundled_registry_is_refused_before_any_client(
        deploy, signed, capsys, no_boto3):
    signed["write"](registry_local_dev=True)
    with pytest.raises(SystemExit) as info:
        _, _ = _verify(deploy, signed)
    assert info.value.code == 1
    assert "bundled registry is not KMS-signed" in capsys.readouterr().out
    assert no_boto3 == []


def test_invalid_kms_signature_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    with pytest.raises(SystemExit) as info:
        _verify(deploy, signed, kms=_kms(valid=False))
    assert info.value.code == 1
    assert "signature verification failed" in capsys.readouterr().out


# ─── Default deploy mode ────────────────────────────────────────────────────

def test_default_deploy_never_builds_and_needs_prebuilt_zips(deploy, tmp_path, monkeypatch, capsys, no_boto3):
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "package_agent", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py"])
    with pytest.raises(SystemExit) as info:
        deploy.main()
    assert info.value.code == 1
    assert "run make package" in capsys.readouterr().out
    assert no_boto3 == []


def test_default_deploy_verifies_before_any_client(deploy, tmp_path, monkeypatch, no_boto3):
    build = tmp_path / "build" / "agentcore"
    build.mkdir(parents=True)
    for cfg in deploy.AGENTS:
        (build / f"{cfg['name']}.zip").write_bytes(b"")
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy, "package_agent", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    order = []

    def refuse(build_dir):
        order.append(("verify", Path(build_dir)))
        raise SystemExit(1)

    monkeypatch.setattr(deploy, "verify_gate_artifact", refuse)
    monkeypatch.setattr(deploy, "get_account_id", lambda: order.append("sts") or "123456789012")
    monkeypatch.setattr(sys, "argv", ["deploy_agentcore_runtimes.py"])
    with pytest.raises(SystemExit):
        deploy.main()
    assert order == [("verify", build)]
    assert no_boto3 == []


def test_verified_bundle_is_uploaded_with_the_embedded_artifact(deploy, signed, monkeypatch):
    sha = signed["write"]()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", signed["build"].parent.parent)
    monkeypatch.setattr(deploy, "_VERIFIED_GATE_ARTIFACT_SHA256", sha)
    s3, agentcore = MagicMock(), MagicMock()
    agentcore.list_agent_runtimes.return_value = {"agentRuntimes": []}
    agentcore.create_agent_runtime.return_value = {"agentRuntimeArn": "arn:x", "status": "CREATING"}
    monkeypatch.setattr(deploy.boto3, "client", lambda name, region_name=None: {
        "s3": s3, "bedrock-agentcore-control": agentcore}[name])
    cfg = deploy.AGENTS[1]
    zip_path = signed["build"] / "ComplianceAgent.zip"
    assert deploy.deploy_agent(cfg, zip_path, "bucket", "123456789012") == "arn:x"
    uploaded, _bucket, _key = s3.upload_file.call_args.args
    extra = s3.upload_file.call_args.kwargs["ExtraArgs"]
    assert extra["Metadata"] == {"gate-artifact-sha256": sha}
    assert extra["ExpectedBucketOwner"] == "123456789012"
    with zipfile.ZipFile(uploaded) as zf:
        assert hashlib.sha256(zf.read("governance/gate-artifact.json")).hexdigest() == sha
        assert "governance/gate-artifact.json.sig" in zf.namelist()
    assert bundle_digest.bundle_digest(uploaded) == bundle_digest.bundle_digest(zip_path)
    env = agentcore.create_agent_runtime.call_args.kwargs["environmentVariables"]
    assert env["GATE_ARTIFACT_SHA256"] == sha


def test_deploy_agent_refuses_an_unverified_artifact(deploy, signed, monkeypatch, capsys, no_boto3):
    signed["write"]()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", signed["build"].parent.parent)
    monkeypatch.setattr(deploy, "_VERIFIED_GATE_ARTIFACT_SHA256", "f" * 64)
    with pytest.raises(SystemExit) as info:
        deploy.deploy_agent(deploy.AGENTS[0], signed["build"] / "DetectionAgent.zip", "b", "123456789012")
    assert info.value.code == 1
    assert "not the one verified" in capsys.readouterr().out
    assert no_boto3 == []


# ─── Pinned keys, freshness and the registry floor ─────────────

def test_alias_repoint_does_not_yield_an_accepted_signature(deploy, signed, capsys, no_boto3):
    """An attacker re-points the alias to their key and signs with it; KMS
    would report the signature valid for any KeyId. The verifier compares
    against the pinned ARN, so it is refused, and DescribeKey is never called."""
    signed["write"](gate_key_id=ATTACKER_KEY_ARN)
    kms = _kms()
    kms.describe_key.side_effect = lambda **k: {"KeyMetadata": {"Arn": ATTACKER_KEY_ARN}}
    with pytest.raises(SystemExit):
        _verify(deploy, signed, kms=kms)
    assert "not the pinned signing key" in capsys.readouterr().out
    kms.describe_key.assert_not_called()
    kms.verify.assert_not_called()


def test_both_signatures_verify_with_the_pinned_arns(deploy, signed, no_boto3):
    signed["write"]()
    kms = _kms()
    _verify(deploy, signed, kms=kms)
    assert [c.kwargs["KeyId"] for c in kms.verify.call_args_list] == [GATE_KEY_ARN, REGISTRY_KEY_ARN]
    kms.describe_key.assert_not_called()


def test_account_mismatch_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    signed["account"].account = "999999999999"
    _refused(deploy, signed, capsys, "pins are for another account")


@pytest.mark.parametrize("output", ["RegistrySigningKeyArn", "GateSigningKeyArn"])
def test_stack_output_mismatch_is_refused(deploy, signed, capsys, no_boto3, output):
    signed["write"]()
    signed["account"].outputs[output] = ATTACKER_KEY_ARN
    _refused(deploy, signed, capsys, f"{output} of FsiComplianceAgents does not match")


def test_missing_stack_output_or_read_error_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    del signed["account"].outputs["GateSigningKeyArn"]
    _refused(deploy, signed, capsys, "GateSigningKeyArn of FsiComplianceAgents does not match")
    signed["account"].cfn_error = ClientError({"Error": {"Code": "AccessDenied", "Message": "m"}}, "DescribeStacks")
    _refused(deploy, signed, capsys, "could not read the account or the FsiComplianceAgents stack")


def test_pins_region_mismatch_is_refused(deploy, signed, capsys, no_boto3, tmp_path):
    signed["write"]()
    signed["pins_path"] = write_pins(
        tmp_path / "eu.json", region="eu-west-1",
        keys={"approved-models-registry": REGISTRY_KEY_ARN.replace("us-east-1", "eu-west-1"),
              "deploy-gate-artifact": GATE_KEY_ARN.replace("us-east-1", "eu-west-1")})
    _refused(deploy, signed, capsys, "pins are for region eu-west-1")


def test_unpinned_repo_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    signed["pins_path"] = str(PROJECT_ROOT / "data" / "signing_key_pins.json")  # shipped: nothing pinned
    _refused(deploy, signed, capsys, "pins are for region None")


def test_stale_gate_signature_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](gate_signed_at=datetime.now(timezone.utc) - timedelta(seconds=3700))
    _refused(deploy, signed, capsys, "stale")


def test_future_dated_signature_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](registry_signed_at=datetime.now(timezone.utc) + timedelta(minutes=10))
    _refused(deploy, signed, capsys, "future-dated")


def test_registry_expiry_warning(deploy, signed, capsys, no_boto3):
    signed["write"](registry_signed_at=datetime.now(timezone.utc) - timedelta(days=110))
    _verify(deploy, signed)
    assert "WARNING: registry signature expires in 9 days" in capsys.readouterr().out
    signed["write"](registry_signed_at=datetime.now(timezone.utc) - timedelta(days=30))
    _verify(deploy, signed)
    assert "WARNING" not in capsys.readouterr().out
    signed["write"](registry_signed_at=datetime.now(timezone.utc) - timedelta(days=121))
    _refused(deploy, signed, capsys, "stale")


def test_artifact_registry_version_must_match_the_bundled_registry(deploy, signed, capsys, no_boto3):
    signed["write"](artifact_version="2026-Q2")
    _refused(deploy, signed, capsys, "registry_version does not match the bundled registry")


def test_v1_artifact_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"](schema="fsi-gate-artifact/v1")
    _refused(deploy, signed, capsys, "v1 artifacts are refused")


def test_first_deploy_without_a_floor_is_allowed(deploy, signed, capsys, no_boto3):
    signed["write"]()
    _verify(deploy, signed)
    assert "not set yet (first deploy)" in capsys.readouterr().out


@pytest.mark.parametrize("floor,match", [
    (lambda: _floor(version="2026-Q4"), "older than the accepted registry floor"),
    (lambda: _floor(sha="0" * 64), "differs from the accepted registry at the same version"),
    (lambda: _floor(gate_signed_at=datetime.now(timezone.utc) + timedelta(minutes=1)),
     "signed before the accepted floor's gate signature"),
    (lambda: "not json", "is malformed"),
])
def test_floor_refusals(deploy, signed, capsys, no_boto3, floor, match):
    signed["write"]()
    signed["account"].floor = floor()
    _refused(deploy, signed, capsys, match)


def test_floor_read_error_is_refused(deploy, signed, capsys, no_boto3):
    signed["write"]()
    signed["account"].ssm_error = ClientError({"Error": {"Code": "AccessDeniedException", "Message": "m"}},
                                              "GetParameter")
    _refused(deploy, signed, capsys, "could not read /fsi/governance/accepted-registry")


def test_equal_or_higher_floor_passes(deploy, signed, no_boto3):
    signed["write"]()
    signed["account"].floor = _floor(version="2026-Q2")
    _verify(deploy, signed)
    signed["account"].floor = _floor()
    _verify(deploy, signed)


def test_record_accepted_raises_and_never_lowers_the_floor(deploy, signed, no_boto3):
    signed["write"]()
    account = signed["account"]
    account.floor = _floor(version="2026-Q2")
    info = deploy._vga.record_accepted(signed["build"], agents=deploy.AGENTS, **_kwargs(signed))
    (put,) = account.puts
    assert put["Name"] == "/fsi/governance/accepted-registry" and put["Overwrite"] is True
    assert put["Type"] == "String"
    recorded = json.loads(put["Value"])
    assert recorded["registry_version"] == VERSION and recorded["registry_sha256"] == info["registry_sha256"]
    assert set(recorded) == {"registry_version", "registry_sha256", "gate_signed_at", "recorded_at"}
    # A higher floor is never lowered.
    account.floor = _floor(version="2026-Q4")
    with pytest.raises(deploy._vga.GateArtifactError, match="older than the accepted registry floor"):
        deploy._vga.record_accepted(signed["build"], agents=deploy.AGENTS, **_kwargs(signed))
    assert len(account.puts) == 1


def test_record_accepted_cli_failure_message(deploy, signed, monkeypatch, capsys):
    monkeypatch.setattr(deploy._vga, "record_accepted",
                        lambda *a, **k: (_ for _ in ()).throw(deploy._vga.GateArtifactError("boom")))
    monkeypatch.setattr(deploy._vga, "_load_agents", lambda: [])
    assert deploy._vga.main(["--record-accepted"]) == 1
    assert "deployed, but the accepted floor was not recorded" in capsys.readouterr().out


def test_makefile_deploy_records_the_floor():
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    deploy_recipe = makefile.split("\ndeploy:", 1)[1].split("\n\n", 1)[0]
    assert "scripts/verify_gate_artifact.py --record-accepted" in deploy_recipe
    assert "\nrecord-accepted:" in makefile
