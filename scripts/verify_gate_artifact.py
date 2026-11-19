#!/usr/bin/env python3
"""
Verify the signed gate artifact against the bundles about to be deployed.
Used by `make verify-gate-artifact` and,
as a function, by cdk/deploy_agentcore_runtimes.py before ANY S3/AgentCore
client is built.

Every local check runs first; only then are the deployer's own read-only
clients built: STS (account), CloudFormation (the stack's signing-key
outputs), KMS (the two signatures against the PINNED key ARNs in
data/signing_key_pins.json, never an alias) and SSM (the accepted-registry
floor). Any failure exits 1 with a specific message and nothing is uploaded:

  - build/agentcore/LOCAL_DEV_BUILD marker present        -> refused
  - artifact / signature missing or malformed            -> refused
  - artifact or bundled registry signed LOCAL_DEV         -> refused
  - now >= expires_at                                     -> refused
  - git_commit != HEAD, tree_clean false, or dirty now    -> refused
  - any packaged source not byte-identical to HEAD        -> refused
  - recomputed bundle digests != artifact "bundles"       -> refused
  - bundled registry sha256 != registry_sha256            -> refused
  - pins region / account != the deploy target, or the
    stack's RegistrySigningKeyArn / GateSigningKeyArn != pins -> refused
  - KMS verification of artifact or bundled registry fails-> refused
  - a signature older than its max age, or future-dated    -> refused
  - artifact registry_version != bundled registry's        -> refused
  - registry older than /fsi/governance/accepted-registry  -> refused
    (same version with other bytes, or an older gate signature, too)

--record-accepted (make record-accepted, run by make deploy after the
runtime deploy) re-verifies the artifact and raises the floor; it never
lowers it.

Usage:
    python scripts/verify_gate_artifact.py [--bundles-dir build/agentcore] [--record-accepted]
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sys
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from governance_common import bundle_digest, head_binding, signing  # noqa: E402
import model_assurance  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")
ARTIFACT_SCHEMA = "fsi-gate-artifact/v2"
AGENTS_STACK = "FsiComplianceAgents"
STACK_KEY_OUTPUTS = {signing.PURPOSE_REGISTRY: "RegistrySigningKeyArn",
                     signing.PURPOSE_GATE: "GateSigningKeyArn"}
ACCEPTED_REGISTRY_PARAMETER = "/fsi/governance/accepted-registry"
REGISTRY_EXPIRY_WARNING_DAYS = 14
_FLOOR_KEYS = frozenset({"registry_version", "registry_sha256", "gate_signed_at", "recorded_at"})
ARTIFACT_NAME = "gate-artifact.json"
AGENT_NAMES = ("DetectionAgent", "ComplianceAgent", "ExecutorAgent")
REGISTRY_ARCNAME = "data/approved_models.json"
_MAX_ARTIFACT_BYTES = 1024 * 1024
_ARTIFACT_KEYS = frozenset({
    "schema", "git_commit", "tree_clean", "created_at", "expires_at", "assertions_total",
    "assertions_passed", "results_sha256", "registry_sha256", "registry_version", "bundles",
    "gate_runner",
})


class GateArtifactError(Exception):
    """Verification refused; the message says why."""


def _default_client(service):
    def factory():
        import boto3  # deferred: built only after every local check passed
        return boto3.client(service, region_name=REGION)
    return factory


_default_kms_client = _default_client("kms")


def _read(path: Path, what: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise GateArtifactError(f"{what} missing ({path.name}); run make gate-sign") from exc
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise GateArtifactError(f"{what} too large")
    return data


def _parse_time(value) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise GateArtifactError("gate artifact has a malformed expires_at") from exc
    if parsed.tzinfo is None:
        raise GateArtifactError("gate artifact expires_at has no timezone")
    return parsed


def _client_error_code(exc) -> str:
    response = getattr(exc, "response", None)
    return str(response.get("Error", {}).get("Code", "")) if isinstance(response, dict) else ""


def _check_pins_against_target(pins, sts_client_factory, cfn_client_factory) -> None:
    """The pins must name this region, the deployer's account, and exactly
    the signing keys the deployed stack outputs."""
    if pins.region != REGION:
        raise GateArtifactError(f"signing key pins are for region {pins.region}, not {REGION}; "
                                "run scripts/pin_signing_keys.py")
    try:
        account = (sts_client_factory or _default_client("sts"))().get_caller_identity()["Account"]
        stacks = (cfn_client_factory or _default_client("cloudformation"))().describe_stacks(
            StackName=AGENTS_STACK)["Stacks"]
    except Exception as exc:  # noqa: BLE001 - any read failure refuses the deploy
        raise GateArtifactError(f"could not read the account or the {AGENTS_STACK} stack "
                                f"({type(exc).__name__})") from exc
    if pins.account != account:
        raise GateArtifactError("signing key pins are for another account; run scripts/pin_signing_keys.py")
    outputs = {o.get("OutputKey"): o.get("OutputValue")
               for stack in stacks[:1] for o in stack.get("Outputs", [])}
    for purpose, output in STACK_KEY_OUTPUTS.items():
        pinned = pins.key_arn(purpose)
        if not pinned or not outputs.get(output) or not hmac.compare_digest(str(outputs[output]), pinned):
            raise GateArtifactError(f"{output} of {AGENTS_STACK} does not match the pinned {purpose} key; "
                                    "run scripts/pin_signing_keys.py and commit the pins")


def _read_floor(ssm_client):
    """The accepted-registry floor, or None when the parameter doesn't exist
    yet (first deploy). Any other error or a malformed value refuses."""
    try:
        value = ssm_client.get_parameter(Name=ACCEPTED_REGISTRY_PARAMETER)["Parameter"]["Value"]
    except Exception as exc:  # noqa: BLE001
        if _client_error_code(exc) == "ParameterNotFound":
            return None
        raise GateArtifactError(f"could not read {ACCEPTED_REGISTRY_PARAMETER} ({type(exc).__name__})") from exc
    try:
        floor = json.loads(value)
        if not isinstance(floor, dict) or set(floor) != _FLOOR_KEYS:
            raise ValueError("unexpected keys")
        version = model_assurance.parse_registry_version(floor["registry_version"])
        gate_signed_at = datetime.fromisoformat(floor["gate_signed_at"])
        if gate_signed_at.tzinfo is None or not isinstance(floor["registry_sha256"], str):
            raise ValueError("malformed")
    except (ValueError, TypeError, KeyError) as exc:
        raise GateArtifactError(f"{ACCEPTED_REGISTRY_PARAMETER} is malformed") from exc
    return {"version": version, "sha256": floor["registry_sha256"], "gate_signed_at": gate_signed_at}


def _check_floor(floor, version, registry_sha256, gate_signed_at) -> None:
    if floor is None:
        return
    if version < floor["version"]:
        raise GateArtifactError("registry_version is older than the accepted registry floor")
    if version == floor["version"] and not hmac.compare_digest(registry_sha256, floor["sha256"]):
        raise GateArtifactError("registry content differs from the accepted registry at the same version")
    if gate_signed_at < floor["gate_signed_at"]:
        raise GateArtifactError("gate artifact was signed before the accepted floor's gate signature")


def check_gate_artifact(build_dir, *, agents, gate_dir=None, repo_root=None, git=None, git_path=None,
                        kms_client_factory=None, cfn_client_factory=None, ssm_client_factory=None,
                        sts_client_factory=None, pins_path=None, now=None) -> str:
    """Raise GateArtifactError unless the artifact authorizes these bundles.
    Returns sha256(artifact bytes) on success."""
    return _check(build_dir, agents=agents, gate_dir=gate_dir, repo_root=repo_root, git=git,
                  git_path=git_path, kms_client_factory=kms_client_factory,
                  cfn_client_factory=cfn_client_factory, ssm_client_factory=ssm_client_factory,
                  sts_client_factory=sts_client_factory, pins_path=pins_path, now=now)["sha256"]


def _check(build_dir, *, agents, gate_dir, repo_root, git, git_path, kms_client_factory,
           cfn_client_factory, ssm_client_factory, sts_client_factory, pins_path, now) -> dict:
    build_dir = Path(build_dir)
    repo_root = Path(repo_root or PROJECT_ROOT)
    gate_dir = Path(gate_dir or repo_root / "build" / "gate")
    now = now or datetime.now(timezone.utc)

    if (build_dir / head_binding.LOCAL_DEV_MARKER).exists():
        raise GateArtifactError("local-dev build cannot be deployed (LOCAL_DEV_BUILD marker present); "
                                "run make package")

    artifact_bytes = _read(gate_dir / ARTIFACT_NAME, "gate artifact")
    sig_bytes = _read(gate_dir / (ARTIFACT_NAME + ".sig"), "gate artifact signature")
    try:
        artifact = json.loads(artifact_bytes)
        envelope = json.loads(sig_bytes)
    except ValueError as exc:
        raise GateArtifactError("gate artifact or signature is not JSON") from exc
    if not isinstance(artifact, dict) or set(artifact) != _ARTIFACT_KEYS:
        raise GateArtifactError("gate artifact has unexpected fields")
    if artifact["schema"] != ARTIFACT_SCHEMA:
        raise GateArtifactError("gate artifact has an unknown schema (v1 artifacts are refused; "
                                "run make gate-sign again)")
    if not isinstance(envelope, dict) or envelope.get("algorithm") != signing.ALG_KMS:
        raise GateArtifactError("gate artifact is not KMS-signed (local-dev artifacts are refused)")
    if not now < _parse_time(artifact["expires_at"]):
        raise GateArtifactError("gate artifact expired; run make gate-sign again")
    if artifact["tree_clean"] is not True:
        raise GateArtifactError("gate artifact was produced from a dirty tree")
    if artifact.get("assertions_total") != artifact.get("assertions_passed"):
        raise GateArtifactError("gate artifact records failing assertions")

    git_path = git_path if git_path is not None else (shutil.which("git") or "")
    if not git_path:
        raise GateArtifactError("git is required to verify the artifact against HEAD")
    git = git or head_binding.default_git_runner(repo_root)
    try:
        head = head_binding.rev_parse_head(git, git_path)
        status = head_binding.porcelain_status(git, git_path)
        fmt = head_binding.object_format(git, git_path)
        tree = head_binding.head_tree(git, git_path)
    except head_binding.HeadBindingError as exc:
        raise GateArtifactError(f"could not read git state ({exc})") from exc
    if not hmac.compare_digest(str(artifact["git_commit"]), head):
        raise GateArtifactError("gate artifact commit does not match HEAD")
    if status:
        raise GateArtifactError("working tree not clean: " + "; ".join(status[:10]))

    by_name = {cfg["name"]: cfg for cfg in agents}
    bundles = artifact["bundles"]
    if not isinstance(bundles, dict) or set(bundles) != set(AGENT_NAMES):
        raise GateArtifactError("gate artifact does not name exactly the three agent bundles")
    registry_bytes = registry_sig_bytes = None
    for name in AGENT_NAMES:
        zip_path = build_dir / f"{name}.zip"
        if not zip_path.is_file():
            raise GateArtifactError(f"bundle build/agentcore/{name}.zip missing; run make package")
        try:
            offending = head_binding.check_bundle_at_head(
                zip_path, by_name[name], git_path=git_path, repo_root=repo_root,
                local_dev=False, git=git, tree=tree, fmt=fmt)
            digest = bundle_digest.bundle_digest(zip_path)
        except (OSError, ValueError, KeyError, zipfile.BadZipFile, head_binding.HeadBindingError) as exc:
            raise GateArtifactError(f"bundle {name}.zip unreadable ({type(exc).__name__})") from exc
        if offending:
            raise GateArtifactError(f"packaged source not at HEAD: {offending[0]}")
        if not hmac.compare_digest(str(bundles[name]), digest):
            raise GateArtifactError(f"bundle {name}.zip digest does not match the gate artifact")
        if name == "ComplianceAgent":
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    registry_bytes = zf.read(REGISTRY_ARCNAME)
                    registry_sig_bytes = zf.read(head_binding.REGISTRY_SIGNATURE_ARCNAME)
            except KeyError as exc:
                raise GateArtifactError("ComplianceAgent bundle lacks the registry or its signature") from exc

    if not hmac.compare_digest(hashlib.sha256(registry_bytes).hexdigest(), str(artifact["registry_sha256"])):
        raise GateArtifactError("bundled registry does not match the gate artifact")
    try:
        registry_envelope = json.loads(registry_sig_bytes)
    except ValueError as exc:
        raise GateArtifactError("bundled registry signature is not JSON") from exc
    if not isinstance(registry_envelope, dict) or registry_envelope.get("algorithm") != signing.ALG_KMS:
        raise GateArtifactError("bundled registry is not KMS-signed (local-dev signatures are refused)")
    try:
        registry_version = model_assurance.load_registry(data=registry_bytes).get("registry_version")
        parsed_version = model_assurance.parse_registry_version(registry_version)
    except ValueError as exc:
        raise GateArtifactError(f"bundled registry has no valid registry_version ({exc})") from exc
    if artifact["registry_version"] != registry_version:
        raise GateArtifactError("gate artifact registry_version does not match the bundled registry")
    try:
        pins = signing.load_key_pins(str(pins_path or repo_root / "data" / "signing_key_pins.json"))
    except signing.SignatureError as exc:
        raise GateArtifactError(f"{exc}; run scripts/pin_signing_keys.py") from exc

    # Only now: the deployer's own read-only clients.
    _check_pins_against_target(pins, sts_client_factory, cfn_client_factory)
    kms_client = (kms_client_factory or _default_kms_client)()
    try:
        gate_signed_at = signing.verify(
            signing.PURPOSE_GATE, artifact_bytes, envelope, kms_client=kms_client, require_kms=True,
            pins=pins, max_age_seconds=pins.max_signature_age(signing.PURPOSE_GATE),
            expected_version=registry_version, now=now)
        registry_max_age = pins.max_signature_age(signing.PURPOSE_REGISTRY)
        registry_signed_at = signing.verify(
            signing.PURPOSE_REGISTRY, registry_bytes, registry_envelope, kms_client=kms_client,
            require_kms=True, pins=pins, max_age_seconds=registry_max_age,
            expected_version=registry_version, now=now)
    except signing.SignatureError as exc:
        raise GateArtifactError(f"signature verification failed ({type(exc).__name__}: {exc})") from exc
    remaining = registry_signed_at + timedelta(seconds=registry_max_age) - now
    if remaining < timedelta(days=REGISTRY_EXPIRY_WARNING_DAYS):
        print(f"  WARNING: registry signature expires in {max(remaining.days, 0)} days; "
              "re-sign (sign_registry.py --kms) and redeploy")

    registry_sha256 = hashlib.sha256(registry_bytes).hexdigest()
    ssm_client = (ssm_client_factory or _default_client("ssm"))()
    floor = _read_floor(ssm_client)
    if floor is None:
        print(f"  notice: {ACCEPTED_REGISTRY_PARAMETER} not set yet (first deploy); "
              "make record-accepted records it")
    _check_floor(floor, parsed_version, registry_sha256, gate_signed_at)
    return {"sha256": hashlib.sha256(artifact_bytes).hexdigest(), "registry_version": registry_version,
            "parsed_version": parsed_version, "registry_sha256": registry_sha256,
            "gate_signed_at": gate_signed_at, "ssm_client": ssm_client}


def record_accepted(build_dir, *, agents, now=None, **kwargs) -> dict:
    """Re-verify the artifact, then raise the accepted-registry floor to it.
    Never lowers the floor (the floor is re-read just before the write)."""
    now = now or datetime.now(timezone.utc)
    info = _check(build_dir, agents=agents, now=now, **{
        k: kwargs.get(k) for k in ("gate_dir", "repo_root", "git", "git_path", "kms_client_factory",
                                   "cfn_client_factory", "ssm_client_factory", "sts_client_factory",
                                   "pins_path")})
    ssm_client = info["ssm_client"]
    floor = _read_floor(ssm_client)
    _check_floor(floor, info["parsed_version"], info["registry_sha256"], info["gate_signed_at"])
    if floor is not None and (info["parsed_version"], info["gate_signed_at"]) < (
            floor["version"], floor["gate_signed_at"]):
        raise GateArtifactError("refusing to lower the accepted registry floor")
    value = json.dumps({"registry_version": info["registry_version"],
                        "registry_sha256": info["registry_sha256"],
                        "gate_signed_at": info["gate_signed_at"].isoformat(),
                        "recorded_at": now.isoformat()}, sort_keys=True)
    try:
        ssm_client.put_parameter(Name=ACCEPTED_REGISTRY_PARAMETER, Value=value, Type="String",
                                 Overwrite=True)
    except Exception as exc:  # noqa: BLE001
        raise GateArtifactError(f"could not write {ACCEPTED_REGISTRY_PARAMETER} ({type(exc).__name__})") from exc
    return info


def verify_gate_artifact(build_dir, *, agents, **kwargs) -> str:
    """check_gate_artifact, but exit 1 with the reason on any refusal."""
    try:
        return check_gate_artifact(build_dir, agents=agents, **kwargs)
    except GateArtifactError as exc:
        print(f"  ✗ Gate artifact verification failed: {exc}. Nothing deployed.")
        sys.exit(1)


def _load_agents():
    path = PROJECT_ROOT / "cdk" / "deploy_agentcore_runtimes.py"
    spec = importlib.util.spec_from_file_location("_verify_deploy_agentcore_runtimes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AGENTS


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify the signed gate artifact before deploy")
    parser.add_argument("--bundles-dir", default=str(PROJECT_ROOT / "build" / "agentcore"))
    parser.add_argument("--record-accepted", action="store_true",
                        help="After a successful deploy: raise /fsi/governance/accepted-registry "
                             "to this artifact's registry (never lowers it)")
    args = parser.parse_args(argv)
    if args.record_accepted:
        try:
            info = record_accepted(args.bundles_dir, agents=_load_agents())
        except GateArtifactError as exc:
            print(f"  ✗ deployed, but the accepted floor was not recorded ({exc}); "
                  "re-run make record-accepted")
            return 1
        print(f"  ✓ accepted registry floor recorded: {info['registry_version']}")
        return 0
    sha = verify_gate_artifact(args.bundles_dir, agents=_load_agents())
    print(f"  ✓ Gate artifact verified (sha256 {sha})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
