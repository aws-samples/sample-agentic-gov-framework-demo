"""
Deploy AgentCore Runtimes — Post-CDK deployment script.

Run AFTER `cdk deploy` to create/update AgentCore Runtimes using the
IAM roles and S3 bucket provisioned by CDK.

Usage (the Makefile chain is `make deploy` = package -> gate-sign ->
verify-gate-artifact -> cdk deploy -> this script):
    python cdk/deploy_agentcore_runtimes.py --package-only [--local-dev]
    python cdk/deploy_agentcore_runtimes.py            # deploy prebuilt bundles

Prerequisites:
    - CDK stack deployed (provides IAM roles + code bucket)
    - AWS credentials configured with AgentCore permissions
    - build/agentcore/<Agent>.zip built by --package-only and a KMS-signed
      gate artifact (build/gate/gate-artifact.json) for exactly those bytes;
      the deploy never rebuilds and refuses anything else
"""
import argparse
import boto3
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 -- static pip argv, list form, no shell (see the nosec B603 on the call)
import sys
import zipfile
from pathlib import Path

# Configuration
REGION = os.environ.get("AWS_REGION", "us-east-1")
PROJECT_ROOT = Path(__file__).parent.parent

# Gate-artifact verification lives in scripts/verify_gate_artifact.py
# (also run by `make verify-gate-artifact`); load it by path, no sys.path edit.
_vga_spec = importlib.util.spec_from_file_location(
    "_deploy_verify_gate_artifact", Path(__file__).resolve().parent.parent / "scripts" / "verify_gate_artifact.py")
_vga = importlib.util.module_from_spec(_vga_spec)
_vga_spec.loader.exec_module(_vga)
from governance_common import bundle_digest  # noqa: E402  (repo root put on sys.path by the loader above)
from governance_common import runtime_pins  # noqa: E402

REGISTRY_SIGNATURE_ARCNAME = "data/approved_models.json.sig"
LOCAL_DEV_MARKER = "LOCAL_DEV_BUILD"
KMS_SIG_MISSING_MESSAGE = (
    "registry not KMS-signed; run scripts/sign_registry.py --kms and commit "
    "data/approved_models.json.kms.sig")
GATE_ARTIFACT_NAME = "gate-artifact.json"
GATE_ARTIFACT_ARCNAMES = ("governance/gate-artifact.json", "governance/gate-artifact.json.sig")

# sha256 of the gate artifact verify_gate_artifact() accepted in this process;
# deploy_agent() refuses to upload anything else.
_VERIFIED_GATE_ARTIFACT_SHA256 = None


class RegistryNotKmsSignedError(FileNotFoundError):
    """data/approved_models.json.kms.sig is missing for a deploy build."""

# Fixed command prefix for dependency installs: the absolute path of the
# running interpreter plus static pip arguments. No shell, no user input.
_PIP_INSTALL = (sys.executable, "-m", "pip", "install")


def _confined(path: Path, root: Path) -> Path:
    """Resolve `path` (following symlinks) and refuse it unless it sits under
    `root`. Guards every filesystem argument handed to the pip subprocess."""
    resolved = Path(path).resolve()
    base = Path(root).resolve()
    if not resolved.is_relative_to(base):
        raise ValueError(f"Refusing path outside {base}: {resolved}")
    return resolved

# Agent definitions
AGENTS = [
    {
        "name": "DetectionAgent",
        "code_dir": PROJECT_ROOT / "agentcore" / "detection_agent",
        "extra_dirs": [PROJECT_ROOT / "lambdas" / "detection_agent"],  # Include handler + modules
        # Shared packages written under <package name>/ at the zip root, which
        # is on sys.path in the runtime. main.py imports
        # governance_common.payload_limits.
        "packages": [PROJECT_ROOT / "governance_common"],
        # The handler's dataset allowlist resolves
        # "sample-small" under ALLOWED_TXN_DIR, which in the zip is
        # /var/task/data (fraud_detection.py's project root is /var/task).
        "root_files": [
            (PROJECT_ROOT / "data" / "transactions_small.jsonl", "data/transactions_small.jsonl"),
            # Pinned signing-key ARNs: the attestation verifies
            # the gate artifact against these, never an alias.
            (PROJECT_ROOT / "data" / "signing_key_pins.json", "data/signing_key_pins.json"),
        ],
        "role_name": "detection-agent-role",
        "idle_timeout": 300,
        "max_lifetime": 1800,
        "env_vars": {
            "DETECTION_TABLE": "detection-results",
            "WRITE_AUDIT": "true",
            # Pin the server-side execution mode. The caller's
            # request body no longer selects mode; the shim reads AGENT_MODE.
            "AGENT_MODE": "cpu",
            # Shim concurrency gate: graph detection is the
            # heaviest per-request workload, so it gets the smallest gate.
            "MAX_CONCURRENT_INVOCATIONS": "2",
            # Secrets Manager ARN of the PAN filter's txn_ref HMAC key.
            # Populated from the FsiComplianceAgents
            # TxnRefHmacSecretArn output in main(). The key itself is never
            # placed in a runtime's environment variables.
            "TXN_REF_HMAC_SECRET_ARN": "",
        },
    },
    {
        "name": "ComplianceAgent",
        "code_dir": PROJECT_ROOT / "agentcore" / "compliance_agent",
        "extra_dirs": [PROJECT_ROOT / "lambdas" / "compliance_agent"],
        "packages": [PROJECT_ROOT / "governance_common"],
        # handler.py imports the repo-root model_assurance module (approved-
        # model enforcement), which reads data/approved_models.json
        # relative to its own location. Both must ship at the zip root or the
        # runtime fails every request with ModuleNotFoundError.
        "root_files": [
            (PROJECT_ROOT / "model_assurance.py", "model_assurance.py"),
            (PROJECT_ROOT / "data" / "approved_models.json", "data/approved_models.json"),
            (PROJECT_ROOT / "data" / "signing_key_pins.json", "data/signing_key_pins.json"),
        ],
        # The registry signature ships at arcname data/approved_models.json.sig.
        # Deploy builds copy the KMS envelope from
        # data/approved_models.json.kms.sig; --package-only --local-dev copies
        # the committed local-dev .sig and marks the build LOCAL_DEV_BUILD.
        "registry_signature": True,
        "role_name": "compliance-agent-role",
        "idle_timeout": 300,
        "max_lifetime": 1800,
        "env_vars": {
            "COMPLIANCE_TABLE": "compliance-decisions",
            # Provenance root: compliance GetItems the recorded
            # detection and assesses the stored clusters.
            "DETECTION_TABLE": "detection-results",
            # "true" only with --allow-unverified-evaluation (optional; no
            # console page needs it, they all record a detection first):
            # evaluation-only, all NEEDS_REVIEW, no drift metrics, no
            # dispatch token.
            "ALLOW_UNVERIFIED_EVALUATION": "false",
            "WRITE_AUDIT": "true",
            "BEDROCK_MODEL_ID": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "CHALLENGER_MODEL_ID": "us.amazon.nova-pro-v1:0",
            # Pin the server-side execution mode to live.
            "AGENT_MODE": "live",
            # Shim concurrency gate.
            "MAX_CONCURRENT_INVOCATIONS": "4",
            "GUARDRAIL_ID": "",  # Populated from CDK (FsiComplianceAgents) output
            # Pin a published guardrail version, not DRAFT, so the attached
            # guardrail is a stable reviewed version. Populated
            # below from the FsiComplianceAgents stack's GuardrailVersion
            # output — the real version number CfnGuardrailVersion published,
            # never a hardcoded "1" that may not correspond to
            # any version that actually exists.
            "GUARDRAIL_VERSION": "",
        },
    },
    {
        "name": "ExecutorAgent",
        "code_dir": PROJECT_ROOT / "agentcore" / "executor_agent",
        "extra_dirs": [PROJECT_ROOT / "lambdas" / "executor_agent"],
        "packages": [PROJECT_ROOT / "governance_common"],
        "root_files": [
            (PROJECT_ROOT / "data" / "signing_key_pins.json", "data/signing_key_pins.json"),
        ],
        "role_name": "executor-agent-role",
        "idle_timeout": 300,
        "max_lifetime": 1800,
        "env_vars": {
            "AUDIT_TABLE": "executor-audit",
            "COMPLIANCE_TABLE": "compliance-decisions",
            "SAR_BUCKET": "",  # Populated from CDK output
            "ANALYST_QUEUE_URL": "",  # Populated from CDK output
            "SAR_KMS_KEY_ARN": "",  # Populated from CDK output (SarFilingsKeyArn)
            "WRITE_AUDIT": "true",
            # Pin the server-side execution mode to live.
            "AGENT_MODE": "live",
            # Shim concurrency gate.
            "MAX_CONCURRENT_INVOCATIONS": "4",
            # Path inside the AgentCore runtime container (where /tmp is the
            # only writable location), never used on the deploy host, so it
            # must stay a literal rather than tempfile.gettempdir() here.
            "LOCAL_OUTPUT_DIR": "/tmp/cached_output",  # nosec B108
            # Name of the deployed circuit-breaker Lambda the executor invokes
            # via boto3 for the CIRCUIT_BREAKER decision — matches
            # the fixed function_name in cdk/agents_stack.py.
            "CIRCUIT_BREAKER_FUNCTION": "fsi-circuit-breaker",
        },
    },
]


def get_account_id():
    """Get the current AWS account ID."""
    sts = boto3.client("sts", region_name=REGION)
    return sts.get_caller_identity()["Account"]


def get_code_bucket_name(account_id: str, explicit_bucket: str = None) -> str:
    """
    Get the code bucket the agent deployment packages are uploaded to.

    Resolution order (no silent exception swallowing, no
    convention-name guessing as a default):
      1. --code-bucket, if the operator passed one explicitly.
      2. The FsiComplianceAgents stack's CodeBucketName output (the
         authoritative source — cdk/agents_stack.py already exports it).
      3. The AgentCore convention name, ONLY reachable via --code-bucket
         (never a silent default).

    Raises:
        RuntimeError: the CFN lookup failed for a reason other than "stack/
        output not found" (credentials, throttling, etc.) — swallowing any
        exception here previously meant a transient AWS error silently fell
        through to the guessed convention name.
    """
    if explicit_bucket:
        return explicit_bucket

    cfn = boto3.client("cloudformation", region_name=REGION)
    try:
        response = cfn.describe_stacks(StackName="FsiComplianceAgents")
    except cfn.exceptions.ClientError as e:
        if "does not exist" in str(e):
            raise RuntimeError(
                "FsiComplianceAgents stack not found — run `cdk deploy` first, or "
                "pass --code-bucket explicitly."
            ) from e
        raise RuntimeError(f"Could not read FsiComplianceAgents stack outputs: {e}") from e

    outputs = {o["OutputKey"]: o["OutputValue"] for o in response["Stacks"][0].get("Outputs", [])}
    if "CodeBucketName" in outputs:
        return outputs["CodeBucketName"]

    raise RuntimeError(
        "FsiComplianceAgents stack has no CodeBucketName output. "
        "Pass --code-bucket explicitly if you intend to use the AgentCore "
        "convention-named bucket."
    )


def get_role_arn(role_name: str, account_id: str) -> str:
    """Construct role ARN."""
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _source_files(directory: Path) -> list:
    """
    Return the .py source files to package from `directory`, excluding
    hidden files and backup copies.

    pathlib's glob("*.py") matches dotfiles (unlike glob.glob), so a local,
    gitignored backup such as `.handler.backup.py` -- an old pre-remediation
    copy of a handler -- was shipped into the deployed runtime zip. Only
    ship real, visible module files.
    """
    return sorted(
        f for f in directory.glob("*.py")
        if f.is_file()
        and not f.name.startswith(".")
        and ".backup" not in f.name
        and not f.name.endswith((".bak.py", ".orig.py"))
    )


def registry_signature_source(local_dev: bool) -> Path:
    """Source file for the bundled data/approved_models.json.sig: the KMS
    envelope (.kms.sig) for deploy builds, the committed local-dev .sig for
    --local-dev builds."""
    name = "approved_models.json.sig" if local_dev else "approved_models.json.kms.sig"
    return PROJECT_ROOT / "data" / name


def package_agent(agent_config: dict, build_dir: Path, *, local_dev: bool = False) -> Path:
    """
    Package an agent into a deployment zip.

    Includes:
    - The AgentCore main.py (HTTP server)
    - The original Lambda handler + supporting modules
    - Python dependencies (installed via uv/pip for ARM64)
    - for the ComplianceAgent, the registry signature at arcname
      data/approved_models.json.sig (KMS envelope unless local_dev)
    """
    agent_name = agent_config["name"]
    # Every path the pip subprocess sees is resolved and confined first:
    # build output under PROJECT_ROOT/build, requirements under PROJECT_ROOT.
    build_dir = _confined(build_dir, PROJECT_ROOT / "build")
    zip_path = build_dir / f"{agent_name}.zip"
    deps_dir = _confined(build_dir / f"{agent_name}_deps", build_dir)

    # Resolve the registry signature before any work: a deploy build without
    # the KMS signature must not produce a zip. Packaging only
    # copies bytes; the gate and verify_gate_artifact verify the envelope.
    signature_src = None
    if agent_config.get("registry_signature"):
        signature_src = registry_signature_source(local_dev)
        if not signature_src.is_file():
            if local_dev:
                raise FileNotFoundError(f"Required runtime file missing: {signature_src}")
            raise RegistryNotKmsSignedError(KMS_SIG_MISSING_MESSAGE)

    print(f"\n  Packaging {agent_name}...")

    # Install dependencies for ARM64 (AgentCore requirement) from the hash
    # lock only: exact pins + sha256 for the whole closure,
    # binary-only, no dependency resolution. There is deliberately no
    # fallback: a failed install aborts packaging (CalledProcessError
    # propagates) rather than shipping host-platform or unpinned wheels.
    code_dir = agent_config["code_dir"]
    requirements_file = _confined(code_dir / "requirements.txt", PROJECT_ROOT)
    lock_file = _confined(code_dir / "requirements.lock", PROJECT_ROOT)
    if requirements_file.exists() and not lock_file.exists():
        raise FileNotFoundError(f"Hash lock missing for {agent_name}: {lock_file} "
                                "(regenerate with scripts/build_host_lock.py --target agent)")
    if lock_file.exists():
        print(f"    Installing deps from {lock_file.name} (--require-hashes)...")
        if deps_dir.exists():
            shutil.rmtree(deps_dir)  # lib/ must hold exactly the locked closure
        deps_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Static pip argv (list form, no shell); paths confined above.
            # numpy/pandas publish aarch64 cp313 wheels only as manylinux_2_24+
            # (up to 2_28), so both platform tags are accepted.
            subprocess.run(  # nosec B603 # nosemgrep -- static pip argv, list form, no shell, paths confined to PROJECT_ROOT
                [
                    *_PIP_INSTALL,
                    "--require-hashes",
                    "--no-deps",
                    "--only-binary=:all:",
                    "--platform", "manylinux2014_aarch64",
                    "--platform", "manylinux_2_28_aarch64",
                    "--implementation", "cp",
                    "--python-version", "3.13",
                    "--target", str(deps_dir),
                    "-r", str(lock_file),
                    "--quiet",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"    ✗ Hash-locked dependency install failed for {agent_name}; packaging aborted.")
            if e.stderr:
                print(e.stderr[-2000:])
            raise
        print(f"    ✓ Dependencies installed to {deps_dir.name}/")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add the AgentCore main.py
        for file in _source_files(code_dir):
            zf.write(file, file.name)
            print(f"    + {file.name}")

        # Add installed dependencies under lib/ prefix to avoid conflicts
        if deps_dir.exists():
            dep_count = 0
            for root, dirs, files in os.walk(deps_dir):
                # Skip __pycache__ and .dist-info
                dirs[:] = [d for d in dirs if d != "__pycache__" and not d.endswith(".dist-info")]
                for file in files:
                    if file.endswith(".pyc"):
                        continue
                    full_path = Path(root) / file
                    arcname = "lib/" + str(full_path.relative_to(deps_dir))
                    zf.write(full_path, arcname)
                    dep_count += 1
            print(f"    + {dep_count} dependency files (in lib/)")

        # Add the original handler and supporting modules
        for extra_dir in agent_config.get("extra_dirs", []):
            for file in _source_files(extra_dir):
                # Place in a subdirectory matching the lambdas layout
                # The main.py adds this to sys.path
                arcname = f"lambdas/{extra_dir.name}/{file.name}"
                zf.write(file, arcname)
                print(f"    + {arcname}")

        # Shared repo-level packages (governance_common), written under
        # <package>/ at the zip root so `import governance_common...` resolves
        # in the runtime exactly as it does from the repo root locally.
        for package_dir in agent_config.get("packages", []):
            package_files = _source_files(package_dir)
            if not package_files:
                raise FileNotFoundError(f"Required runtime package missing or empty: {package_dir}")
            for file in package_files:
                arcname = f"{package_dir.name}/{file.name}"
                zf.write(file, arcname)
                print(f"    + {arcname}")

        # Repo-level modules/data a handler imports from outside its own dir.
        # Fail the packaging step if one is missing rather than shipping a
        # runtime that crashes on its first request.
        for src, arcname in agent_config.get("root_files", []):
            if not src.is_file():
                raise FileNotFoundError(f"Required runtime file missing: {src}")
            zf.write(src, arcname)
            print(f"    + {arcname}")

        if signature_src is not None:
            zf.write(signature_src, REGISTRY_SIGNATURE_ARCNAME)
            print(f"    + {REGISTRY_SIGNATURE_ARCNAME} (from {signature_src.name})")

        # NOTE: cached_output/*.json fixtures are deliberately NOT packaged
        # into the deployed runtime. Shipping them made the
        # caller-selectable local-mode short-circuit return authentic-looking
        # detection/compliance results that never ran the PAN filter, model,
        # guardrail or audit write. Local mode is a developer/CLI convenience
        # only and reads fixtures from the source tree, not the runtime zip.

    print(f"  → {zip_path.name} ({zip_path.stat().st_size / 1024:.0f} KB)")
    return zip_path


def package_only(build_dir: Path, *, local_dev: bool = False) -> list:
    """`--package-only`: build every bundle into build_dir; no AWS calls.

    A deploy build (default) needs data/approved_models.json.kms.sig and exits
    1 before any zip is written if it is missing; it deletes a stale
    LOCAL_DEV_BUILD marker. --local-dev packages the committed local-dev
    signature and writes the marker first, so a local-dev build can never be
    signed for deploy or deployed."""
    build_dir.mkdir(parents=True, exist_ok=True)
    marker = build_dir / LOCAL_DEV_MARKER
    if local_dev:
        marker.write_text("local-dev\n", encoding="utf-8")
    else:
        if not registry_signature_source(False).is_file():
            print(f"  ✗ {KMS_SIG_MISSING_MESSAGE}")
            sys.exit(1)
        if marker.exists():
            marker.unlink()
    zips = []
    for agent_config in AGENTS:
        try:
            zips.append(package_agent(agent_config, build_dir, local_dev=local_dev))
        except RegistryNotKmsSignedError:
            print(f"  ✗ {KMS_SIG_MISSING_MESSAGE}")
            sys.exit(1)
    return zips


def _load_prebuilt_bundle(cfg: dict, build_dir: Path) -> Path:
    """The default deploy never builds: it uploads the exact bytes the gate
    signed. A missing bundle exits 1."""
    zip_path = Path(build_dir) / f"{cfg['name']}.zip"
    if not zip_path.is_file():
        print(f"  ✗ bundle build/agentcore/{cfg['name']}.zip missing; run make package")
        sys.exit(1)
    return zip_path


def verify_gate_artifact(build_dir: Path) -> str:
    """Verify the signed gate artifact against the prebuilt bundles (exit 1
    on any refusal). Runs before any S3/AgentCore client is built."""
    return _vga.verify_gate_artifact(build_dir, agents=AGENTS, repo_root=PROJECT_ROOT,
                                     gate_dir=PROJECT_ROOT / "build" / "gate")


def _embed_gate_artifact(agent_config: dict, zip_path: Path) -> tuple:
    """Write <Agent>.upload.zip = the signed bundle + governance/gate-artifact.json(.sig).

    Refuses (exit 1) unless the artifact on disk is the one verified in this
    process and the upload zip still has the gate-signed bundle digest."""
    agent_name = agent_config["name"]
    gate_dir = PROJECT_ROOT / "build" / "gate"
    try:
        artifact_bytes = (gate_dir / GATE_ARTIFACT_NAME).read_bytes()
        sig_bytes = (gate_dir / (GATE_ARTIFACT_NAME + ".sig")).read_bytes()
    except OSError:
        print(f"  ✗ {agent_name}: gate artifact missing; run make gate-sign. Nothing deployed.")
        sys.exit(1)
    artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
    if _VERIFIED_GATE_ARTIFACT_SHA256 is None or not hmac.compare_digest(
            artifact_sha256, _VERIFIED_GATE_ARTIFACT_SHA256):
        print(f"  ✗ {agent_name}: gate artifact is not the one verified for this deploy. Nothing deployed.")
        sys.exit(1)
    expected_digest = json.loads(artifact_bytes)["bundles"][agent_name]
    upload_zip = zip_path.with_name(f"{agent_name}.upload.zip")
    with zipfile.ZipFile(zip_path) as src, zipfile.ZipFile(upload_zip, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            if info.filename.startswith("governance/"):
                continue
            dst.writestr(info, src.read(info))
        dst.writestr(GATE_ARTIFACT_ARCNAMES[0], artifact_bytes)
        dst.writestr(GATE_ARTIFACT_ARCNAMES[1], sig_bytes)
    if not hmac.compare_digest(bundle_digest.bundle_digest(upload_zip), str(expected_digest)):
        print(f"  ✗ {agent_name}: bundle changed since the gate signed it. Nothing deployed.")
        sys.exit(1)
    return upload_zip, artifact_sha256


def deploy_agent(agent_config: dict, zip_path: Path, bucket: str, account_id: str):
    """Deploy a single agent to AgentCore Runtime."""
    agent_name = agent_config["name"]

    # Tripwire: a plaintext txn_ref HMAC key must never reach a
    # runtime's environment variables (they are readable via GetAgentRuntime).
    # Checked before any API call so a future edit cannot ship one.
    if "TXN_REF_HMAC_KEY" in agent_config.get("env_vars", {}):
        print(f"  ✗ {agent_name}: env_vars contains TXN_REF_HMAC_KEY. The "
              "txn_ref key is read from Secrets Manager "
              "(TXN_REF_HMAC_SECRET_ARN); a plaintext key in runtime "
              "configuration is not allowed.")
        sys.exit(1)

    # Only the bundle the verified gate artifact describes is uploaded, with
    # the artifact embedded under governance/. Checked before
    # any client is built.
    upload_zip, artifact_sha256 = _embed_gate_artifact(agent_config, zip_path)

    role_arn = get_role_arn(agent_config["role_name"], account_id)
    s3_prefix = f"{agent_name}/deployment_package.zip"

    print(f"\n  Deploying {agent_name} to AgentCore Runtime...")

    # Upload zip to S3
    s3_client = boto3.client("s3", region_name=REGION)
    print(f"    Uploading to s3://{bucket}/{s3_prefix}")
    s3_client.upload_file(
        str(upload_zip),
        bucket,
        s3_prefix,
        ExtraArgs={
            "ExpectedBucketOwner": account_id,
            "Metadata": {"gate-artifact-sha256": artifact_sha256},
        },
    )

    # Create or update AgentCore Runtime
    agentcore = boto3.client("bedrock-agentcore-control", region_name=REGION)

    # Environment variables the runtime injects into the agent process.
    # NOTE: this must be passed to create/update — without it the agent falls
    # back to the defaults hard-coded in its handler (e.g. BEDROCK_MODEL_ID,
    # CHALLENGER_MODEL_ID, SAR_BUCKET, ANALYST_QUEUE_URL).
    env_vars = {k: str(v) for k, v in agent_config.get("env_vars", {}).items() if v is not None}
    # Runtime attestation (governance_common.runtime_attestation) compares the
    # embedded artifact's sha256 against this value.
    env_vars["GATE_ARTIFACT_SHA256"] = artifact_sha256

    runtime_config = {
        "agentRuntimeName": agent_name,
        "agentRuntimeArtifact": {
            "codeConfiguration": {
                "code": {
                    "s3": {
                        "bucket": bucket,
                        "prefix": s3_prefix,
                    }
                },
                "runtime": "PYTHON_3_13",
                "entryPoint": ["main.py"],
            }
        },
        "networkConfiguration": {"networkMode": "PUBLIC"},
        "roleArn": role_arn,
        "lifecycleConfiguration": {
            "idleRuntimeSessionTimeout": agent_config["idle_timeout"],
            "maxLifetime": agent_config["max_lifetime"],
        },
        "environmentVariables": env_vars,
    }

    # Check if runtime already exists (paginate through all runtimes)
    existing_id = None
    try:
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            runtimes = agentcore.list_agent_runtimes(**kwargs)
            for rt in runtimes.get("agentRuntimes", []):
                if rt.get("agentRuntimeName") == agent_name:
                    existing_id = rt["agentRuntimeId"]
                    break
            if existing_id:
                break
            next_token = runtimes.get("nextToken")
            if not next_token:
                break
    except Exception as e:
        # Same flow as before: fall through to create with whatever was found.
        print(f"    ⚠ Could not list existing runtimes ({type(e).__name__}); will attempt create")

    try:
        if existing_id:
            # Update existing runtime. environmentVariables MUST be included —
            # otherwise a redeploy keeps the old (or absent) env and the agent
            # silently falls back to its handler defaults.
            update_config = {
                "agentRuntimeId": existing_id,
                "agentRuntimeArtifact": runtime_config["agentRuntimeArtifact"],
                "networkConfiguration": runtime_config["networkConfiguration"],
                "roleArn": role_arn,
                "environmentVariables": env_vars,
            }
            response = agentcore.update_agent_runtime(**update_config)
            print(f"    ✓ Updated: {response['agentRuntimeArn']}")
            print(f"    Status: {response['status']}")
        else:
            # Create new runtime
            response = agentcore.create_agent_runtime(**runtime_config)
            print(f"    ✓ Created: {response['agentRuntimeArn']}")
            print(f"    Status: {response['status']}")

        return response.get("agentRuntimeArn")

    except Exception as e:
        print(f"    ✗ Failed: {e}")
        return None


def pin_runtime_arns(results: dict, account_id: str) -> bool:
    """Write the deployed runtime ARNs to runtime_pins.RUNTIME_ARNS_PARAMETER
    (the only runtimes the console invokes). Refuses an incomplete or
    invalid set (nothing written). Returns True when written."""
    try:
        value = runtime_pins.encode_runtime_arns(results, account=account_id, region=REGION)
    except runtime_pins.RuntimePinsError as e:
        print(f"  ✗ Runtime ARNs not pinned ({e}); the console keeps the previous pins.")
        return False
    ssm = boto3.client("ssm", region_name=REGION)
    ssm.put_parameter(Name=runtime_pins.RUNTIME_ARNS_PARAMETER, Value=value, Type="String",
                      Overwrite=True)
    print(f"  ✓ Pinned runtime ARNs in {runtime_pins.RUNTIME_ARNS_PARAMETER}")
    return True


def get_agents_stack_outputs() -> dict:
    """Read CDK agents stack outputs (GuardrailId, DenyPolicyArn, etc.)."""
    cfn = boto3.client("cloudformation", region_name=REGION)
    outputs = {}
    try:
        response = cfn.describe_stacks(StackName="FsiComplianceAgents")
        for o in response["Stacks"][0].get("Outputs", []):
            outputs[o["OutputKey"]] = o["OutputValue"]
    except Exception as e:
        # Same return value as before (whatever was read, possibly empty).
        print(f"  ⚠ Could not read FsiComplianceAgents outputs ({type(e).__name__}); continuing with none")
    return outputs


def get_data_stack_outputs() -> dict:
    """
    Read the FsiComplianceData stack's SarBucketName / AnalystQueueUrl
    outputs — the authoritative source (cdk/data_stack.py already exports
    both).

    This used to fall back to a substring sweep over EVERY
    bucket in the account ("sarfiling" or "fsi" in the name) and the first
    SQS queue matching a name prefix when the stack output was missing, and
    swallowed the CloudFormation lookup failure in a bare
    `except Exception: pass`. In an account containing any other
    similarly-named bucket that sorts first, confidential SAR narratives
    would be written to an unintended destination with no error surfaced.
    A missing/unreadable output now raises instead of guessing.

    Raises:
        RuntimeError: the stack cannot be read, or lacks the expected
        outputs — the caller (main()) treats this as fatal and aborts the
        deploy rather than proceeding with a guessed destination.
    """
    cfn = boto3.client("cloudformation", region_name=REGION)
    try:
        response = cfn.describe_stacks(StackName="FsiComplianceData")
    except cfn.exceptions.ClientError as e:
        if "does not exist" in str(e):
            raise RuntimeError(
                "FsiComplianceData stack not found — run `cdk deploy` "
                "(FsiComplianceData) first."
            ) from e
        raise RuntimeError(f"Could not read FsiComplianceData stack outputs: {e}") from e

    outputs = {o["OutputKey"]: o["OutputValue"] for o in response["Stacks"][0].get("Outputs", [])}

    missing = [k for k in ("SarBucketName", "AnalystQueueUrl", "SarFilingsKeyArn") if k not in outputs]
    if missing:
        raise RuntimeError(
            "FsiComplianceData stack is missing output(s): " + ", ".join(missing) +
            ". Run `cdk deploy` (FsiComplianceData) to (re)create them."
        )

    return outputs


def main():
    parser = argparse.ArgumentParser(description="Deploy AgentCore Runtimes")
    parser.add_argument(
        "--code-bucket", type=str, default=None,
        help="Explicit code bucket name. Bypasses the FsiComplianceAgents "
             "stack output lookup — use this only if you intend to target "
             "the AgentCore convention-named bucket or a bucket outside "
             "this stack (the convention name is no longer a "
             "silent fallback)."
    )
    parser.add_argument(
        "--allow-unverified-evaluation", action="store_true",
        help="Let the ComplianceAgent evaluate detection output that has no "
             "recorded detection (UNVERIFIED: every decision NEEDS_REVIEW, no "
             "drift metrics, no dispatch token). Optional: no console page "
             "needs it, because the live pages record a detection first."
    )
    parser.add_argument(
        "--package-only", action="store_true",
        help="Build build/agentcore/<Agent>.zip for every agent and stop (no "
             "AWS calls). The default deploy never builds; run this first "
             "(make package), then make gate-sign, then deploy."
    )
    parser.add_argument(
        "--local-dev", action="store_true",
        help="With --package-only: bundle the committed local-dev registry "
             "signature and mark the build LOCAL_DEV_BUILD (never deployable)."
    )
    args = parser.parse_args()
    if args.local_dev and not args.package_only:
        parser.error("--local-dev is only valid with --package-only")
    for agent_config in AGENTS:
        if agent_config["name"] == "ComplianceAgent":
            agent_config["env_vars"]["ALLOW_UNVERIFIED_EVALUATION"] = (
                "true" if args.allow_unverified_evaluation else "false")

    build_dir = PROJECT_ROOT / "build" / "agentcore"
    if args.package_only:
        print("=" * 60)
        print("  FSI Agentic Compliance — package AgentCore bundles (no AWS calls)")
        print("=" * 60)
        package_only(build_dir, local_dev=args.local_dev)
        print("\n  Next: make gate-sign GATE_SIGNER_PROFILE=<profile>, then make deploy.\n")
        return

    print("=" * 60)
    print("  FSI Agentic Compliance — AgentCore Runtime Deployment")
    print("=" * 60)

    # The deploy uploads only prebuilt bundles the signed gate artifact
    # describes, verified BEFORE any AWS client is built.
    bundles = {cfg["name"]: _load_prebuilt_bundle(cfg, build_dir) for cfg in AGENTS}
    global _VERIFIED_GATE_ARTIFACT_SHA256
    _VERIFIED_GATE_ARTIFACT_SHA256 = verify_gate_artifact(build_dir)

    account_id = get_account_id()
    print(f"\n  Account: {account_id}")
    print(f"  Region:  {REGION}")

    try:
        bucket = get_code_bucket_name(account_id, explicit_bucket=args.code_bucket)
    except RuntimeError as e:
        print(f"  ✗ Could not resolve code bucket: {e}")
        sys.exit(1)
    print(f"  Bucket:  {bucket}")

    # PAN-filter txn_ref HMAC key. The key now lives in a
    # CDK-generated Secrets Manager secret; only its (non-sensitive) ARN
    # reaches a runtime, and only the DetectionAgent's (the only AgentCore
    # runtime that bundles the PAN filter). A plaintext TXN_REF_HMAC_KEY in
    # the deploy environment is never copied anywhere.
    if os.environ.get("TXN_REF_HMAC_KEY"):
        print("  ℹ TXN_REF_HMAC_KEY is set in the deploy environment and is "
              "ignored: the txn_ref key is read from Secrets Manager "
              "and is never placed in runtime environment "
              "variables.")

    # Resolve agents stack outputs (guardrail) for the compliance agent env vars.
    # The compliance agent now fails closed when GUARDRAIL_ID is unset (it
    # sends caller-controlled cluster data to Bedrock and must not do so
    # unguarded) — wire the stack's own Guardrail through so a normal deploy
    # keeps SAR/challenger calls working rather than failing every call.
    agents_outputs = get_agents_stack_outputs()
    guardrail_id = agents_outputs.get("GuardrailId", "")
    # GuardrailVersion — the real published version number from
    # the stack's CfnGuardrailVersion resource, not a hardcoded "1". Without
    # a real published version, guardrailed Converse calls either fail
    # closed (a version that doesn't exist) or silently use the mutable
    # DRAFT guardrail if a caller's default ever changed — version pinning
    # must come from the thing CDK actually published.
    guardrail_version = agents_outputs.get("GuardrailVersion", "")
    # A missing GuardrailVersion output must abort the deploy,
    # the same way every other missing-output branch in this script does
    # (get_data_stack_outputs above, the code-bucket lookup) — this used to
    # just print a warning and continue, popping GUARDRAIL_VERSION from the
    # env so the handler's own os.environ.get("GUARDRAIL_VERSION", "DRAFT")
    # default kicked in, silently deploying against the mutable DRAFT
    # guardrail with no deploy-time signal. GuardrailId is treated the same
    # way: a Guardrail with no published numbered version is not a valid
    # deploy target either.
    if not guardrail_id or not guardrail_version:
        print("  ✗ GuardrailId/GuardrailVersion not found in FsiComplianceAgents "
              "outputs. Run `cdk deploy` (FsiComplianceAgents) first.")
        sys.exit(1)
    print(f"  Guardrail: {guardrail_id} (version {guardrail_version})")

    # txn_ref HMAC secret ARN: a missing output aborts the deploy,
    # the same way GuardrailId/GuardrailVersion do, rather than provisioning a
    # DetectionAgent whose PAN filter would fail closed on first invocation.
    txn_ref_secret_arn = agents_outputs.get("TxnRefHmacSecretArn", "")
    if not txn_ref_secret_arn:
        print("  ✗ TxnRefHmacSecretArn not found in FsiComplianceAgents "
              "outputs. Run `cdk deploy` (FsiComplianceAgents) first.")
        sys.exit(1)
    for agent_config in AGENTS:
        if agent_config["name"] == "DetectionAgent":
            agent_config["env_vars"]["TXN_REF_HMAC_SECRET_ARN"] = txn_ref_secret_arn

    for agent_config in AGENTS:
        if agent_config["name"] == "ComplianceAgent":
            agent_config["env_vars"]["GUARDRAIL_ID"] = guardrail_id
            agent_config["env_vars"]["GUARDRAIL_VERSION"] = guardrail_version

    # Resolve data stack outputs for executor env vars. get_data_stack_outputs
    # now raises (rather than guessing from list_buckets/list_queues) when the
    # stack or its outputs cannot be read — treat that the same
    # way the previous missing-destination check did: abort the deploy.
    try:
        data_outputs = get_data_stack_outputs()
    except RuntimeError as e:
        print(f"  ✗ Could not resolve SAR bucket / analyst queue: {e}")
        sys.exit(1)
    sar_bucket = data_outputs["SarBucketName"]
    analyst_queue_url = data_outputs["AnalystQueueUrl"]
    print(f"  SAR Bucket: {sar_bucket}")
    print(f"  Analyst Queue: {analyst_queue_url}")

    # Populate executor agent env vars from CDK outputs
    for agent_config in AGENTS:
        if agent_config["name"] == "ExecutorAgent":
            agent_config["env_vars"]["SAR_BUCKET"] = sar_bucket
            agent_config["env_vars"]["ANALYST_QUEUE_URL"] = analyst_queue_url
            # SAR filings CMK. get_data_stack_outputs requires
            # it; the executor also fails fast at runtime if it is unset.
            agent_config["env_vars"]["SAR_KMS_KEY_ARN"] = data_outputs.get("SarFilingsKeyArn", "")

    # Deploy each verified prebuilt bundle (never rebuilt here, so the
    # gate-signed digests describe the exact bytes uploaded).
    results = {}
    for agent_config in AGENTS:
        arn = deploy_agent(agent_config, bundles[agent_config["name"]], bucket, account_id)
        results[agent_config["name"]] = arn

    # Summary
    print("\n" + "=" * 60)
    print("  Deployment Summary")
    print("=" * 60)
    for name, arn in results.items():
        status = "✓" if arn else "✗"
        print(f"  {status} {name}: {arn or 'FAILED'}")

    # Pin exactly these ARNs for the console. Only a complete, valid set is
    # written; a failed agent leaves the previous pins in place and fails
    # the deploy.
    if not pin_runtime_arns(results, account_id):
        sys.exit(1)

    print("\n  To invoke an agent:")
    print("    agentcore invoke --name ComplianceAgent '{\"mode\": \"local\"}'")
    print("\n  To check status:")
    print("    agentcore status")
    print()


if __name__ == "__main__":
    main()
