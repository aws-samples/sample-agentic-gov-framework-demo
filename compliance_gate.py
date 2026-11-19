#!/usr/bin/env python3
"""
============================================================================
BLUEPRINT 5 — DEPLOYMENT CONTROL (governance-as-code deploy blocker)
============================================================================
This gate runs in CI/CD BEFORE any deploy. It asserts the governance
guarantees across five domains (Boundary, Model Governance, Audit, Access
Control, Model Assurance) — PCI-DSS, SOX, SR 11-7, and IAM isolation. ALL assertions must
pass or the deploy is blocked with a non-zero exit code. A weakened guardrail
or a broken IAM boundary never reaches production because this gate stops it.
============================================================================

Compliance Gate — CI/CD deploy blocker with 100+ assertions.

Extended gate with 5 domains of assertions for the hybrid architecture.
ALL domains must pass → deploy proceeds.
ANY failure → deploy blocked, exit code 1, failure details printed.

Domains:
1. Boundary (PAN ingress, guardrail output, IAM isolation)
2. Model Governance (audit metadata, prompt independence, guardrail config)
3. Audit (detection fields, compliance reasoning, provenance chain, PITR,
   immutable S3 audit archive from the synthesized CDK app)
4. Access Control (distinct roles, permissions, no role passing)
5. Model Assurance (D5.2 — configured + observed models on approved registry)
"""
import argparse
import getpass
import glob
import json
import os
import re
import shutil
import subprocess  # nosec B404 -- static argv, list form, no shell (see the nosec B603 on the call below)
import sys
import hashlib
import importlib.util
import zipfile
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

import model_assurance  # noqa: E402
from model_assurance import (  # noqa: E402
    load_verified_registry, validate_model, approved_model_ids, configured_model_id,
)
from governance_common import bundle_digest, head_binding, signing  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")

# ─── Signed gate artifact ───────────────────
# v2: carries registry_version, which the envelope also signs.
ARTIFACT_SCHEMA = "fsi-gate-artifact/v2"
ARTIFACT_TTL = timedelta(minutes=60)
GATE_ARTIFACT_DIR = os.path.join(PROJECT_ROOT, "build", "gate")
ARTIFACT_NAME = "gate-artifact.json"
DEFAULT_BUNDLES_DIR = os.path.join("build", "agentcore")
AGENT_NAMES = ("DetectionAgent", "ComplianceAgent", "ExecutorAgent")
KMS_SIG_MISSING_MESSAGE = (
    "registry not KMS-signed; run scripts/sign_registry.py --kms and commit "
    "data/approved_models.json.kms.sig")
STATUS_LINES_SHOWN = 10

# Exact requirement pin: name[extras]==version.
PIN_LINE_RE = re.compile(r"^[A-Za-z0-9_.-]+(\[[a-z,]+\])?==[0-9][A-Za-z0-9.+!-]*$")

SIGN_MODE_KMS = "kms"
SIGN_MODE_LOCAL_DEV = "local-dev"

_GIT_PATH = None


def _git_path() -> str:
    """The git executable, resolved once (no PATH lookups per call)."""
    global _GIT_PATH
    if _GIT_PATH is None:
        _GIT_PATH = shutil.which("git") or ""
    return _GIT_PATH


def _git(argv):
    """The single seam for every git call: list argv (argv[0] is the resolved
    git path), run in PROJECT_ROOT, no shell, bounded. Tests monkeypatch it."""
    return subprocess.run(  # nosec B603 # nosemgrep -- static git argv, list form, no shell, resolved git_path
        list(argv), cwd=PROJECT_ROOT, check=True, capture_output=True,
        timeout=head_binding.GIT_TIMEOUT_SECONDS,
    )


def _signer_session():
    """The gate signer's own AWS session (AWS_PROFILE=$(GATE_SIGNER_PROFILE))."""
    import boto3
    return boto3.Session()


def _load_deploy_agents():
    """AGENTS from cdk/deploy_agentcore_runtimes.py (packaging layout)."""
    path = os.path.join(PROJECT_ROOT, "cdk", "deploy_agentcore_runtimes.py")
    spec = importlib.util.spec_from_file_location("_gate_deploy_agentcore_runtimes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.AGENTS


def artifact_paths(gate_dir: str = None) -> tuple:
    gate_dir = gate_dir or GATE_ARTIFACT_DIR
    artifact = os.path.join(gate_dir, ARTIFACT_NAME)
    return artifact, artifact + ".sig"


def remove_stale_artifact(gate_dir: str = None) -> None:
    for path in artifact_paths(gate_dir):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def resolve_deployed_guardrail_id() -> tuple:
    """
    Resolve the GUARDRAIL_ID the COMPLIANCE AGENT RUNTIME is actually
    configured with, rather than grepping handler.py source text for the
    strings "guardrailConfig"/"guardrailIdentifier" — those
    strings are present in the code whether or not a guardrail is ever
    attached, since GUARDRAIL_ID can still resolve to "" at runtime.

    Queries the deployed AgentCore Runtime (ComplianceAgent) via
    bedrock-agentcore-control:GetAgentRuntime and reads its
    environmentVariables.GUARDRAIL_ID — the ONLY source of truth. There is
    deliberately no fallback to this gate process's own GUARDRAIL_ID
    environment variable: a prior version of this function
    fell back to that env var on any AWS lookup failure, and the
    assertion at check_model_governance only tested `bool(guardrail_id)` —
    so `GUARDRAIL_ID=anything make gate` passed without the gate ever
    contacting AWS or verifying anything about the deployed runtime. An
    AWS lookup failure (no credentials, runtime not deployed, API error,
    runtime not found) now resolves to "" and is reported as a FAIL by the
    caller, rather than silently substituting an unverified local value.

    Returns:
        (guardrail_id: str, source: str) — guardrail_id is "" if the
        deployed runtime could not be reached or has none configured;
        source explains why, so a gate failure is actionable.
    """
    guardrail_id, _guardrail_version, source = _resolve_deployed_compliance_runtime_guardrail()
    return guardrail_id, source


def resolve_deployed_guardrail_version() -> tuple:
    """
    Companion to resolve_deployed_guardrail_id(): resolves the
    GUARDRAIL_VERSION the deployed ComplianceAgent runtime is actually
    configured with, from the same environmentVariables lookup, so the
    guardrail-attachment assertion can verify the full
    (guardrail_id, guardrail_version) pair against the stack's own
    published outputs rather than id alone.

    Returns:
        (guardrail_version: str, source: str) — guardrail_version is "" if
        the deployed runtime could not be reached or has no version
        configured.
    """
    _guardrail_id, guardrail_version, source = _resolve_deployed_compliance_runtime_guardrail()
    return guardrail_version, source


def _resolve_deployed_compliance_runtime_guardrail() -> tuple:
    """Shared AWS lookup backing resolve_deployed_guardrail_id() and
    resolve_deployed_guardrail_version() — a single
    list_agent_runtimes/get_agent_runtime round trip resolves both
    environment variables together, rather than making the call twice."""
    import boto3
    try:
        client = boto3.client("bedrock-agentcore-control", region_name=REGION)
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            runtimes = client.list_agent_runtimes(**kwargs)
            for rt in runtimes.get("agentRuntimes", []):
                if rt.get("agentRuntimeName") == "ComplianceAgent":
                    detail = client.get_agent_runtime(agentRuntimeId=rt["agentRuntimeId"])
                    env_vars = detail.get("environmentVariables", {}) or {}
                    return (
                        env_vars.get("GUARDRAIL_ID", ""),
                        env_vars.get("GUARDRAIL_VERSION", ""),
                        "deployed AgentCore Runtime",
                    )
            next_token = runtimes.get("nextToken")
            if not next_token:
                break
        return "", "", "ComplianceAgent AgentCore Runtime not found (not deployed?)"
    except Exception as e:
        # No AWS access / no credentials / API error. This is a hard FAIL,
        # not a cue to fall back to a locally-set value — the gate cannot
        # verify the deployed runtime's guardrail, so it must say so rather
        # than vacuously pass.
        return "", "", f"could not reach deployed AgentCore Runtime ({e})"


def resolve_deployed_agent_role_arns() -> tuple:
    """
    Resolve the three agents' IAM role ARNs from IAM itself
    (iam:GetRole), rather than asserting distinctness over the three local
    string literals the gate already hardcodes elsewhere —
    that assertion (`len(set(roles)) == 3` over
    ["detection-agent-role", "compliance-agent-role", "executor-agent-role"])
    is tautologically true no matter what is actually deployed, since it
    never inspects deployed IAM; it would pass identically even if the
    stack's CDK source were edited to point all three roles at the same
    underlying role.

    Mirrors resolve_deployed_guardrail_id()'s fail-closed shape: an AWS
    lookup failure (no credentials, role not created yet, API error)
    resolves to an empty dict and is reported as a FAIL by the caller,
    never silently substituted with the unverified local role-name
    literals.

    Returns:
        (role_arns: dict[str, str], source: str) — role_arns maps each of
        the three well-known role names to its live ARN (only for roles
        that were found); source explains the resolution outcome.
    """
    import boto3
    role_names = ["detection-agent-role", "compliance-agent-role", "executor-agent-role"]
    iam = boto3.client("iam", region_name=REGION)
    role_arns = {}
    try:
        for role_name in role_names:
            try:
                role_arns[role_name] = iam.get_role(RoleName=role_name)["Role"]["Arn"]
            except iam.exceptions.NoSuchEntityException:
                continue
        if len(role_arns) < len(role_names):
            missing = [r for r in role_names if r not in role_arns]
            return role_arns, f"role(s) not found in deployed IAM: {', '.join(missing)}"
        return role_arns, "deployed IAM roles"
    except Exception as e:
        # No AWS access / no credentials / API error — a hard FAIL, not a
        # cue to fall back to the local role-name literals (same fail-closed
        # posture as resolve_deployed_guardrail_id).
        return {}, f"could not reach IAM to resolve agent role ARNs ({e})"


def resolve_published_guardrail() -> tuple:
    """
    Resolve the FsiComplianceAgents stack's OWN published GuardrailId /
    GuardrailVersion CloudFormation outputs (cdk/agents_stack.py), the same
    way cdk/deploy_agentcore_runtimes.py:get_agents_stack_outputs() does.

    This is the comparison target for resolve_deployed_guardrail_id()'s
    result: that function already resolves what the deployed
    ComplianceAgent runtime is actually configured with, but the gate only
    ever asserted that value was non-empty — it never checked that it
    matches what the stack itself published, so a runtime pointed at a
    stale, hand-edited, or entirely different guardrail would still pass.

    Returns:
        (guardrail_id, guardrail_version, source) — guardrail_id/version
        are "" if the stack or its outputs could not be read.
    """
    import boto3
    try:
        cfn = boto3.client("cloudformation", region_name=REGION)
        response = cfn.describe_stacks(StackName="FsiComplianceAgents")
        outputs = {o["OutputKey"]: o["OutputValue"] for o in response["Stacks"][0].get("Outputs", [])}
        guardrail_id = outputs.get("GuardrailId", "")
        guardrail_version = outputs.get("GuardrailVersion", "")
        if not guardrail_id or not guardrail_version:
            return "", "", "FsiComplianceAgents stack is missing GuardrailId/GuardrailVersion outputs"
        return guardrail_id, guardrail_version, "FsiComplianceAgents stack outputs"
    except Exception as e:
        return "", "", f"could not read FsiComplianceAgents stack outputs ({e})"


def _load_evidence_or_fail(gate, domain: str, relative_path: str, required_list_key: str):
    """
    Load a cached_output/*.json evidence fixture and record a FAIL (not a
    silent skip) if it is absent, unreadable, or missing the expected
    top-level list key.

    Every fixture-dependent assertion in this gate used to be wrapped in a
    bare `if os.path.exists(fixture):` with no `else` — so deleting or
    truncating an ordinary, unprotected repo file made every assertion that
    depended on it vanish from `self.results` entirely, and the gate's PASS
    is computed only over assertions that ran (`failed = total - passed`),
    so missing evidence silently became a pass rather than a failure.

    Returns:
        The parsed evidence dict if valid, otherwise None (the caller must
        skip its per-item assertions — the FAIL recorded here already
        reflects that).
    """
    full_path = os.path.join(PROJECT_ROOT, relative_path)
    if not os.path.exists(full_path):
        gate.assert_true(False, domain, f"Evidence file present: {relative_path}")
        return None
    try:
        with open(full_path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        gate.assert_true(False, domain, f"Evidence file present: {relative_path} ({e})")
        return None
    if not isinstance(data, dict) or not isinstance(data.get(required_list_key), list):
        gate.assert_true(
            False, domain,
            f"Evidence file {relative_path} contains a '{required_list_key}' list"
        )
        return None
    # An EMPTY list is a FAIL, not a vacuous PASS: callers
    # iterate this list to emit per-item assertions, so zero items means
    # zero assertions ran and the gate would report green with nothing
    # checked.
    if not data[required_list_key]:
        gate.assert_true(
            False, domain,
            f"Evidence file {relative_path} has a non-empty '{required_list_key}' list"
        )
        return None
    gate.assert_true(True, domain, f"Evidence file present: {relative_path}")
    return data

# ─── Immutable audit archive (synthesized CDK templates) ─────────────────────
CDK_DIR = os.path.join(PROJECT_ROOT, "cdk")
CDK_JSON = os.path.join(CDK_DIR, "cdk.json")
SYNTH_CACHE_DIR = os.path.join(GATE_ARTIFACT_DIR, "synth-cache")
SYNTH_TIMEOUT_SECONDS = 300
DATA_STACK_TEMPLATE = "FsiComplianceData.template.json"
AGENTS_STACK_TEMPLATE = "FsiComplianceAgents.template.json"
ARCHIVE_RETENTION_CONTEXT_KEY = "audit_archive_retention_days"
ARCHIVE_MIN_RETENTION_DAYS = 90
ARCHIVER_FUNCTION_NAME = "fsi-audit-archiver"
ARCHIVER_ROLE_NAME = "fsi-audit-archiver-role"
ARCHIVER_DLQ_NAME = "fsi-audit-archiver-dlq"
ARCHIVE_KEY_ALIAS = "alias/fsi-audit-archive"
SAR_KEY_ALIAS = "alias/fsi-sar-filings"
READER_ROLE_NAME = "fsi-compliance-reader"
DRIFT_FUNCTION_NAME = "fsi-drift-metric-publisher"
DRIFT_DLQ_NAME = "fsi-drift-metric-publisher-dlq"
# table name -> stream view type
ARCHIVED_TABLES = {
    "detection-results": "NEW_IMAGE",
    "compliance-decisions": "KEYS_ONLY",
    "executor-audit": "NEW_IMAGE",
    "governance-audit": "NEW_IMAGE",
    "operator-audit": "NEW_IMAGE",
}
# DynamoDB stream-read actions the archiver legitimately holds (the ESM needs them).
ARCHIVER_STREAM_READ_ACTIONS = frozenset({
    "dynamodb:ListStreams", "dynamodb:DescribeStream", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
})
ARCHIVE_LOCKDOWN_ACTIONS = {
    "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging",
    "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:BypassGovernanceRetention",
}
ARCHIVE_PROTECTION_ACTIONS = {
    "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration", "s3:PutBucketVersioning",
    "s3:PutEncryptionConfiguration", "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
    "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
}
KMS_DATA_PLANE_PREFIXES = ("kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt",
                           "kms:CreateGrant")
# alarm name -> (namespace, metric name)
ARCHIVE_ALARMS = {
    "fsi-audit-archiver-dlq-not-empty": ("AWS/SQS", "ApproximateNumberOfMessagesVisible"),
    "fsi-audit-archiver-errors": ("AWS/Lambda", "Errors"),
    "fsi-audit-archive-record-failures": ("FSI/AuditArchive", "ArchiveRecordFailures"),
    "fsi-audit-archiver-iterator-age": ("AWS/Lambda", "IteratorAge"),
    "fsi-audit-archive-conflict": ("FSI/AuditArchive", "ArchiveConflicts"),
    "fsi-audit-archive-pan-refused": ("FSI/AuditArchive", "PanRefused"),
    "fsi-audit-archive-record-removed": ("FSI/AuditArchive", "AuditRecordRemoved"),
    "fsi-audit-archive-item-missing": ("FSI/AuditArchive", "ArchiveItemMissing"),
    "fsi-audit-archive-source-refused": ("FSI/AuditArchive", "ArchiveSourceRefused"),
}
# On-call notification topic and the alarms that must page through it.
ALARM_TOPIC_NAME = "fsi-governance-alarms"
ALARM_TOPIC_KEY_ALIAS = "alias/fsi-governance-alarms"
NOTIFYING_ALARMS = tuple(ARCHIVE_ALARMS) + (
    "fsi-out-of-band-hold-change", "fsi-break-glass-assumed", "fsi-uncorroborated-drift-alarm",
    "fsi-corroboration-unavailable", "fsi-drift-shaping-suspected", "fsi-drift-metric-publisher-dlq-not-empty",
    "fsi-drift-metric-publisher-iterator-age", "fsi-drift-metric-publisher-errors", "fsi-hold-reconciled",
    "fsi-hold-sweep-failed", "fsi-compliance-invocation-surge", "fsi-challenger-output-rejected",
    "fsi-circuit-breaker-dlq-not-empty", "fsi-hold-sweep-not-running",
)
# Sweep liveness: absent heartbeats must breach (a stopped sweep is silent).
SWEEP_LIVENESS_ALARM = "fsi-hold-sweep-not-running"
SWEEP_HEARTBEAT = ("FSI/GovernanceIntegrity", "HoldSweepHeartbeat")
# The breaker-trigger alarms keep the automated breaker as their only action.
BREAKER_TRIGGER_ALARMS = (
    "fsi-challenger-dispute-rate-breach", "fsi-guardrail-intervention-rate-breach",
    "fsi-detection-volume-anomaly", "fsi-challenger-dispute-rate-sustained",
)
ANALYST_QUEUE_NAME = "fsi-analyst-review"
EXECUTOR_ROLE_NAME = "executor-agent-role"
# Lambda function -> its role; each logs only to /fsi/lambda/<function>.
LAMBDA_LOG_PREFIX = "/fsi/lambda/"
SCOPED_LOG_FUNCTIONS = {
    "fsi-audit-archiver": "fsi-audit-archiver-role",
    "fsi-pan-filter": "pan-filter-role",
    "fsi-circuit-breaker": "circuit-breaker-role",
    "fsi-circuit-breaker-human": "circuit-breaker-role",
    "fsi-governance-hold-sweep": "governance-hold-sweep-role",
    "fsi-drift-metric-publisher": "fsi-drift-metric-publisher-role",
}


class SynthUnavailable(Exception):
    """The CDK app could not be synthesized (the gate fails closed)."""


def _cdk_context() -> dict:
    try:
        with open(CDK_JSON, encoding="utf-8") as f:
            context = json.load(f).get("context", {})
    except (OSError, ValueError) as e:
        raise SynthUnavailable(f"cdk/cdk.json unreadable: {type(e).__name__}") from None
    if not isinstance(context, dict):
        raise SynthUnavailable("cdk/cdk.json context is not an object")
    return context


def audit_archive_min_retention_days() -> int:
    """max(90, cdk.json audit_archive_retention_days) — the single configured value."""
    value = _cdk_context().get(ARCHIVE_RETENTION_CONTEXT_KEY, ARCHIVE_MIN_RETENTION_DAYS)
    if isinstance(value, bool):
        raise SynthUnavailable(f"cdk.json {ARCHIVE_RETENTION_CONTEXT_KEY} is not an integer")
    try:
        return max(ARCHIVE_MIN_RETENTION_DAYS, int(value))
    except (TypeError, ValueError):
        raise SynthUnavailable(f"cdk.json {ARCHIVE_RETENTION_CONTEXT_KEY} is not an integer") from None


def _aws_cdk_version() -> str:
    from importlib import metadata
    try:
        return metadata.version("aws-cdk-lib")
    except metadata.PackageNotFoundError:
        raise SynthUnavailable("aws_cdk not installed (make setup)") from None


def synth_cache_key(context: dict) -> str:
    digest = hashlib.sha256()
    for path in sorted(glob.glob(os.path.join(CDK_DIR, "*.py"))) + [CDK_JSON]:
        digest.update(os.path.basename(path).encode() + b"\0")
        with open(path, "rb") as f:
            digest.update(f.read())
    digest.update(json.dumps(context, sort_keys=True).encode())
    digest.update(_aws_cdk_version().encode())
    digest.update(repr(tuple(sys.version_info[:2])).encode())
    return digest.hexdigest()


def _run_cdk_synth(outdir: str, context: dict):
    """The single synth seam: static argv, no shell, bounded. Tests monkeypatch it."""
    env = dict(os.environ, CDK_OUTDIR=outdir, CDK_CONTEXT_JSON=json.dumps(context))
    return subprocess.run(  # nosec B603 # nosemgrep -- static argv (this interpreter + cdk/app.py), list form, no shell
        [sys.executable, "app.py"], cwd=CDK_DIR, env=env, capture_output=True,
        timeout=SYNTH_TIMEOUT_SECONDS, check=False,
    )


def synth_cdk_templates(use_cache: bool = True) -> tuple:
    """(data template, agents template) of the real CDK app.

    Plain runs cache the two template JSONs under build/gate/synth-cache
    (keyed on cdk/*.py, cdk.json, the context, aws-cdk-lib and Python
    versions); assertions are always recomputed. --sign passes
    use_cache=False. Raises SynthUnavailable on any failure."""
    import tempfile
    if shutil.which("node") is None:
        raise SynthUnavailable("Node.js not found on PATH")
    if importlib.util.find_spec("aws_cdk") is None:
        raise SynthUnavailable("aws_cdk not installed (make setup)")
    context = _cdk_context()
    key = synth_cache_key(context)
    cache_path = os.path.join(SYNTH_CACHE_DIR, f"{key}.json")
    if use_cache and os.path.isfile(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                cached = json.load(f)
            return cached["data"], cached["agents"]
        except (OSError, ValueError, KeyError, TypeError):
            pass  # unreadable cache: synthesize
    with tempfile.TemporaryDirectory(prefix="fsi-gate-synth-") as outdir:
        try:
            result = _run_cdk_synth(outdir, context)
        except subprocess.TimeoutExpired:
            raise SynthUnavailable(f"timed out after {SYNTH_TIMEOUT_SECONDS}s") from None
        except OSError as e:
            raise SynthUnavailable(type(e).__name__) from None
        if result.returncode != 0:
            raise SynthUnavailable(f"cdk synth exited {result.returncode}")
        try:
            with open(os.path.join(outdir, DATA_STACK_TEMPLATE), encoding="utf-8") as f:
                data_tpl = json.load(f)
            with open(os.path.join(outdir, AGENTS_STACK_TEMPLATE), encoding="utf-8") as f:
                agents_tpl = json.load(f)
        except (OSError, ValueError) as e:
            raise SynthUnavailable(f"template unreadable: {type(e).__name__}") from None
    if use_cache:
        try:
            os.makedirs(SYNTH_CACHE_DIR, exist_ok=True)
            tmp = cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"data": data_tpl, "agents": agents_tpl}, f)
            os.replace(tmp, cache_path)
        except OSError:
            pass  # caching is best effort
    return data_tpl, agents_tpl


def _tpl_resources(template: dict, resource_type: str) -> dict:
    return {lid: r for lid, r in (template.get("Resources") or {}).items()
            if isinstance(r, dict) and r.get("Type") == resource_type}


def _props(resource: dict) -> dict:
    props = resource.get("Properties") if isinstance(resource, dict) else None
    return props if isinstance(props, dict) else {}


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _render(value) -> str:
    """Flatten Fn::Join / Ref / GetAtt into a comparable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and "Fn::Join" in value:
        sep, parts = value["Fn::Join"]
        return sep.join(_render(p) for p in parts)
    if isinstance(value, dict) and "Ref" in value:
        return "${" + str(value["Ref"]) + "}"
    if isinstance(value, dict) and "Fn::GetAtt" in value:
        return "${" + ".".join(str(p) for p in value["Fn::GetAtt"]) + "}"
    return json.dumps(value, sort_keys=True)


def _role_arn_suffix(value, role_name: str) -> bool:
    return _render(value).endswith(f":role/{role_name}")


def _alias_key_id(template: dict, alias_name: str):
    for alias in _tpl_resources(template, "AWS::KMS::Alias").values():
        if _props(alias).get("AliasName") == alias_name:
            target = _props(alias).get("TargetKeyId")
            if isinstance(target, dict) and "Fn::GetAtt" in target:
                return target["Fn::GetAtt"][0]
            if isinstance(target, dict) and "Ref" in target:
                return target["Ref"]
    return None


def _lid_by_prop(template: dict, resource_type: str, prop: str, value):
    for lid, r in _tpl_resources(template, resource_type).items():
        if _props(r).get(prop) == value:
            return lid
    return None


def _is_any_principal(principal) -> bool:
    return principal == "*" or principal == {"AWS": "*"}


def _resolve_import(value, data_tpl: dict):
    """Fn::ImportValue of a data-stack export -> that output's Value."""
    if isinstance(value, dict) and "Fn::ImportValue" in value:
        name = value["Fn::ImportValue"]
        for output in (data_tpl.get("Outputs") or {}).values():
            if isinstance(output, dict) and (output.get("Export") or {}).get("Name") == name:
                return output.get("Value")
    return value


def audit_archive_assertions(data_tpl: dict, agents_tpl: dict, min_days: int) -> list:
    """[(passed, description)] for the immutable audit archive. Pure."""
    results = []

    def check(passed, description):
        results.append((bool(passed), description))

    min_days = max(ARCHIVE_MIN_RETENTION_DAYS, int(min_days))
    buckets = {lid: r for lid, r in _tpl_resources(data_tpl, "AWS::S3::Bucket").items()
               if _props(r).get("ObjectLockEnabled") is True}
    check(len(buckets) == 1, "exactly one Object Lock bucket (ObjectLockEnabled: true)")
    bucket_id, bucket = next(iter(buckets.items())) if len(buckets) == 1 else (None, {})
    props = _props(bucket)

    # 1. Object Lock COMPLIANCE with retention >= the configured floor.
    lock = props.get("ObjectLockConfiguration") or {}
    retention = ((lock.get("Rule") or {}).get("DefaultRetention") or {})
    days = retention.get("Days")
    if days is None and isinstance(retention.get("Years"), int):
        days = retention["Years"] * 365
    check(lock.get("ObjectLockEnabled") == "Enabled", "ObjectLockConfiguration.ObjectLockEnabled is Enabled")
    check(retention.get("Mode") == "COMPLIANCE", "default retention mode is COMPLIANCE")
    check(isinstance(days, int) and not isinstance(days, bool) and days >= min_days,
          f"default retention >= {min_days} days (got {days})")

    # 2. Versioning and ownership.
    check((props.get("VersioningConfiguration") or {}).get("Status") == "Enabled", "bucket versioning enabled")
    rules = (props.get("OwnershipControls") or {}).get("Rules") or [{}]
    check([r.get("ObjectOwnership") for r in rules] == ["BucketOwnerEnforced"], "object ownership BucketOwnerEnforced")

    # 3. SSE-KMS with the archive's own CMK (not the SAR key), rotating, RETAIN, policy shape.
    key_id = _alias_key_id(data_tpl, ARCHIVE_KEY_ALIAS)
    sar_key_id = _alias_key_id(data_tpl, SAR_KEY_ALIAS)
    sse = ((props.get("BucketEncryption") or {}).get("ServerSideEncryptionConfiguration") or [{}])
    default = (sse[0] or {}).get("ServerSideEncryptionByDefault") or {}
    check(default.get("SSEAlgorithm") == "aws:kms", "bucket SSE is aws:kms")
    check(key_id is not None and key_id != sar_key_id
          and default.get("KMSMasterKeyID") == {"Fn::GetAtt": [key_id, "Arn"]},
          f"bucket encrypts with the dedicated {ARCHIVE_KEY_ALIAS} key")
    key = (data_tpl.get("Resources") or {}).get(key_id) or {}
    check(_props(key).get("EnableKeyRotation") is True, "archive key rotation enabled")
    check(key.get("DeletionPolicy") == "Retain", "archive key DeletionPolicy Retain")
    key_statements = (_props(key).get("KeyPolicy") or {}).get("Statement") or []
    root_ok, data_plane = True, []
    for s in key_statements:
        actions = [a for a in _as_list(s.get("Action")) if isinstance(a, str)]
        touches = [a for a in actions if a in ("kms:*", "*") or a.startswith(KMS_DATA_PLANE_PREFIXES)]
        if not touches or s.get("Effect") != "Allow":
            continue
        if "Condition" not in s:
            root_ok = False
        data_plane.append(s)

    def _data_plane_shape(s, role, actions):
        cond = s.get("Condition") or {}
        arns = _as_list((cond.get("ArnEquals") or {}).get("aws:PrincipalArn"))
        via = _render((cond.get("StringEquals") or {}).get("kms:ViaService"))
        return (sorted(_as_list(s.get("Action"))) == sorted(actions) and len(arns) == 1
                and _role_arn_suffix(arns[0], role) and via.startswith("s3.") and via.endswith(".amazonaws.com"))

    check(root_ok, "archive key: no unconditioned statement grants data-plane use")
    check(len(data_plane) == 2
          and any(_data_plane_shape(s, ARCHIVER_ROLE_NAME, ["kms:GenerateDataKey", "kms:Decrypt"]) for s in data_plane)
          and any(_data_plane_shape(s, READER_ROLE_NAME, ["kms:Decrypt"]) for s in data_plane),
          "archive key: data plane only archiver {GenerateDataKey, Decrypt} and reader {Decrypt} via S3")

    # 4. Block Public Access.
    bpa = props.get("PublicAccessBlockConfiguration") or {}
    check(all(bpa.get(k) is True for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                                           "RestrictPublicBuckets")), "all four Block Public Access flags on")

    # 5. Bucket policy: deny-only, TLS, delete/lock, protection, put, read.
    policies = [(lid, r) for lid, r in _tpl_resources(data_tpl, "AWS::S3::BucketPolicy").items()
                if bucket_id and _props(r).get("Bucket") == {"Ref": bucket_id}]
    check(len(policies) == 1, "archive bucket has a bucket policy")
    policy = policies[0][1] if len(policies) == 1 else {}
    statements = (_props(policy).get("PolicyDocument") or {}).get("Statement") or []
    by_sid = {s.get("Sid"): s for s in statements if isinstance(s, dict)}
    check(statements and all(s.get("Effect") == "Deny" and _is_any_principal(s.get("Principal"))
                             for s in statements), "bucket policy is Deny-only (no Principal:* Allow)")
    check(any(s.get("Effect") == "Deny" and "s3:*" in _as_list(s.get("Action"))
              and (s.get("Condition") or {}) == {"Bool": {"aws:SecureTransport": "false"}} for s in statements),
          "bucket policy denies non-TLS access")
    s = by_sid.get("DenyObjectDeleteAndLockChanges") or {}
    check(ARCHIVE_LOCKDOWN_ACTIONS <= set(_as_list(s.get("Action"))) and "Condition" not in s
          and _render(s.get("Resource")).endswith("/*"),
          "bucket policy denies object delete, retention, legal hold and bypass to everyone")
    s = by_sid.get("DenyBucketProtectionChangesExceptCfn") or {}
    exempt = _as_list(((s.get("Condition") or {}).get("ArnNotLike") or {}).get("aws:PrincipalArn"))
    check(ARCHIVE_PROTECTION_ACTIONS <= set(_as_list(s.get("Action"))) and len(exempt) == 1
          and "cfn-exec-role" in _render(exempt[0]),
          "bucket policy denies lock/versioning/encryption/BPA/ownership/policy changes except CloudFormation")
    s = by_sid.get("DenyPutExceptArchiver") or {}
    exempt = _as_list(((s.get("Condition") or {}).get("ArnNotEquals") or {}).get("aws:PrincipalArn"))
    check("s3:PutObject" in _as_list(s.get("Action")) and len(exempt) == 1
          and _role_arn_suffix(exempt[0], ARCHIVER_ROLE_NAME),
          "bucket policy denies PutObject to everyone except the archiver role")
    s = by_sid.get("DenyReadsExceptArchiverAndReader") or {}
    exempt = _as_list(((s.get("Condition") or {}).get("ArnNotEquals") or {}).get("aws:PrincipalArn"))
    check({"s3:GetObject", "s3:GetObjectVersion"} <= set(_as_list(s.get("Action"))) and len(exempt) == 2
          and sorted(_render(a).rsplit("/", 1)[-1] for a in exempt) == sorted([ARCHIVER_ROLE_NAME, READER_ROLE_NAME]),
          "bucket policy denies reads except the archiver and fsi-compliance-reader")
    writers = set()
    for template in (data_tpl, agents_tpl):
        roles = {lid: _props(r).get("RoleName", lid) for lid, r in _tpl_resources(template, "AWS::IAM::Role").items()}
        for p in _tpl_resources(template, "AWS::IAM::Policy").values():
            for st in (_props(p).get("PolicyDocument") or {}).get("Statement") or []:
                acts = _as_list(st.get("Action"))
                if st.get("Effect") != "Allow" or not any(a in ("s3:PutObject", "s3:Put*", "s3:*", "*") for a in acts):
                    continue
                if any(bucket_id and bucket_id in _render(r) or _render(r) == "*" for r in _as_list(st.get("Resource"))):
                    writers |= {roles.get(ref.get("Ref"), str(ref)) if isinstance(ref, dict) else str(ref)
                                for ref in _props(p).get("Roles") or []}
    check(writers == {ARCHIVER_ROLE_NAME}, f"only {ARCHIVER_ROLE_NAME} may PutObject (got {sorted(writers)})")

    # 6. RETAIN, and nothing empties the bucket.
    check(bucket.get("DeletionPolicy") == "Retain" and policy.get("DeletionPolicy") == "Retain",
          "bucket and bucket policy DeletionPolicy Retain")
    check(not _tpl_resources(data_tpl, "Custom::S3AutoDeleteObjects"), "no auto-delete custom resource in the data stack")

    # 7. Five tables streamed to the archiver with no-silent-gap ESM settings.
    fn_id = _lid_by_prop(data_tpl, "AWS::Lambda::Function", "FunctionName", ARCHIVER_FUNCTION_NAME)
    fn_props = _props((data_tpl.get("Resources") or {}).get(fn_id) or {})
    check(fn_id is not None, f"{ARCHIVER_FUNCTION_NAME} function exists")
    reserved = fn_props.get("ReservedConcurrentExecutions")
    check(reserved is None or (isinstance(reserved, int) and reserved >= 1),
          f"{ARCHIVER_FUNCTION_NAME} reserved concurrency absent or >= 1")
    dlq_id = _lid_by_prop(data_tpl, "AWS::SQS::Queue", "QueueName", ARCHIVER_DLQ_NAME)
    esms = list(_tpl_resources(data_tpl, "AWS::Lambda::EventSourceMapping").values())
    for table_name, view in ARCHIVED_TABLES.items():
        table_id = _lid_by_prop(data_tpl, "AWS::DynamoDB::Table", "TableName", table_name)
        table_props = _props((data_tpl.get("Resources") or {}).get(table_id) or {})
        check((table_props.get("StreamSpecification") or {}).get("StreamViewType") == view,
              f"{table_name} stream is {view}")
        mine = [_props(e) for e in esms
                if table_id and _props(e).get("EventSourceArn") == {"Fn::GetAtt": [table_id, "StreamArn"]}
                and fn_id and _props(e).get("FunctionName") == {"Ref": fn_id}]
        check(len(mine) == 1, f"{table_name} stream has exactly one ESM to {ARCHIVER_FUNCTION_NAME}")
        p = mine[0] if len(mine) == 1 else {}
        retries = p.get("MaximumRetryAttempts")
        age = p.get("MaximumRecordAgeInSeconds")
        check(p.get("Enabled", True) is True, f"{table_name} archiver ESM enabled")
        check("FilterCriteria" not in p, f"{table_name} archiver ESM has no filter (all events archived)")
        check(p.get("StartingPosition") == "TRIM_HORIZON", f"{table_name} archiver ESM starts at TRIM_HORIZON")
        check(isinstance(age, int) and 1 <= age <= 86400,
              f"{table_name} archiver ESM max record age within 1..86400 s")
        check(p.get("BisectBatchOnFunctionError") is True and isinstance(retries, int) and 0 <= retries <= 10
              and "ReportBatchItemFailures" in _as_list(p.get("FunctionResponseTypes")),
              f"{table_name} archiver ESM bisects, bounded retries, reports item failures")
        check(dlq_id is not None and ((p.get("DestinationConfig") or {}).get("OnFailure") or {}).get("Destination")
              == {"Fn::GetAtt": [dlq_id, "Arn"]}, f"{table_name} archiver ESM on-failure -> {ARCHIVER_DLQ_NAME}")

    # 8. The compliance-decisions stream: exactly the archiver and the drift publisher.
    cd_id = _lid_by_prop(data_tpl, "AWS::DynamoDB::Table", "TableName", "compliance-decisions")
    cd_stream = {"Fn::GetAtt": [cd_id, "StreamArn"]}
    on_stream = []
    for template in (data_tpl, agents_tpl):
        for e in _tpl_resources(template, "AWS::Lambda::EventSourceMapping").values():
            if _resolve_import(_props(e).get("EventSourceArn"), data_tpl) == cd_stream:
                on_stream.append((template, _props(e)))
    check(len(on_stream) == 2, f"compliance-decisions stream has exactly 2 consumers (got {len(on_stream)})")
    drift_fn = _lid_by_prop(agents_tpl, "AWS::Lambda::Function", "FunctionName", DRIFT_FUNCTION_NAME)
    drift_dlq = _lid_by_prop(agents_tpl, "AWS::SQS::Queue", "QueueName", DRIFT_DLQ_NAME)
    drift = [p for t, p in on_stream if t is agents_tpl and drift_fn and p.get("FunctionName") == {"Ref": drift_fn}]
    p = drift[0] if len(drift) == 1 else {}
    check(len(drift) == 1 and p.get("StartingPosition") == "LATEST" and p.get("BatchSize") == 100
          and p.get("BisectBatchOnFunctionError") is True and p.get("MaximumRetryAttempts") == 3
          and p.get("MaximumRecordAgeInSeconds") == 3600
          and p.get("FunctionResponseTypes") == ["ReportBatchItemFailures"]
          and p.get("FilterCriteria") == {"Filters": [{"Pattern": '{"eventName":["INSERT"]}'}]}
          and drift_dlq is not None
          and (p.get("DestinationConfig") or {}).get("OnFailure", {}).get("Destination")
          == {"Fn::GetAtt": [drift_dlq, "Arn"]},
          "drift metric publisher ESM unchanged (LATEST, 100, bisect, 3 retries, 1 h, INSERT filter, DLQ)")

    # 8b. The archiver archives only what it re-reads from the source table:
    # dynamodb:GetItem on exactly the five table ARNs (no wildcard, no index, no
    # Query/Scan/BatchGetItem, no write), and the expected stream ARNs in its env.
    archiver_role_id = _lid_by_prop(data_tpl, "AWS::IAM::Role", "RoleName", ARCHIVER_ROLE_NAME)
    table_ids = {name: _lid_by_prop(data_tpl, "AWS::DynamoDB::Table", "TableName", name) for name in ARCHIVED_TABLES}
    expected_tables = {"${" + lid + ".Arn}" for lid in table_ids.values() if lid}
    get_item_resources, other_ddb_actions = [], []
    for pol in _tpl_resources(data_tpl, "AWS::IAM::Policy").values():
        if {"Ref": archiver_role_id} not in _as_list(_props(pol).get("Roles")):
            continue
        for st in (_props(pol).get("PolicyDocument") or {}).get("Statement") or []:
            for act in _as_list(st.get("Action")):
                if not isinstance(act, str):
                    continue
                if st.get("Effect") == "Allow" and act == "dynamodb:GetItem":
                    get_item_resources += [_render(r) for r in _as_list(st.get("Resource"))]
                elif st.get("Effect") == "Allow" and (act in ("*",) or act.startswith(("dynamodb:", "dynamodb*"))) \
                        and act not in ARCHIVER_STREAM_READ_ACTIONS:
                    other_ddb_actions.append(act)
    check(archiver_role_id is not None and all(table_ids.values())
          and sorted(get_item_resources) == sorted(expected_tables) and len(expected_tables) == 5,
          "archiver dynamodb:GetItem scoped to exactly the five audit table ARNs (no wildcard, no indexes)")
    check(not other_ddb_actions,
          f"archiver role has no other DynamoDB action than stream reads (got {sorted(set(other_ddb_actions))})")
    stream_env = _render(((fn_props.get("Environment") or {}).get("Variables") or {}).get("EXPECTED_STREAM_ARNS", ""))
    check(len(expected_tables) == 5 and all(("${" + lid + ".StreamArn}") in stream_env for lid in table_ids.values())
          and stream_env.count("${") == 5,
          "archiver EXPECTED_STREAM_ARNS lists exactly the five audit table streams")
    # 9. DLQ, no function DLQ, the eight alarms.
    dlq = _props((data_tpl.get("Resources") or {}).get(dlq_id) or {})
    check(dlq_id is not None and (dlq.get("SqsManagedSseEnabled") is True or "KmsMasterKeyId" in dlq),
          f"{ARCHIVER_DLQ_NAME} exists and is encrypted")
    check(fn_id is not None and "DeadLetterConfig" not in fn_props,
          f"{ARCHIVER_FUNCTION_NAME} has no function DLQ (it would hold full items)")
    alarms = {_props(a).get("AlarmName"): _props(a) for a in _tpl_resources(data_tpl, "AWS::CloudWatch::Alarm").values()}
    for name, (namespace, metric) in ARCHIVE_ALARMS.items():
        a = alarms.get(name) or {}
        check(a.get("Namespace") == namespace and a.get("MetricName") == metric,
              f"alarm {name} on {namespace}/{metric}")
    return results


def hardening_assertions(data_tpl: dict, agents_tpl: dict) -> list:
    """[(domain, passed, description)]: on-call alarm topic, analyst-queue
    send restriction, scoped Lambda logging. Pure."""
    results = []

    def check(domain, passed, description):
        results.append((domain, bool(passed), description))

    resources_of = {"data": data_tpl.get("Resources") or {}, "agents": agents_tpl.get("Resources") or {}}

    # 1. KMS-encrypted topic, CloudWatch-alarms-only publish, TLS only.
    topic_id = _lid_by_prop(data_tpl, "AWS::SNS::Topic", "TopicName", ALARM_TOPIC_NAME)
    topic = _props(resources_of["data"].get(topic_id) or {})
    key_id = _alias_key_id(data_tpl, ALARM_TOPIC_KEY_ALIAS)
    key = _props(resources_of["data"].get(key_id) or {})
    check("Audit", topic_id is not None and key_id is not None
          and topic.get("KmsMasterKeyId") == {"Fn::GetAtt": [key_id, "Arn"]} and key.get("EnableKeyRotation") is True,
          f"{ALARM_TOPIC_NAME} topic is encrypted with its own rotating {ALARM_TOPIC_KEY_ALIAS} key")
    statements = []
    for p in _tpl_resources(data_tpl, "AWS::SNS::TopicPolicy").values():
        if topic_id and {"Ref": topic_id} in _as_list(_props(p).get("Topics")):
            statements.extend((_props(p).get("PolicyDocument") or {}).get("Statement") or [])
    alarm_arns = "arn:aws:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:*"
    allows = [s for s in statements if s.get("Effect") == "Allow"]
    cond = (allows[0].get("Condition") or {}) if len(allows) == 1 else {}
    check("Audit", len(allows) == 1 and allows[0].get("Principal") == {"Service": "cloudwatch.amazonaws.com"}
          and _as_list(allows[0].get("Action")) == ["sns:Publish"]
          and _render((cond.get("StringEquals") or {}).get("aws:SourceAccount")) == "${AWS::AccountId}"
          and _render((cond.get("ArnLike") or {}).get("aws:SourceArn")) == alarm_arns,
          f"{ALARM_TOPIC_NAME}: only this account's CloudWatch alarms are allowed to publish")
    check("Audit", any(s.get("Effect") == "Deny" and _is_any_principal(s.get("Principal"))
                       and "sns:Publish" in _as_list(s.get("Action"))
                       and _render(((s.get("Condition") or {}).get("ArnNotLike") or {}).get("aws:SourceArn"))
                       == alarm_arns for s in statements),
          f"{ALARM_TOPIC_NAME}: Publish denied to every other source")
    check("Audit", any(s.get("Effect") == "Deny" and (s.get("Condition") or {}) == {"Bool": {"aws:SecureTransport": "false"}}
                       for s in statements), f"{ALARM_TOPIC_NAME}: non-TLS publish denied")

    # 2. Review-only alarms notify the topic; trigger alarms keep only the breaker.
    alarms = {}
    for name in ("data", "agents"):
        template = data_tpl if name == "data" else agents_tpl
        for a in _tpl_resources(template, "AWS::CloudWatch::Alarm").values():
            alarms[_props(a).get("AlarmName")] = (name, _props(a))
    topic_ref = {"Ref": topic_id} if topic_id else None
    for alarm_name in NOTIFYING_ALARMS:
        where, props = alarms.get(alarm_name, (None, {}))
        actions = [_resolve_import(a, data_tpl) for a in _as_list(props.get("AlarmActions") or [])]
        check("Audit", topic_ref is not None and actions == [topic_ref],
              f"alarm {alarm_name} notifies {ALARM_TOPIC_NAME} (its only action)")
    breaker_id = _lid_by_prop(agents_tpl, "AWS::Lambda::Function", "FunctionName", "fsi-circuit-breaker")
    for alarm_name in BREAKER_TRIGGER_ALARMS:
        _, props = alarms.get(alarm_name, (None, {}))
        check("Audit", breaker_id is not None
              and _as_list(props.get("AlarmActions") or []) == [{"Fn::GetAtt": [breaker_id, "Arn"]}],
              f"trigger alarm {alarm_name}: the automated breaker is its only action")
    _, sweep_alarm = alarms.get(SWEEP_LIVENESS_ALARM, (None, {}))
    check("Audit", (sweep_alarm.get("Namespace"), sweep_alarm.get("MetricName")) == SWEEP_HEARTBEAT
          and sweep_alarm.get("TreatMissingData") == "breaching"
          and sweep_alarm.get("ComparisonOperator") == "LessThanThreshold"
          and sweep_alarm.get("Threshold") == 1,
          f"alarm {SWEEP_LIVENESS_ALARM} watches {SWEEP_HEARTBEAT[1]} and treats missing data as breaching")

    # 3. Only the executor may SendMessage to the analyst queue (TLS deny kept).
    queue_id = _lid_by_prop(data_tpl, "AWS::SQS::Queue", "QueueName", ANALYST_QUEUE_NAME)
    queue_statements = []
    for p in _tpl_resources(data_tpl, "AWS::SQS::QueuePolicy").values():
        if queue_id and {"Ref": queue_id} in _as_list(_props(p).get("Queues")):
            queue_statements.extend((_props(p).get("PolicyDocument") or {}).get("Statement") or [])
    send_denies = [s for s in queue_statements
                   if s.get("Effect") == "Deny" and _is_any_principal(s.get("Principal"))
                   and "sqs:SendMessage" in _as_list(s.get("Action"))
                   and "ArnNotEquals" in (s.get("Condition") or {})]
    exempt = _as_list(((send_denies[0].get("Condition") or {}).get("ArnNotEquals") or {}).get("aws:PrincipalArn")) \
        if len(send_denies) == 1 else []
    check("Access Control", len(exempt) == 1 and _role_arn_suffix(exempt[0], EXECUTOR_ROLE_NAME),
          f"{ANALYST_QUEUE_NAME}: SendMessage denied to every principal except {EXECUTOR_ROLE_NAME}")
    check("Access Control", any(s.get("Effect") == "Deny" and (s.get("Condition") or {})
                                == {"Bool": {"aws:SecureTransport": "false"}} for s in queue_statements),
          f"{ANALYST_QUEUE_NAME}: non-TLS access denied")

    # 4. Scoped Lambda logging: no AWSLambdaBasicExecutionRole, own group, retention.
    for function_name, role_name in SCOPED_LOG_FUNCTIONS.items():
        template = data_tpl if function_name == ARCHIVER_FUNCTION_NAME else agents_tpl
        res = template.get("Resources") or {}
        fn_id = _lid_by_prop(template, "AWS::Lambda::Function", "FunctionName", function_name)
        group_ref = ((_props(res.get(fn_id) or {}).get("LoggingConfig") or {}).get("LogGroup") or {})
        group = _props(res.get(group_ref.get("Ref")) or {}) if isinstance(group_ref, dict) else {}
        days = group.get("RetentionInDays")
        check("Access Control", group.get("LogGroupName") == f"{LAMBDA_LOG_PREFIX}{function_name}"
              and isinstance(days, int) and not isinstance(days, bool) and days >= 1,
              f"{function_name} logs to its own {LAMBDA_LOG_PREFIX}{function_name} group with a retention period")
    for role_name in sorted(set(SCOPED_LOG_FUNCTIONS.values())):
        template = data_tpl if role_name == ARCHIVER_ROLE_NAME else agents_tpl
        role_id = _lid_by_prop(template, "AWS::IAM::Role", "RoleName", role_name)
        managed = [_render(a) for a in _as_list(_props((template.get("Resources") or {}).get(role_id) or {})
                                               .get("ManagedPolicyArns") or [])]
        check("Access Control", role_id is not None and not any("AWSLambdaBasicExecutionRole" in a for a in managed),
              f"{role_name}: no AWSLambdaBasicExecutionRole")
        log_resources, wide = [], False
        for p in _tpl_resources(template, "AWS::IAM::Policy").values():
            if not role_id or {"Ref": role_id} not in _as_list(_props(p).get("Roles")):
                continue
            for s in (_props(p).get("PolicyDocument") or {}).get("Statement") or []:
                acts = [a for a in _as_list(s.get("Action")) if isinstance(a, str)]
                if s.get("Effect") != "Allow" or not any(a.startswith("logs:") or a == "*" for a in acts):
                    continue
                wide |= any(a in ("*", "logs:*") for a in acts) or \
                    not set(acts) <= {"logs:CreateLogStream", "logs:PutLogEvents"}
                log_resources.extend(_render(r) for r in _as_list(s.get("Resource")))
        expected = sorted(f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{LAMBDA_LOG_PREFIX}{fn}:*"
                          for fn, r in SCOPED_LOG_FUNCTIONS.items() if r == role_name)
        check("Access Control", not wide and sorted(log_resources) == expected,
              f"{role_name}: log writes scoped to its functions' log groups only")
    return results


# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ComplianceGate:
    """Compliance gate runner — collects and reports assertion results."""

    def __init__(self, sign_mode: str = None, kms_client=None, bundles_dir: str = None):
        """sign_mode None = today's run-and-report gate; "kms" = deploy
        signing (registry must be KMS-signed, verified with kms_client);
        "local-dev" = local-dev signed artifact (tests / local demo only)."""
        self.results = []
        self.domain_results = {}
        self.sign_mode = sign_mode
        self.kms_client = kms_client
        bundles_dir = bundles_dir or DEFAULT_BUNDLES_DIR
        self.bundles_dir = bundles_dir if os.path.isabs(bundles_dir) else os.path.join(PROJECT_ROOT, bundles_dir)
        # Facts established by check_deploy_artifact_preconditions().
        self.git_commit = None
        self.tree_clean = False
        self.bundle_digests = {}

    def assert_true(self, condition: bool, domain: str, description: str):
        """Record a single assertion."""
        result = {"domain": domain, "description": description, "passed": condition}
        self.results.append(result)
        if domain not in self.domain_results:
            self.domain_results[domain] = {"passed": 0, "failed": 0, "assertions": []}
        if condition:
            self.domain_results[domain]["passed"] += 1
        else:
            self.domain_results[domain]["failed"] += 1
        self.domain_results[domain]["assertions"].append(result)

    def run_all(self):
        """Run all domain checks."""
        self.check_boundary()
        self.check_model_governance()
        self.check_audit()
        self.check_audit_archive()
        self.check_access_control()
        self.check_model_assurance()
        self.check_supply_chain()

    def check_supply_chain(self):
        """Domain 6: Supply chain.

        Every line of every requirements*.txt and agentcore/*/requirements.txt
        is an exact `name==version` pin (comments and blank lines allowed),
        and each has a hash lock next to it in which every requirement
        carries at least one --hash=sha256:<64 hex>. The gate artifact binds
        the bundle digests (including lib/), so the installed dependency
        bytes are signed too."""
        domain = "Supply chain"
        requirement_files = sorted(
            glob.glob(os.path.join(PROJECT_ROOT, "requirements*.txt"))
            + glob.glob(os.path.join(PROJECT_ROOT, "agentcore", "*", "requirements.txt")))
        if not requirement_files:
            self.assert_true(False, domain, "Requirements files present")
            return
        for path in requirement_files:
            rel = os.path.relpath(path, PROJECT_ROOT)
            with open(path, encoding="utf-8") as f:
                lines = [ln.split("#", 1)[0].strip() for ln in f]
            unpinned = [ln for ln in lines if ln and not PIN_LINE_RE.match(ln)]
            self.assert_true(not unpinned, domain,
                             f"{rel}: every requirement is an exact pin"
                             + (f" (not pinned: {', '.join(unpinned[:5])})" if unpinned else ""))
            lock = path[:-len(".txt")] + ".lock"
            lock_rel = os.path.relpath(lock, PROJECT_ROOT)
            if not os.path.isfile(lock):
                self.assert_true(False, domain, f"{lock_rel}: hash lock present")
                continue
            logical, current = [], ""
            with open(lock, encoding="utf-8") as f:
                for raw in f:
                    text = raw.strip()
                    if not text or text.startswith("#"):
                        continue
                    if text.endswith("\\"):
                        current += text[:-1] + " "
                        continue
                    logical.append((current + text).strip())
                    current = ""
            if current.strip():
                logical.append(current.strip())
            unhashed = [entry.split()[0] for entry in logical
                        if not PIN_LINE_RE.match(entry.split()[0])
                        or not re.search(r"--hash=sha256:[0-9a-f]{64}(\s|$)", entry)]
            self.assert_true(bool(logical) and not unhashed, domain,
                             f"{lock_rel}: every requirement is pinned with a sha256 hash"
                             + (f" (missing: {', '.join(unhashed[:5])})" if unhashed else ""))

    def check_boundary(self):
        """Domain 1: Boundary enforcement."""
        domain = "Boundary"

        # --- PAN ingress filter tests ---
        from lambdas.detection_agent.pan_filter import contains_full_pan

        # 6 evasion variants must be caught
        test_pans = [
            ("plain_16", "4532015112830366"),
            ("dash_sep", "4532-0151-1283-0366"),
            ("space_sep", "4532 0151 1283 0366"),
            ("zero_width", "4532\u200b0151\u200b1283\u200b0366"),
            ("mixed_sep", "4532-0151 1283-0366"),
            ("unicode_fw", "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"),
        ]
        for name, pan in test_pans:
            self.assert_true(
                contains_full_pan(pan),
                domain,
                f"PAN evasion variant '{name}' caught at ingress"
            )

        # Masked PANs must NOT be caught (no false positives)
        safe_pans = [
            ("masked_star", "4532-01**-****-0366"),
            ("masked_x", "4532xxxxxxxx0366"),
        ]
        for name, masked in safe_pans:
            self.assert_true(
                not contains_full_pan(masked),
                domain,
                f"Masked PAN '{name}' correctly allowed"
            )

        # --- Guardrail blocks account IDs in output ---
        # Simulate: cached compliance output should not contain full account IDs.
        # Missing/empty evidence must FAIL, not silently skip and let the
        # overall gate report green — an attacker (or a broken
        # pipeline step) who deletes cached_output/compliance_result.json
        # must not be able to turn this into a vacuous pass.
        comp_data = _load_evidence_or_fail(
            self, domain, "cached_output/compliance_result.json",
            "clusters_assessed",
        )
        if comp_data is not None:
            for cluster in comp_data.get("clusters_assessed", []):
                narrative = cluster.get("sar_narrative", "")
                # Real account IDs from detection should not appear in SAR text
                self.assert_true(
                    "acc-7f3a" not in narrative,
                    domain,
                    f"Account ID not exposed in SAR narrative (cluster {cluster.get('cluster_id', '')[:8]})"
                )

        # --- Detection agent cannot invoke Bedrock (structural check) ---
        detection_handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "detection_agent", "handler.py"
        )
        if os.path.exists(detection_handler_path):
            with open(detection_handler_path, encoding="utf-8") as f:
                detection_code = f.read()
            self.assert_true(
                "bedrock" not in detection_code.lower() or "invoke_model" not in detection_code,
                domain,
                "Detection agent does not invoke Bedrock models"
            )
            self.assert_true(
                "bedrock-runtime" not in detection_code,
                domain,
                "Detection agent has no bedrock-runtime client"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/detection_agent/handler.py missing - cannot verify control"
            )

    def check_model_governance(self):
        """Domain 2: Model Governance."""
        domain = "Model Governance"

        # SAR generation captures model_id + latency + guardrail_action.
        # Missing evidence FAILS rather than silently skipping.
        comp_data = _load_evidence_or_fail(
            self, domain, "cached_output/compliance_result.json",
            "clusters_assessed",
        )
        if comp_data is not None:
            for cluster in comp_data.get("clusters_assessed", []):
                metadata = cluster.get("model_metadata", {})
                sar_meta = metadata.get("sar_call", {})
                chal_meta = metadata.get("challenger_call", {})

                self.assert_true(
                    "model_id" in sar_meta,
                    domain,
                    "SAR call captures model_id"
                )
                self.assert_true(
                    "latency_ms" in sar_meta,
                    domain,
                    "SAR call captures latency_ms"
                )
                self.assert_true(
                    "guardrail_action" in sar_meta,
                    domain,
                    "SAR call captures guardrail_action"
                )

                # Challenger captures same metadata
                self.assert_true(
                    "model_id" in chal_meta,
                    domain,
                    "Challenger call captures model_id"
                )
                self.assert_true(
                    "latency_ms" in chal_meta,
                    domain,
                    "Challenger call captures latency_ms"
                )
                self.assert_true(
                    "guardrail_action" in chal_meta,
                    domain,
                    "Challenger call captures guardrail_action"
                )

                # Prompt independence (hash comparison). Missing evidence
                # must FAIL, not default both sides to the same sentinel
                # ("a") and compare equal-to-itself as a pass —
                # a record with no fingerprints is unevidenced, not proof of
                # independence.
                sar_fp = sar_meta.get("prompt_fingerprint")
                chal_fp = chal_meta.get("prompt_fingerprint")
                self.assert_true(
                    bool(sar_fp) and bool(chal_fp) and sar_fp != chal_fp,
                    domain,
                    "SAR and Challenger use different prompt methodologies (hash differs)"
                )

        # Guardrail attached to BOTH Bedrock calls. A source-text substring
        # grep for "guardrailConfig"/"guardrailIdentifier" passes whether or
        # not a guardrail is ever attached at runtime — those strings are
        # present in the code unconditionally, but GUARDRAIL_ID can still be
        # empty in the deployed environment. Assert against the
        # DEPLOYED runtime's configuration instead: resolve the live
        # AgentCore Runtime's environmentVariables (or, if unreachable in
        # this environment, the resolved GUARDRAIL_ID the agent would
        # actually use) and require it to be a non-empty, real guardrail
        # that matches the stack's own guardrail.
        #
        # This fails closed: if no deployed runtime is reachable AND
        # GUARDRAIL_ID is unset in this process, the assertion FAILS rather
        # than passing (the old behavior) or silently skipping (equally
        # vacuous) — a gate that cannot verify the guardrail is attached must
        # say so, not report green.
        guardrail_id, guardrail_source = resolve_deployed_guardrail_id()
        if not guardrail_id:
            print(
                f"{YELLOW}  ⚠ Cannot verify guardrail attachment: {guardrail_source}. "
                f"Ensure the ComplianceAgent AgentCore Runtime is deployed and "
                f"reachable with this environment's AWS credentials — there is no "
                f"local-env-var fallback for this check. "
                f"Failing closed.{RESET}"
            )
        self.assert_true(
            bool(guardrail_id),
            domain,
            f"Compliance agent has a non-empty GUARDRAIL_ID configured ({guardrail_source})"
        )

        # Non-emptiness alone is not enough: a deployed runtime
        # that drifted to a stale, hand-edited, or unrelated guardrail would
        # still pass a bare bool() check. Compare the deployed runtime's
        # configured (guardrail_id, guardrail_version) against the
        # FsiComplianceAgents stack's OWN published GuardrailId/
        # GuardrailVersion outputs — the actual thing CDK published, not a
        # second unverified local value.
        guardrail_version, _version_source = resolve_deployed_guardrail_version()
        published_id, published_version, published_source = resolve_published_guardrail()
        if not published_id:
            print(
                f"{YELLOW}  ⚠ Cannot verify guardrail matches published stack output: "
                f"{published_source}. Failing closed.{RESET}"
            )
        self.assert_true(
            bool(published_id) and guardrail_id == published_id and guardrail_version == published_version,
            domain,
            "Deployed compliance agent's GUARDRAIL_ID/GUARDRAIL_VERSION matches the "
            f"FsiComplianceAgents stack's published Guardrail ({published_source})"
        )

    def check_audit(self):
        """Domain 3: Audit trail completeness."""
        domain = "Audit"

        # Detection output has all required fields. Missing evidence FAILS
        # rather than silently skipping.
        det_data = _load_evidence_or_fail(
            self, domain, "cached_output/detection_result.json",
            "flagged_clusters",
        )
        if det_data is not None:
            required_fields = ["detection_id", "timestamp", "transaction_count",
                              "gpu_time_seconds", "flagged_clusters", "pagerank_top_10"]
            for field in required_fields:
                self.assert_true(
                    field in det_data,
                    domain,
                    f"Detection output contains '{field}'"
                )

            # Cluster fields
            for cluster in det_data.get("flagged_clusters", []):
                for cfield in ["cluster_id", "typology", "accounts", "account_count",
                              "total_amount_usd", "confidence_factors"]:
                    self.assert_true(
                        cfield in cluster,
                        domain,
                        f"Flagged cluster contains '{cfield}'"
                    )

        # Compliance decision includes both SAR + challenger reasoning.
        # Missing evidence FAILS rather than silently skipping.
        comp_data = _load_evidence_or_fail(
            self, domain, "cached_output/compliance_result.json",
            "clusters_assessed",
        )
        if comp_data is not None:
            for cluster in comp_data.get("clusters_assessed", []):
                self.assert_true(
                    "sar_narrative" in cluster and len(cluster["sar_narrative"]) > 0,
                    domain,
                    "Compliance includes SAR narrative"
                )
                self.assert_true(
                    "challenger_opinion" in cluster,
                    domain,
                    "Compliance includes challenger opinion"
                )
                self.assert_true(
                    "challenger_rationale" in cluster and len(cluster["challenger_rationale"]) > 0,
                    domain,
                    "Compliance includes challenger rationale"
                )
                self.assert_true(
                    cluster.get("decision") in ("FILE_SAR", "NEEDS_REVIEW"),
                    domain,
                    f"Decision is valid: {cluster.get('decision')}"
                )

        # Executor provenance chain
        executor_handler = os.path.join(
            PROJECT_ROOT, "lambdas", "executor_agent", "handler.py"
        )
        if os.path.exists(executor_handler):
            with open(executor_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "provenance_chain" in code,
                domain,
                "Executor records full provenance chain"
            )
            self.assert_true(
                "detection_id" in code and "compliance_id" in code and "action_id" in code,
                domain,
                "Provenance chain links detection → compliance → action"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/executor_agent/handler.py missing - cannot verify control"
            )

    def check_audit_archive(self):
        """Domain 3 (Audit): the immutable S3 audit archive can't be silently
        dropped or weakened. Synthesizes the real CDK app and asserts the
        archive on the templates; a synth failure fails closed. --sign always
        synthesizes fresh (never the cache)."""
        domain = "Audit"
        try:
            min_days = audit_archive_min_retention_days()
            data_tpl, agents_tpl = synth_cdk_templates(use_cache=self.sign_mode is None)
        except SynthUnavailable as e:
            self.assert_true(False, domain, f"Audit archive: CDK app synthesizes ({e})")
            self.assert_true(False, "Access Control", f"Hardening: CDK app synthesizes ({e})")
            return
        self.assert_true(True, domain, "Audit archive: CDK app synthesizes")
        for passed, description in audit_archive_assertions(data_tpl, agents_tpl, min_days):
            self.assert_true(passed, domain, f"Audit archive: {description}")
        # Same templates: on-call alarm topic, analyst-queue send
        # restriction, scoped Lambda logging.
        for hardening_domain, passed, description in hardening_assertions(data_tpl, agents_tpl):
            self.assert_true(passed, hardening_domain, f"Hardening: {description}")

    def check_access_control(self):
        """Domain 4: Access Control (NHI governance)."""
        domain = "Access Control"

        # Three distinct IAM roles defined. Checking len(set(roles)) == 3
        # over the three local string literals below is tautologically
        # true — it never inspects deployed IAM, so it would pass
        # identically even if all three agents were actually pointed at
        # the same underlying role. Resolve each role's real
        # ARN from IAM itself and assert distinctness over THOSE, failing
        # closed if any role could not be resolved.
        role_arns, role_source = resolve_deployed_agent_role_arns()
        if len(role_arns) < 3:
            print(
                f"{YELLOW}  ⚠ Cannot verify IAM role distinctness: {role_source}. "
                f"Failing closed.{RESET}"
            )
        self.assert_true(
            len(role_arns) == 3 and len(set(role_arns.values())) == 3,
            domain,
            f"Three distinct deployed IAM role ARNs resolved ({role_source})"
        )

        # Detection agent cannot invoke Bedrock
        det_handler = os.path.join(PROJECT_ROOT, "lambdas", "detection_agent", "handler.py")
        if os.path.exists(det_handler):
            with open(det_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "bedrock-runtime" not in code,
                domain,
                "Detection role: no bedrock-runtime client (cannot invoke models)"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/detection_agent/handler.py missing - cannot verify control"
            )

        # Compliance agent cannot write SAR filings
        comp_handler = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py")
        if os.path.exists(comp_handler):
            with open(comp_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "SAR_BUCKET" not in code and "s3.put_object" not in code,
                domain,
                "Compliance role: cannot write to SAR filing bucket"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/compliance_agent/handler.py missing - cannot verify control"
            )

        # Executor cannot invoke Bedrock
        exec_handler = os.path.join(PROJECT_ROOT, "lambdas", "executor_agent", "handler.py")
        if os.path.exists(exec_handler):
            with open(exec_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "bedrock-runtime" not in code and "bedrock_runtime" not in code,
                domain,
                "Executor role: no bedrock-runtime client"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/executor_agent/handler.py missing - cannot verify control (Bedrock check)"
            )

        # SOX enforcement: executor rejects overrides
        if os.path.exists(exec_handler):
            with open(exec_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "FORBIDDEN_SIGNALS" in code or "sox_violation" in code.lower(),
                domain,
                "Executor enforces SOX separation of duties"
            )
            self.assert_true(
                "override" in code and "reject" in code.lower(),
                domain,
                "Executor rejects override/approve signals"
            )
        else:
            self.assert_true(
                False, domain,
                "lambdas/executor_agent/handler.py missing - cannot verify control (SOX check)"
            )

        # Circuit breaker can revoke all roles
        cb_handler = os.path.join(PROJECT_ROOT, "circuit_breaker", "handler.py")
        if os.path.exists(cb_handler):
            with open(cb_handler, encoding="utf-8") as f:
                code = f.read()
            self.assert_true(
                "AGENT_ROLES" in code,
                domain,
                "Circuit breaker knows about all agent roles"
            )
            self.assert_true(
                "attach_role_policy" in code or "deny" in code.lower(),
                domain,
                "Circuit breaker can attach deny policy to revoke roles"
            )
        else:
            self.assert_true(
                False, domain,
                "circuit_breaker/handler.py missing - cannot verify control"
            )

    def check_model_assurance(self):
        """
        Domain 5 (D5.2): Model Assurance.

        Validate that the configured model AND every model observed in the
        audit trail are on the organization's approved-models registry
        (exact, version-pinned match). Any unapproved/expired model blocks
        the deploy.
        """
        domain = "Model Assurance"

        # --- Registry must exist and be well-formed ---
        # The registry is read only through the verified loader:
        # the run-and-report gate (and --sign --local-dev) verifies the
        # committed local-dev data/approved_models.json.sig (needs
        # ALLOW_LOCAL_DEV_SIGNING=true, set by `make gate`); deploy signing
        # (--sign) requires the KMS envelope in data/approved_models.json.kms.sig.
        registry = self._load_registry_for_mode(domain)
        if registry is None:
            # Nothing further we can validate without a verified registry.
            return

        self.assert_true(
            True, domain,
            f"Approved-models registry loaded (version {registry.get('registry_version', 'unknown')}, "
            f"{len(approved_model_ids(registry))} approved model(s))"
        )

        # --- Configured models (deploy-time) must be approved ---
        # Champion (SAR) and challenger both — resolved env-var-then-handler,
        # the SAME way the dashboard resolves them (via model_assurance).
        for role_label, env_key in (("champion", "BEDROCK_MODEL_ID"),
                                    ("challenger", "CHALLENGER_MODEL_ID")):
            configured_model = configured_model_id(env_key)
            if configured_model:
                ok, reason = validate_model(configured_model, registry)
                self.assert_true(
                    ok, domain,
                    f"Configured {role_label} model is approved — {reason}"
                )

        # --- Every observed model in the audit trail (runtime) must be approved ---
        # Missing evidence FAILS rather than silently skipping.
        comp_data = _load_evidence_or_fail(
            self, domain, "cached_output/compliance_result.json",
            "clusters_assessed",
        )
        if comp_data is not None:
            for cluster in comp_data.get("clusters_assessed", []):
                metadata = cluster.get("model_metadata", {})
                for call_name in ("sar_call", "challenger_call"):
                    observed = metadata.get(call_name, {}).get("model_id")
                    if observed:
                        ok, reason = validate_model(observed, registry)
                        self.assert_true(
                            ok, domain,
                            f"Observed {call_name} model is approved — {reason}"
                        )

    def _load_registry_for_mode(self, domain: str):
        """Return the verified registry, or None after recording the FAIL."""
        if self.sign_mode == SIGN_MODE_KMS:
            description = "Approved-models registry is KMS-signed"
            path = model_assurance.DEFAULT_REGISTRY_PATH
            kms_sig = model_assurance.default_signature_path(path, True)
            if not os.path.isfile(kms_sig):
                self.assert_true(False, domain, f"{description} — {KMS_SIG_MISSING_MESSAGE}")
                return None
            try:
                envelope = model_assurance.read_signature_envelope(kms_sig)
                if not isinstance(envelope, dict) or envelope.get("algorithm") != signing.ALG_KMS:
                    raise signing.SignatureInvalidError("registry signature is not a KMS envelope")
                if self.kms_client is None:
                    raise signing.SignatureVerificationUnavailableError("no gate signer KMS client")
                registry = load_verified_registry(path, require_kms=True, sig_path=kms_sig,
                                                  kms_client=self.kms_client)
            except signing.SignatureError as e:
                self.assert_true(False, domain, f"{description} ({type(e).__name__}: {e})")
                return None
            except (FileNotFoundError, ValueError) as e:
                self.assert_true(False, domain, f"Approved-models registry loads and is well-formed ({e})")
                return None
            self.assert_true(True, domain, description)
            return registry

        description = "Approved-models registry signature verifies"
        try:
            registry = load_verified_registry()
        except signing.SignatureError as e:
            self.assert_true(
                False, domain,
                f"{description} ({type(e).__name__}: {e}; local runs need ALLOW_LOCAL_DEV_SIGNING=true)")
            return None
        except (FileNotFoundError, ValueError) as e:
            self.assert_true(False, domain, f"Approved-models registry loads and is well-formed ({e})")
            return None
        self.assert_true(True, domain, description)
        return registry

    def check_deploy_artifact_preconditions(self, agents=None):
        """Domain "Deploy Artifact" (only with --sign):

        - the working tree is clean (`git status --porcelain
          --untracked-files=all`); the FAIL lists the first 10 lines;
        - HEAD resolves to a commit id;
        - every bundle zip exists and every packaged source equals its HEAD
          blob (head_binding.check_bundle_at_head);
        - kms mode: no LOCAL_DEV_BUILD marker, and the ComplianceAgent zip's
          bundled registry signature is the committed .kms.sig byte for byte.

        `--sign --local-dev` runs the same git checks."""
        domain = "Deploy Artifact"
        local_dev = self.sign_mode == SIGN_MODE_LOCAL_DEV
        git_path = _git_path()
        if not git_path:
            self.assert_true(False, domain, "git available to bind the artifact to HEAD")
            return
        try:
            status = head_binding.porcelain_status(_git, git_path)
            self.git_commit = head_binding.rev_parse_head(_git, git_path)
            fmt = head_binding.object_format(_git, git_path)
            tree = head_binding.head_tree(_git, git_path)
        except head_binding.HeadBindingError as e:
            self.assert_true(False, domain, f"git facts resolved for the artifact ({e})")
            return
        self.tree_clean = not status
        if status:
            shown = "; ".join(status[:STATUS_LINES_SHOWN])
            more = f" (+{len(status) - STATUS_LINES_SHOWN} more)" if len(status) > STATUS_LINES_SHOWN else ""
            self.assert_true(False, domain, f"working tree not clean: {shown}{more}")
        else:
            self.assert_true(True, domain, "Working tree clean (git status --porcelain --untracked-files=all)")
        self.assert_true(True, domain, f"HEAD commit resolved ({self.git_commit})")

        marker = os.path.join(self.bundles_dir, head_binding.LOCAL_DEV_MARKER)
        if not local_dev:
            self.assert_true(not os.path.exists(marker), domain,
                             "local-dev build cannot be signed for deploy" if os.path.exists(marker)
                             else "Bundles are not a local-dev build")

        agents = agents if agents is not None else _load_deploy_agents()
        by_name = {cfg["name"]: cfg for cfg in agents}
        for name in AGENT_NAMES:
            zip_path = os.path.join(self.bundles_dir, f"{name}.zip")
            if name not in by_name or not os.path.isfile(zip_path):
                self.assert_true(False, domain, f"Bundle present: {name}.zip (run make package)")
                continue
            try:
                offending = head_binding.check_bundle_at_head(
                    zip_path, by_name[name], git_path=git_path, repo_root=PROJECT_ROOT,
                    local_dev=local_dev, git=_git, tree=tree, fmt=fmt)
                digest = bundle_digest.bundle_digest(zip_path)
            except (OSError, ValueError, head_binding.HeadBindingError) as e:
                self.assert_true(False, domain, f"Bundle {name}.zip readable ({type(e).__name__})")
                continue
            for arcname in offending:
                self.assert_true(False, domain, f"packaged source not at HEAD: {arcname}")
            if not offending:
                self.assert_true(True, domain, f"Packaged sources of {name} match HEAD")
                self.bundle_digests[name] = digest

            if name == "ComplianceAgent" and not local_dev:
                kms_sig = model_assurance.default_signature_path(model_assurance.DEFAULT_REGISTRY_PATH, True)
                try:
                    with zipfile.ZipFile(zip_path) as zf:
                        bundled = zf.read(head_binding.REGISTRY_SIGNATURE_ARCNAME)
                    with open(kms_sig, "rb") as f:
                        committed = f.read()
                    same = bundled == committed
                except (OSError, KeyError):
                    same = False
                self.assert_true(same, domain,
                                 "Bundled registry signature is the committed KMS signature" if same
                                 else "bundled registry signature is not the committed KMS signature")

    def build_artifact(self, gate_runner: str) -> dict:
        """The artifact for a fully passing --sign run."""
        now = datetime.now(timezone.utc)
        with open(model_assurance.DEFAULT_REGISTRY_PATH, "rb") as f:
            registry_bytes = f.read()
        registry_sha256 = hashlib.sha256(registry_bytes).hexdigest()
        registry_version = model_assurance.load_registry(data=registry_bytes).get("registry_version")
        model_assurance.parse_registry_version(registry_version)  # ValueError: refused to sign
        passed = sum(1 for r in self.results if r["passed"])
        return {
            "schema": ARTIFACT_SCHEMA,
            "git_commit": self.git_commit,
            "tree_clean": self.tree_clean,
            "created_at": now.isoformat(),
            "expires_at": (now + ARTIFACT_TTL).isoformat(),
            "assertions_total": len(self.results),
            "assertions_passed": passed,
            "results_sha256": hashlib.sha256(signing.canonical_json(self.results)).hexdigest(),
            "registry_sha256": registry_sha256,
            "registry_version": registry_version,
            "bundles": dict(self.bundle_digests),
            "gate_runner": gate_runner,
        }

    def report(self) -> int:
        """Print report and return exit code (0=pass, 1=fail)."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r["passed"])
        failed = total - passed

        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}  COMPLIANCE GATE — Results{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")

        for domain, stats in self.domain_results.items():
            d_pass = stats["passed"]
            d_fail = stats["failed"]
            d_total = d_pass + d_fail
            color = GREEN if d_fail == 0 else RED
            print(f"\n  {BOLD}{domain}{RESET}: {color}{d_pass}/{d_total} passed{RESET}")

            # Show failures
            for assertion in stats["assertions"]:
                if not assertion["passed"]:
                    print(f"    {RED}FAIL:{RESET} {assertion['description']}")

        print(f"\n  {'='*60}")
        if failed == 0:
            print(f"  {GREEN}{BOLD}GATE: PASS ({passed}/{total} assertions){RESET}")
            print(f"  {GREEN}Deploy may proceed.{RESET}")
        else:
            print(f"  {RED}{BOLD}GATE: FAIL ({failed} failures out of {total} assertions){RESET}")
            print(f"  {RED}Deploy BLOCKED.{RESET}")

        print(f"{'='*60}\n")
        return 0 if failed == 0 else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(description="Compliance gate (CI/CD deploy blocker)")
    parser.add_argument("--sign", action="store_true",
                        help="On a full PASS from a clean tree, write and sign "
                             "build/gate/gate-artifact.json (KMS: gate signer role)")
    parser.add_argument("--local-dev", action="store_true",
                        help="With --sign: local-dev signature (tests/local demo only; "
                             "deploy verification always refuses it)")
    parser.add_argument("--bundles-dir", default=DEFAULT_BUNDLES_DIR,
                        help="Directory holding the packaged <Agent>.zip bundles")
    args = parser.parse_args(argv)
    if args.local_dev and not args.sign:
        parser.error("--local-dev requires --sign")
    return args


def _write_signed_artifact(gate: ComplianceGate, session) -> None:
    """Sign and write the artifact (only called after a full PASS)."""
    if gate.sign_mode == SIGN_MODE_LOCAL_DEV:
        runner = f"local:{getpass.getuser()}"
        artifact = gate.build_artifact(runner)
        payload = signing.canonical_json(artifact)
        envelope = signing.sign(signing.PURPOSE_GATE, payload, local_dev=True, signed_by=runner,
                                version=artifact["registry_version"])
    else:
        runner = session.client("sts", region_name=REGION).get_caller_identity()["Arn"]
        artifact = gate.build_artifact(runner)
        payload = signing.canonical_json(artifact)
        envelope = signing.sign(signing.PURPOSE_GATE, payload, kms_client=gate.kms_client, signed_by=runner,
                                version=artifact["registry_version"])
    artifact_path, sig_path = artifact_paths()
    os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
    for path, data in ((artifact_path, payload), (sig_path, json.dumps(envelope, sort_keys=True).encode())):
        tmp = path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    print(f"  {GREEN}Gate artifact written: build/gate/{ARTIFACT_NAME} (+ .sig, "
          f"{envelope['algorithm']}, expires {artifact['expires_at']}){RESET}")


def main(argv=None):
    args = _parse_args(argv)
    if not args.sign:
        gate = ComplianceGate()
        gate.run_all()
        exit_code = gate.report()
        sys.exit(exit_code)

    # --sign: a previous pass can never be reused, whatever happens below.
    remove_stale_artifact()
    session = None
    kms_client = None
    sign_mode = SIGN_MODE_LOCAL_DEV if args.local_dev else SIGN_MODE_KMS
    if sign_mode == SIGN_MODE_KMS:
        try:
            session = _signer_session()
            kms_client = session.client("kms", region_name=REGION)
        except Exception as e:  # no SDK / no profile: the KMS assertions FAIL
            print(f"{YELLOW}  ⚠ No gate signer session ({type(e).__name__}); failing closed.{RESET}")
    gate = ComplianceGate(sign_mode=sign_mode, kms_client=kms_client, bundles_dir=args.bundles_dir)
    gate.run_all()
    gate.check_deploy_artifact_preconditions()
    exit_code = gate.report()
    if exit_code == 0:
        try:
            _write_signed_artifact(gate, session)
        except Exception as e:
            remove_stale_artifact()
            print(f"  {RED}Gate artifact could not be signed ({type(e).__name__}); deploy BLOCKED.{RESET}")
            exit_code = 1
    else:
        remove_stale_artifact()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
