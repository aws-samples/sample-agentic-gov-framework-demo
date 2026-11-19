#!/usr/bin/env python3
"""
============================================================================
BLUEPRINT 5 — DEPLOYMENT CONTROL / D5.2 MODEL ASSURANCE
============================================================================
Model Assurance validates that every foundation model the system is
configured to use — and every model actually observed in the audit trail —
appears on the organization's approved-models registry
(data/approved_models.json), which is owned by the Model Risk Committee.

Matching is EXACT and version-pinned: the fully-qualified model_id
(including the trailing version, e.g. `...-v1:0`) must be present on the
list, its status must be `approved`, and its approval must not be expired.
A new model — or even a new *version* of an approved model — is NOT allowed
until it has been reviewed and added to the registry.

This module is deliberately dependency-free and side-effect-free so it can
be reused by:
  - the compliance gate (deploy-time blocker), and
  - runtime/audit checks (validate observed model_ids from metadata).
============================================================================
"""
import hashlib
import json
import os
import re
import sys
import threading
from datetime import date, datetime

# Default registry location (organization-approved model inventory).
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# governance_common sits next to this module both in the repo and at the
# ComplianceAgent zip root.
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
from governance_common import signing  # noqa: E402
DEFAULT_REGISTRY_PATH = os.path.join(PROJECT_ROOT, "data", "approved_models.json")


def normalize_model_id(model_id: str) -> str:
    """
    Normalize a model identifier for comparison.

    We intentionally keep this conservative: only strip surrounding
    whitespace and lowercase. We do NOT strip region/inference-profile
    prefixes or version suffixes — the whole point of Option A (exact,
    version-pinned matching) is that a different version or profile is a
    different, unreviewed artifact and must fail until explicitly approved.
    """
    if model_id is None:
        return ""
    return str(model_id).strip().lower()


def _parse_registry(data: bytes) -> dict:
    """Parse and shape-check registry bytes (no integrity check)."""
    registry = json.loads(data.decode("utf-8"))
    if not isinstance(registry, dict):
        raise ValueError("Registry must be a JSON object")
    if not isinstance(registry.get("approved_models"), list):
        raise ValueError("Registry must contain an 'approved_models' list")
    return registry


def load_registry(path: str = DEFAULT_REGISTRY_PATH, *, data: bytes = None) -> dict:
    """
    Load and validate the approved-models registry file (pure parse: NO
    signature check — governance readers use load_verified_registry).

    `data`, when given, is parsed instead of reading `path` (used by
    load_verified_registry so the bytes parsed are the bytes verified).

    Raises:
        FileNotFoundError: registry file missing.
        ValueError: registry malformed (not an object, or missing/!list
                    'approved_models').

    Returns:
        The parsed registry dict.
    """
    if data is None:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Approved-models registry not found at: {path}")
        with open(path, "rb") as f:
            data = f.read()
    return _parse_registry(data)


# ─── Signed registry ─────────────────────────────────────────────
#
# Two signature files:
#   data/approved_models.json.sig      LOCAL_DEV_HMAC_SHA256, committed; read by
#                                      tests, console, in-process compliance,
#                                      `make gate`, demos (ALLOW_LOCAL_DEV_SIGNING)
#   data/approved_models.json.kms.sig  KMS_ECDSA_SHA_256, written only by
#                                      scripts/sign_registry.py --kms; read by
#                                      `compliance_gate.py --sign` and packaging
# Inside the ComplianceAgent runtime there is one file, arcname
# data/approved_models.json.sig, and it always holds the KMS envelope.

_MAX_SIGNATURE_BYTES = 64 * 1024
_RUNTIME_KMS_CLIENT = None

# registry_version: "YYYY-Qn" or "YYYY-Qn.rev".
_REGISTRY_VERSION_RE = re.compile(r"^(\d{4})-Q([1-4])(?:\.(\d{1,3}))?$")

# In-process monotonic latch: (highest accepted parsed version,
# its sha256). A strict (KMS) read refuses a lower version, or the same
# version with different bytes. Defense in depth against a swapped file
# mid-process; the durable floor is the SSM parameter checked at deploy.
_ACCEPTED_REGISTRY = None
_ACCEPTED_LOCK = threading.Lock()


def parse_registry_version(value) -> tuple:
    """"2026-Q3" -> (2026, 3, 0); "2026-Q3.2" -> (2026, 3, 2). Anything else
    -> ValueError (refused to sign, Invalid on a strict verify)."""
    match = _REGISTRY_VERSION_RE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(f"registry_version must look like 2026-Q3 or 2026-Q3.1, got {value!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _latch(version: tuple, sha256: str) -> None:
    global _ACCEPTED_REGISTRY
    with _ACCEPTED_LOCK:
        if _ACCEPTED_REGISTRY is not None:
            highest, highest_sha = _ACCEPTED_REGISTRY
            if version < highest:
                raise signing.SignatureInvalidError(
                    "registry_version is older than one this process already accepted")
            if version == highest and sha256 != highest_sha:
                raise signing.SignatureInvalidError(
                    "registry content changed without a registry_version bump")
            if version == highest:
                return
        _ACCEPTED_REGISTRY = (version, sha256)


def default_signature_path(path: str, require_kms: bool) -> str:
    """Which signature file a verified read uses (see the table above)."""
    if signing.in_deployed_runtime():
        return path + ".sig"
    if require_kms:
        return path + ".kms.sig"
    return path + ".sig"


def _runtime_kms_client():
    """The deployed runtime's own execution-role KMS client, built once per
    process. Never called outside a deployed runtime."""
    global _RUNTIME_KMS_CLIENT
    if _RUNTIME_KMS_CLIENT is None:
        import boto3  # deferred: only the runtime path needs it
        _RUNTIME_KMS_CLIENT = boto3.client(
            "kms", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    return _RUNTIME_KMS_CLIENT


def read_signature_envelope(sig_path: str) -> dict:
    """Read a signature envelope file; a missing/unreadable/non-JSON file is a
    definitive SignatureInvalidError."""
    try:
        with open(sig_path, "rb") as f:
            raw = f.read(_MAX_SIGNATURE_BYTES + 1)
    except OSError as exc:
        raise signing.SignatureInvalidError(
            f"registry signature file missing: {os.path.basename(sig_path)}") from exc
    if len(raw) > _MAX_SIGNATURE_BYTES:
        raise signing.SignatureInvalidError("registry signature file is too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise signing.SignatureInvalidError("registry signature file is not JSON") from exc


def verified_registry_bytes(path: str = None, *, require_kms: bool = None, sig_path: str = None,
                            kms_client=None, pins=None, now=None) -> tuple:
    """Verify and parse the registry; return (registry, verified_bytes, signed_at).

    The envelope's signed version must equal the registry's registry_version.
    A KMS envelope is checked against the pinned key and the registry's
    maximum signature age; a strict read also needs a well-formed
    registry_version and passes the in-process latch.

    Raises signing.SignatureInvalidError (definitive) or
    signing.SignatureVerificationUnavailableError (transient), or
    FileNotFoundError / ValueError for a missing / malformed registry."""
    path = path or DEFAULT_REGISTRY_PATH
    strict = require_kms if require_kms is not None else signing.in_deployed_runtime()
    if sig_path is None:
        sig_path = default_signature_path(path, strict)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Approved-models registry not found at: {path}")
    with open(path, "rb") as f:
        data = f.read()
    envelope = read_signature_envelope(sig_path)
    if kms_client is None and isinstance(envelope, dict) and envelope.get("algorithm") == signing.ALG_KMS:
        if not signing.in_deployed_runtime():
            # Console / in-process compliance / `make gate` / demos never
            # reach KMS on ambient credentials (no AWS call made here).
            raise signing.SignatureVerificationUnavailableError(
                "KMS envelope not verifiable in console")
        kms_client = _runtime_kms_client()
    registry = load_registry(path, data=data)
    version = registry.get("registry_version")
    if not isinstance(version, str):
        raise signing.SignatureInvalidError("registry has no registry_version")
    max_age = None
    if isinstance(envelope, dict) and envelope.get("algorithm") == signing.ALG_KMS:
        pins = pins if pins is not None else signing.load_key_pins()
        max_age = pins.max_signature_age(signing.PURPOSE_REGISTRY)
    signed_at = signing.verify(signing.PURPOSE_REGISTRY, data, envelope,
                               kms_client=kms_client, require_kms=strict, pins=pins,
                               max_age_seconds=max_age, expected_version=version, now=now)
    if strict:
        try:
            parsed = parse_registry_version(version)
        except ValueError as exc:
            raise signing.SignatureInvalidError(str(exc)) from exc
        _latch(parsed, hashlib.sha256(data).hexdigest())
    return registry, data, signed_at


def load_verified_registry(path: str = None, *, require_kms: bool = None, sig_path: str = None,
                           kms_client=None) -> dict:
    """Load the approved-models registry only if its signature verifies.

    path        defaults to DEFAULT_REGISTRY_PATH (resolved at call time).
    require_kms defaults to in_deployed_runtime().
    sig_path    defaults per default_signature_path().
    kms_client  explicit client; inside a deployed runtime a missing one is
                the runtime's own (built once); outside a runtime none is
                ever built."""
    registry, _data, _signed_at = verified_registry_bytes(
        path, require_kms=require_kms, sig_path=sig_path, kms_client=kms_client)
    return registry


def _index_by_model_id(registry: dict) -> dict:
    """Build a normalized model_id -> entry index from the registry."""
    index = {}
    for entry in registry.get("approved_models", []):
        if isinstance(entry, dict) and entry.get("model_id"):
            index[normalize_model_id(entry["model_id"])] = entry
    return index


def _is_expired(expires_on: str, today: date) -> bool:
    """Return True if expires_on is a valid past date. Unparseable => not expired."""
    if not expires_on:
        return False
    try:
        exp = datetime.strptime(str(expires_on), "%Y-%m-%d").date()
    except ValueError:
        # Malformed date — treat as non-expiring rather than silently blocking.
        return False
    return exp < today


def validate_model(model_id: str, registry: dict, today: date = None) -> tuple:
    """
    Validate a single model_id against the approved-models registry.

    Exact, version-pinned membership check plus status and expiry gates.

    Args:
        model_id: The fully-qualified model identifier to validate.
        registry: Registry dict (from load_registry).
        today: Override for the current date (testing). Defaults to date.today().

    Returns:
        (approved: bool, reason: str) — reason is human-readable and names
        exactly why validation failed so the fix is obvious.
    """
    if today is None:
        today = date.today()

    if not model_id or not str(model_id).strip():
        return False, "No model_id provided (empty or missing)"

    index = _index_by_model_id(registry)
    entry = index.get(normalize_model_id(model_id))

    if entry is None:
        return False, (
            f"Model '{model_id}' is NOT on the approved-models registry "
            f"(exact version-pinned match required). It must be reviewed and "
            f"added before use."
        )

    status = str(entry.get("status", "")).strip().lower()
    if status != "approved":
        return False, f"Model '{model_id}' status is '{status or 'unspecified'}', not 'approved'"

    if _is_expired(entry.get("expires_on"), today):
        return False, (
            f"Model '{model_id}' approval EXPIRED on {entry.get('expires_on')} "
            f"— requires re-review"
        )

    return True, f"Model '{model_id}' is approved (registry {registry.get('registry_version', 'unknown')})"


def approved_model_ids(registry: dict) -> list:
    """Return the list of currently-approved (status=approved) model_ids."""
    return [
        e["model_id"]
        for e in registry.get("approved_models", [])
        if isinstance(e, dict) and str(e.get("status", "")).strip().lower() == "approved" and e.get("model_id")
    ]


# Compliance agent handler — the single source of the configured-model defaults.
_HANDLER_PATH = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py")


def configured_model_id(env_key: str, handler_path: str = _HANDLER_PATH) -> str:
    """
    Determine the model the system is configured to use for a given env key
    (e.g. 'BEDROCK_MODEL_ID' for the champion, 'CHALLENGER_MODEL_ID' for the
    challenger).

    Resolution order — identical for the gate and the dashboard so they never
    disagree:
      1. the environment variable (what a deploy would actually apply), else
      2. the default pinned in the compliance agent handler source, read
         statically (so editing handler.py live is reflected on the next read).

    Returns "" if neither is found.
    """
    env_model = os.environ.get(env_key)
    if env_model:
        return env_model.strip()

    if os.path.exists(handler_path):
        with open(handler_path, encoding="utf-8") as f:
            for line in f:
                if env_key in line and "os.environ.get" in line:
                    # e.g. MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "<default>")
                    parts = line.split('"')
                    if len(parts) >= 4:
                        return parts[3].strip()
    return ""
