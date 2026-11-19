"""
Runtime self-check of the signed gate artifact.

State machine (module-level instance guarded by a lock):

    UNCHECKED  -> VERIFIED    success (cached for the process lifetime)
    UNCHECKED  -> UNVERIFIED  transient failure (KMS unavailable/throttled/denied);
    UNVERIFIED -> VERIFIED       retried at most once every RETRY_SECONDS
    UNCHECKED  -> INVALID     definitive failure (bad signature, hash mismatch,
    UNVERIFIED -> INVALID        missing/malformed artifact); terminal (latched)

check() returns None when the request may be served, otherwise the error
code the shim returns with a 503. Outside a deployed runtime it is a no-op
unless REQUIRE_GATE_ARTIFACT=true.

This is defense in depth: deploy-path verification is the primary control,
and a code-rewriting attacker could remove this check.
"""
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid

from governance_common import signing

logger = logging.getLogger(__name__)

STATE_UNCHECKED = "UNCHECKED"
STATE_VERIFIED = "VERIFIED"
STATE_UNVERIFIED = "UNVERIFIED"
STATE_INVALID = "INVALID"

ERROR_INVALID = "GOVERNANCE_ARTIFACT_INVALID"
ERROR_UNVERIFIED = "GOVERNANCE_ARTIFACT_UNVERIFIED"

RETRY_SECONDS = 30.0
ARTIFACT_ARCNAME = "governance/gate-artifact.json"
SIGNATURE_ARCNAME = "governance/gate-artifact.json.sig"
PINS_ARCNAME = "data/signing_key_pins.json"  # bundled at the zip root
EXPECTED_SHA256_ENV = "GATE_ARTIFACT_SHA256"
REQUIRE_ENV = "REQUIRE_GATE_ARTIFACT"
REGION = os.environ.get("AWS_REGION", "us-east-1")

_SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}")
_MAX_ARTIFACT_BYTES = 1024 * 1024


class ArtifactInvalidError(Exception):
    """Definitive: the artifact or its envelope is missing, malformed or mismatched."""


def attestation_required() -> bool:
    return signing.in_deployed_runtime() or os.environ.get(REQUIRE_ENV, "") == "true"


def _default_kms_client_factory():
    # Only the deployed runtime's own execution role may be used for KMS.
    if not signing.in_deployed_runtime():
        raise signing.SignatureVerificationUnavailableError(
            "no KMS client outside a deployed runtime")
    import boto3  # deferred: the shims keep cold start light
    return boto3.client("kms", region_name=REGION)


def _read_bounded(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError as exc:
        raise ArtifactInvalidError(f"cannot read {os.path.basename(path)}") from exc
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ArtifactInvalidError(f"{os.path.basename(path)} is too large")
    return data


class RuntimeAttestation:
    def __init__(self, root: str, *, registry_relpath: str | None = None,
                 kms_client_factory=None, retry_seconds: float = RETRY_SECONDS,
                 pins_path: str | None = None):
        self._root = root
        self._pins_path = pins_path
        self._registry_relpath = registry_relpath
        self._kms_client_factory = kms_client_factory or _default_kms_client_factory
        self._kms_client = None
        self._retry_seconds = retry_seconds
        self._lock = threading.Lock()
        self._state = STATE_UNCHECKED
        self._next_attempt = 0.0

    @property
    def state(self) -> str:
        return self._state

    def check(self) -> str | None:
        if not attestation_required():
            return None
        with self._lock:
            if self._state == STATE_VERIFIED:
                return None
            if self._state == STATE_INVALID:
                return ERROR_INVALID
            if self._state == STATE_UNVERIFIED and time.monotonic() < self._next_attempt:
                return ERROR_UNVERIFIED
            error_id = str(uuid.uuid4())
            try:
                self._verify()
            except (signing.SignatureInvalidError, ArtifactInvalidError) as exc:
                self._state = STATE_INVALID
                logger.error("Gate artifact attestation failed definitively [%s]: %s",
                             error_id, type(exc).__name__)
                return ERROR_INVALID
            except Exception as exc:  # transient: Unavailable, client construction, network
                self._state = STATE_UNVERIFIED
                self._next_attempt = time.monotonic() + self._retry_seconds
                logger.warning("Gate artifact could not be verified yet [%s]: %s",
                               error_id, type(exc).__name__)
                return ERROR_UNVERIFIED
            self._state = STATE_VERIFIED
            logger.info("Gate artifact verified")
            return None

    def _verify(self) -> None:
        artifact_bytes = _read_bounded(os.path.join(self._root, ARTIFACT_ARCNAME))
        signature_bytes = _read_bounded(os.path.join(self._root, SIGNATURE_ARCNAME))
        try:
            envelope = json.loads(signature_bytes)
            artifact = json.loads(artifact_bytes)
        except ValueError as exc:
            raise ArtifactInvalidError("artifact or signature is not JSON") from exc
        if not isinstance(artifact, dict) or not isinstance(envelope, dict):
            raise ArtifactInvalidError("artifact or signature is not an object")

        expected = os.environ.get(EXPECTED_SHA256_ENV, "")
        if not _SHA256_HEX_RE.fullmatch(expected):
            raise ArtifactInvalidError(f"{EXPECTED_SHA256_ENV} is missing or malformed")
        if not hmac.compare_digest(hashlib.sha256(artifact_bytes).hexdigest(), expected):
            raise ArtifactInvalidError("artifact hash does not match the deployed runtime")

        registry_version = artifact.get("registry_version")
        if not isinstance(registry_version, str) or not signing.VERSION_RE.fullmatch(registry_version):
            raise ArtifactInvalidError("gate artifact has no registry_version")
        if self._registry_relpath:
            registry_bytes = _read_bounded(os.path.join(self._root, self._registry_relpath))
            recorded = artifact.get("registry_sha256")
            if not isinstance(recorded, str) or not hmac.compare_digest(
                    hashlib.sha256(registry_bytes).hexdigest(), recorded):
                raise ArtifactInvalidError("bundled registry does not match the gate artifact")
            try:
                bundled_version = json.loads(registry_bytes).get("registry_version")
            except (ValueError, AttributeError) as exc:
                raise ArtifactInvalidError("bundled registry is not a JSON object") from exc
            if bundled_version != registry_version:
                raise ArtifactInvalidError("gate artifact registry_version does not match the bundled registry")

        if self._kms_client is None:
            self._kms_client = self._kms_client_factory()
        # Pinned gate key (data/signing_key_pins.json at the bundle root), no
        # alias lookup; the envelope must sign the artifact's registry_version.
        # No freshness here: the artifact hash is pinned at deploy, and a
        # runtime may start long after.
        signing.verify(signing.PURPOSE_GATE, artifact_bytes, envelope,
                       kms_client=self._kms_client, require_kms=True, pins=self._pins(),
                       expected_version=registry_version)

    def _pins(self):
        return signing.load_key_pins(self._pins_path) if self._pins_path else signing.load_key_pins()


_DEFAULT = None
_DEFAULT_LOCK = threading.Lock()


def check_once(root: str, *, registry_relpath: str | None = None) -> str | None:
    """Process-wide attestation for a shim; the first call fixes root/registry."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = RuntimeAttestation(root, registry_relpath=registry_relpath,
                                          pins_path=os.path.join(root, PINS_ARCNAME))
        instance = _DEFAULT
    return instance.check()
