"""
Governance signature envelopes.

Two algorithms:

- KMS_ECDSA_SHA_256: AWS KMS asymmetric ECC_NIST_P256 SIGN_VERIFY keys,
  pinned by key ARN in the committed data/signing_key_pins.json
  (written at deploy time from the CDK outputs by scripts/pin_signing_keys.py).
  Aliases are never resolved: sign() and verify() never call DescribeKey, so
  re-pointing an alias has no effect. The verifier requires the envelope's
  key_id to equal the pinned ARN; the key is never taken from the envelope or
  from an environment variable.
- LOCAL_DEV_HMAC_SHA256: a well-known constant key for local demos and tests.
  Honoured only with ALLOW_LOCAL_DEV_SIGNING=true outside a deployed runtime,
  and never when the caller requires KMS.

Envelope v3 signs signed_at, a version (the registry's registry_version)
and signed_by (the STS-verified signer ARN for KMS envelopes) together with
the payload, so none of them can be edited after signing. verify() can
require a maximum signature age (KMS envelopes; local-dev envelopes skip
freshness) and an expected version. v1 and v2 envelopes are refused (v2 left
signed_by outside the digest); re-sign with sign_registry.py / make gate-sign.

No implicit KMS client: sign() and verify() never construct one. A KMS
envelope with kms_client=None raises SignatureVerificationUnavailableError
without any AWS call, so non-runtime callers (console, in-process compliance,
`make gate`, demos) can never reach KMS on ambient credentials.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

FORMAT_V1 = "fsi-governance-signature/v1"
FORMAT_V2 = "fsi-governance-signature/v2"
FORMAT_V3 = "fsi-governance-signature/v3"
FORMAT = FORMAT_V3

PURPOSE_REGISTRY = "approved-models-registry"
PURPOSE_GATE = "deploy-gate-artifact"
PURPOSES = frozenset({PURPOSE_REGISTRY, PURPOSE_GATE})

ALG_KMS = "KMS_ECDSA_SHA_256"
ALG_LOCAL_DEV = "LOCAL_DEV_HMAC_SHA256"
ALGORITHMS = frozenset({ALG_KMS, ALG_LOCAL_DEV})
LOCAL_DEV_KEY_ID = "local-dev"

ENVELOPE_KEYS = frozenset({
    "format", "purpose", "algorithm", "key_id",
    "payload_sha256", "signature_b64", "signed_at", "signed_by", "version",
})
_V1_ENVELOPE_KEYS = ENVELOPE_KEYS - {"version"}
VERSION_RE = re.compile(r"^[0-9A-Za-z.-]{1,32}$")
# signed_by is joined into the digest with "\n", so it may not contain
# control characters (no newline can shift bytes between fields).
SIGNED_BY_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,512}$")
FUTURE_SKEW_SECONDS = 300

# ─── Pinned signing keys ───────────────────────────────────────
PINS_FORMAT = "fsi-signing-key-pins/v1"
DEFAULT_PINS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "data", "signing_key_pins.json")
MAX_SIGNATURE_AGE_CAPS = {PURPOSE_REGISTRY: 400 * 86400, PURPOSE_GATE: 7 * 86400}
DEFAULT_MAX_SIGNATURE_AGE = {PURPOSE_REGISTRY: 120 * 86400, PURPOSE_GATE: 3600}
_PINS_KEYS = frozenset({"format", "account", "region", "keys", "max_signature_age_seconds"})
_MAX_PINS_BYTES = 16 * 1024
_ACCOUNT_RE = re.compile(r"^\d{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")
_KEY_ARN_RE = re.compile(
    r"^arn:aws:kms:([a-z0-9-]+):(\d{12}):key/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")

ALLOW_LOCAL_DEV_FLAG = "ALLOW_LOCAL_DEV_SIGNING"

# Deliberately public and constant: local-dev signatures prove nothing about
# who signed, which is why deploy verification always refuses them.
_LOCAL_DEV_ONLY_SIGNING_KEY = b"local-dev-only-governance-signing-key-not-for-production"

_KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256"
_MAX_SIGNATURE_B64_CHARS = 1024


class SignatureError(Exception):
    """Base class for governance signature failures."""


class SignatureInvalidError(SignatureError):
    """Definitive: the envelope is malformed, mismatched or the signature is wrong."""


class SignatureVerificationUnavailableError(SignatureError):
    """Transient: verification could not be performed (no client, KMS error).

    Callers must refuse the guarded operation for this request but must not
    cache or latch on this outcome."""


def in_deployed_runtime() -> bool:
    """True inside an AgentCore/Lambda runtime (mirrors pan_filter._txn_ref_key)."""
    return os.path.isdir("/var/task") or bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def local_dev_signing_allowed() -> bool:
    return os.environ.get(ALLOW_LOCAL_DEV_FLAG, "") == "true" and not in_deployed_runtime()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(purpose: str, payload: bytes, signed_at: str, version: str, signed_by: str) -> bytes:
    """v3 message digest: purpose, signed_at, version and signed_by are all signed."""
    return hashlib.sha256(
        FORMAT_V3.encode() + b"\n" + purpose.encode() + b"\n" + signed_at.encode() + b"\n"
        + version.encode() + b"\n" + signed_by.encode("utf-8") + b"\n" + payload).digest()


def _require_purpose(purpose: str) -> None:
    if purpose not in PURPOSES:
        raise ValueError(f"unknown signing purpose: {purpose!r}")


@dataclass(frozen=True)
class KeyPins:
    """The committed signing-key pins (data/signing_key_pins.json)."""
    account: str | None
    region: str | None
    keys: tuple = ()               # ((purpose, key ARN), ...)
    max_ages: tuple = ()           # ((purpose, seconds), ...)

    def key_arn(self, purpose: str):
        return dict(self.keys).get(purpose)

    def max_signature_age(self, purpose: str) -> int:
        return dict(self.max_ages).get(purpose, DEFAULT_MAX_SIGNATURE_AGE[purpose])


def _pins_invalid(message: str):
    raise SignatureInvalidError(f"signing key pins invalid: {message}")


def parse_key_pins(data) -> KeyPins:
    """Validate a parsed pins object; any violation is SignatureInvalidError."""
    if not isinstance(data, dict) or set(data) != _PINS_KEYS:
        _pins_invalid("unexpected keys")
    if data["format"] != PINS_FORMAT:
        _pins_invalid("unknown format")
    account, region, keys, ages = (data["account"], data["region"], data["keys"],
                                   data["max_signature_age_seconds"])
    if account is None or region is None:
        if account is not None or region is not None or keys != {}:
            _pins_invalid("account and region must both be set when any key is pinned")
    elif not (isinstance(account, str) and _ACCOUNT_RE.fullmatch(account)
              and isinstance(region, str) and _REGION_RE.fullmatch(region)):
        _pins_invalid("malformed account or region")
    if not isinstance(keys, dict) or not set(keys) <= PURPOSES:
        _pins_invalid("keys must map signing purposes to key ARNs")
    for purpose, arn in keys.items():
        match = _KEY_ARN_RE.fullmatch(arn) if isinstance(arn, str) else None
        if match is None or match.group(1) != region or match.group(2) != account:
            _pins_invalid(f"{purpose} is not a key ARN in the pinned account and region")
    if not isinstance(ages, dict) or not set(ages) <= PURPOSES:
        _pins_invalid("max_signature_age_seconds must map signing purposes to seconds")
    for purpose, seconds in ages.items():
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not (
                0 < seconds <= MAX_SIGNATURE_AGE_CAPS[purpose]):
            _pins_invalid(f"max_signature_age_seconds.{purpose} out of range")
    return KeyPins(account=account, region=region, keys=tuple(sorted(keys.items())),
                   max_ages=tuple(sorted(ages.items())))


def load_key_pins(path: str = None) -> KeyPins:
    """Load and validate the pins file; missing / oversized / malformed ->
    SignatureInvalidError. Only called for KMS envelopes."""
    path = path or DEFAULT_PINS_PATH
    try:
        with open(path, "rb") as f:
            raw = f.read(_MAX_PINS_BYTES + 1)
    except OSError as exc:
        raise SignatureInvalidError(f"signing key pins missing ({os.path.basename(path)})") from exc
    if len(raw) > _MAX_PINS_BYTES:
        _pins_invalid("file too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise SignatureInvalidError("signing key pins invalid: not JSON") from exc
    return parse_key_pins(data)


def _check_signed_by(signed_by) -> str:
    if not isinstance(signed_by, str) or not SIGNED_BY_RE.fullmatch(signed_by):
        raise SignatureInvalidError("signed_by is malformed")
    return signed_by


def _check_version(version) -> str:
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise SignatureInvalidError("signature version is malformed")
    return version


def _parse_signed_at(value) -> datetime:
    if not isinstance(value, str):
        raise SignatureInvalidError("signed_at is malformed")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise SignatureInvalidError("signed_at is malformed") from exc
    if parsed.tzinfo is None:
        raise SignatureInvalidError("signed_at has no timezone")
    return parsed


def _client_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def sign(purpose: str, payload: bytes, *, kms_client=None, local_dev: bool = False,
         signed_by: str, version: str, pins: KeyPins = None, now: datetime = None) -> dict:
    """Return a v3 signature envelope for `payload` at `version`, signed by
    `signed_by` (bound into the digest).

    local_dev=True signs with the constant local-dev key (refused inside a
    deployed runtime). Otherwise the caller must pass its own KMS client and
    the key is the pinned ARN (pins, default DEFAULT_PINS_PATH); no alias is
    resolved. Errors from KMS propagate to the caller unchanged."""
    _require_purpose(purpose)
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if not isinstance(signed_by, str) or not signed_by:
        raise ValueError("signed_by is required")
    _check_signed_by(signed_by)
    _check_version(version)
    signed_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
    _parse_signed_at(signed_at)
    payload = bytes(payload)
    message_digest = digest(purpose, payload, signed_at, version, signed_by)
    if local_dev:
        if in_deployed_runtime():
            raise SignatureError("local-dev signing is refused in a deployed runtime")
        algorithm = ALG_LOCAL_DEV
        key_id = LOCAL_DEV_KEY_ID
        signature = hmac.new(_LOCAL_DEV_ONLY_SIGNING_KEY, message_digest, hashlib.sha256).digest()
    else:
        if kms_client is None:
            raise SignatureVerificationUnavailableError(
                "KMS signing requires an explicit KMS client")
        key_id = (pins if pins is not None else load_key_pins()).key_arn(purpose)
        if not key_id:
            raise SignatureInvalidError(f"no pinned signing key for {purpose}; run scripts/pin_signing_keys.py")
        response = kms_client.sign(
            KeyId=key_id,
            Message=message_digest,
            MessageType="DIGEST",
            SigningAlgorithm=_KMS_SIGNING_ALGORITHM,
        )
        algorithm = ALG_KMS
        signature = response["Signature"]
    return {
        "format": FORMAT,
        "purpose": purpose,
        "algorithm": algorithm,
        "key_id": key_id,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signed_at": signed_at,
        "signed_by": signed_by,
        "version": version,
    }


def _validate_envelope_shape(envelope) -> None:
    if not isinstance(envelope, dict):
        raise SignatureInvalidError("signature envelope is not an object")
    if envelope.get("format") == FORMAT_V1 or set(envelope) == _V1_ENVELOPE_KEYS:
        raise SignatureInvalidError(
            "v1 signature envelope refused; re-sign (sign_registry.py / make gate-sign)")
    if envelope.get("format") == FORMAT_V2:
        raise SignatureInvalidError(
            "v2 signature envelope refused (signed_by is not signed); re-sign "
            "(sign_registry.py / make gate-sign)")
    if set(envelope) != ENVELOPE_KEYS:
        raise SignatureInvalidError("signature envelope has unexpected keys")
    for key in ENVELOPE_KEYS:
        if not isinstance(envelope[key], str) or not envelope[key]:
            raise SignatureInvalidError(f"signature envelope field {key} is not a non-empty string")
    if envelope["format"] != FORMAT:
        raise SignatureInvalidError("unknown signature envelope format")
    if envelope["algorithm"] not in ALGORITHMS:
        raise SignatureInvalidError("unknown signature algorithm")
    if len(envelope["signature_b64"]) > _MAX_SIGNATURE_B64_CHARS:
        raise SignatureInvalidError("signature is too long")
    # All three are joined with "\n" in the digest, so none may be free text.
    _check_version(envelope["version"])
    _check_signed_by(envelope["signed_by"])
    _parse_signed_at(envelope["signed_at"])


def verify(purpose: str, payload: bytes, envelope, *, kms_client=None, require_kms: bool,
           pins: KeyPins = None, max_age_seconds: int = None, expected_version: str = None,
           now: datetime = None) -> datetime:
    """Raise unless `envelope` is a valid v3 signature of `payload` for
    `purpose`; returns the envelope's signed_at.

    expected_version: the envelope's signed version must equal it.
    max_age_seconds (KMS envelopes): signed_at more than 300 s in the future
    or older than this is refused. KMS envelopes are verified against the
    pinned key ARN (pins, default DEFAULT_PINS_PATH); no alias is resolved.

    SignatureInvalidError is definitive; SignatureVerificationUnavailableError
    is transient (no explicit KMS client, or any KMS/network error)."""
    _require_purpose(purpose)
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    payload = bytes(payload)
    _validate_envelope_shape(envelope)
    if envelope["purpose"] != purpose:
        raise SignatureInvalidError("signature purpose mismatch")
    if expected_version is not None and not hmac.compare_digest(envelope["version"], str(expected_version)):
        raise SignatureInvalidError("signature version does not match the signed content")
    signed_at = _parse_signed_at(envelope["signed_at"])
    if not hmac.compare_digest(envelope["payload_sha256"], hashlib.sha256(payload).hexdigest()):
        raise SignatureInvalidError("payload digest mismatch")
    try:
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignatureInvalidError("signature is not valid base64") from exc
    # signed_by is part of the signed digest: an edited signer fails here.
    message_digest = digest(purpose, payload, envelope["signed_at"], envelope["version"],
                            envelope["signed_by"])

    if envelope["algorithm"] == ALG_LOCAL_DEV:
        if require_kms:
            raise SignatureInvalidError("local-dev signature not accepted where KMS is required")
        if in_deployed_runtime():
            raise SignatureInvalidError("local-dev signature not accepted in a deployed runtime")
        if os.environ.get(ALLOW_LOCAL_DEV_FLAG, "") != "true":
            raise SignatureInvalidError(f"local-dev signature requires {ALLOW_LOCAL_DEV_FLAG}=true")
        if envelope["key_id"] != LOCAL_DEV_KEY_ID:
            raise SignatureInvalidError("local-dev signature has an unexpected key id")
        expected = hmac.new(_LOCAL_DEV_ONLY_SIGNING_KEY, message_digest, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise SignatureInvalidError("local-dev signature does not verify")
        # Local-dev envelopes skip freshness (deploy refuses them anyway).
        return signed_at

    # KMS_ECDSA_SHA_256
    if max_age_seconds is not None:
        now = now or datetime.now(timezone.utc)
        if signed_at > now + timedelta(seconds=FUTURE_SKEW_SECONDS):
            raise SignatureInvalidError("signature is future-dated")
        if now - signed_at > timedelta(seconds=max_age_seconds):
            raise SignatureInvalidError("signature is stale (older than the maximum signature age)")
    if kms_client is None:
        raise SignatureVerificationUnavailableError(
            "KMS envelope not verifiable without an explicit KMS client")
    key_arn = (pins if pins is not None else load_key_pins()).key_arn(purpose)
    if not key_arn:
        raise SignatureInvalidError(f"no pinned signing key for {purpose}")
    if not hmac.compare_digest(envelope["key_id"], key_arn):
        raise SignatureInvalidError("signature key is not the pinned signing key for the purpose")
    try:
        response = kms_client.verify(
            KeyId=key_arn,
            Message=message_digest,
            MessageType="DIGEST",
            Signature=signature,
            SigningAlgorithm=_KMS_SIGNING_ALGORITHM,
        )
    except Exception as exc:
        if _client_error_code(exc) == "KMSInvalidSignatureException":
            raise SignatureInvalidError("KMS signature does not verify") from exc
        raise SignatureVerificationUnavailableError(
            f"KMS verify failed ({type(exc).__name__})") from exc
    if response.get("SignatureValid") is not True:
        raise SignatureInvalidError("KMS signature does not verify")
    return signed_at
