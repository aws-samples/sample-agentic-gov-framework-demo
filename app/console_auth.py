"""
Console authentication: per-operator sign-in, throttling and lockout.

CONSOLE_AUTH_MODE is required and has no default; unset or unknown -> the
sign-in page renders "Console authentication is not configured" and stops.

- local: per-operator scrypt credentials from a 0600 operators file owned by
  the current user. Loopback-only: refuses to render unless server.address
  is 127.0.0.1, ::1 or localhost. Unknown operator ids still run scrypt
  against a fixed dummy record (constant work). Per-identity backoff, never
  a hard or global lockout. This is per-operator attribution for a presenter
  laptop, not an exposure gate.
- alb-cognito: an ALB (TLS + Cognito OIDC) forwards the Cognito access token
  in x-amzn-oidc-accesstoken; Cognito itself validates it through an
  unsigned GetUser call (no host credentials involved), then iss/client_id/
  token_use are checked. Results are cached per sha256(token) for up to 60 s.

DASHBOARD_PASSWORD is ignored (one WARNING per process if still set).
"""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone

from app.console_identity import (
    CONSOLE_ROLES,
    PURPOSES,
    Principal,
    audit_purpose_for,
    clear_principal,
    current_principal,
    governance_session,
    set_principal,
)

logger = logging.getLogger(__name__)

MODE_LOCAL = "local"
MODE_ALB_COGNITO = "alb-cognito"
AUTH_MODES = (MODE_LOCAL, MODE_ALB_COGNITO)

LOOPBACK_ADDRESSES = frozenset({"127.0.0.1", "::1", "localhost"})

# ─── Messages (fixed strings; never file contents or exception text) ──────────
NOT_CONFIGURED = "NOT_CONFIGURED"
NON_LOOPBACK = "NON_LOOPBACK"
OPERATORS_FILE_MISSING = "OPERATORS_FILE_MISSING"
OPERATORS_FILE_PERMISSIONS = "OPERATORS_FILE_PERMISSIONS"
OPERATORS_FILE_MALFORMED = "OPERATORS_FILE_MALFORMED"
COGNITO_NOT_CONFIGURED = "COGNITO_NOT_CONFIGURED"

CONFIG_MESSAGES = {
    NOT_CONFIGURED: "Console authentication is not configured",
    NON_LOOPBACK: ("Local console sign-in is only available on a loopback address "
                   "(server.address must be 127.0.0.1, ::1 or localhost)"),
    OPERATORS_FILE_MISSING: "Operators file not found (create one with scripts/console_add_operator.py)",
    OPERATORS_FILE_PERMISSIONS: "operators file permissions too open",
    OPERATORS_FILE_MALFORMED: "Operators file is malformed",
    COGNITO_NOT_CONFIGURED: "Console authentication is not configured",
}
SIGN_IN_FAILED_MESSAGE = "Incorrect operator id or password"
ALB_SIGN_IN_REQUIRED_MESSAGE = "Sign-in required (via the load balancer)"


class ConsoleAuthConfigError(Exception):
    def __init__(self, code: str):
        super().__init__(CONFIG_MESSAGES[code])
        self.code = code
        self.message = CONFIG_MESSAGES[code]


_LOGGED_ONCE = set()
_LOGGED_ONCE_LOCK = threading.Lock()


def _log_once(key: str, level: int, message: str, *args) -> None:
    with _LOGGED_ONCE_LOCK:
        if key in _LOGGED_ONCE:
            return
        _LOGGED_ONCE.add(key)
    logger.log(level, message, *args)


def configured_mode() -> str | None:
    mode = os.environ.get("CONSOLE_AUTH_MODE")
    return mode if mode in AUTH_MODES else None


def warn_if_dashboard_password_set() -> None:
    if os.environ.get("DASHBOARD_PASSWORD"):
        _log_once("dashboard-password", logging.WARNING,
                  "DASHBOARD_PASSWORD is ignored; set CONSOLE_AUTH_MODE")


# ─── Loopback enforcement (local mode) ────────────────────────────────────────

def _server_address():
    import streamlit as st
    return st.get_option("server.address")


def server_address_is_loopback() -> bool:
    # Streamlit's default (unset) address binds every interface, so only an
    # explicit loopback value passes.
    address = _server_address()
    return isinstance(address, str) and address in LOOPBACK_ADDRESSES


# ─── Operators file (local mode) ──────────────────────────────────────────────

DEFAULT_OPERATORS_FILE = os.path.join("~", ".fsi-console", "operators.json")
MAX_OPERATORS = 20
MAX_OPERATORS_FILE_BYTES = 256 * 1024
OPERATOR_ID_RE = re.compile(r"[a-z][a-z0-9_-]{2,31}")
AWS_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16
_SCRYPT_MAXMEM = 64 * 1024 * 1024

_OPERATOR_KEYS_REQUIRED = frozenset({"operator_id", "display_name", "roles", "scrypt"})
_OPERATOR_KEYS_ALLOWED = _OPERATOR_KEYS_REQUIRED | {"aws_profiles"}
_SCRYPT_KEYS = frozenset({"salt_b64", "n", "r", "p", "dk_b64"})


@dataclass(frozen=True)
class OperatorRecord:
    operator_id: str
    display_name: str
    roles: frozenset
    salt: bytes
    n: int
    r: int
    p: int
    dk: bytes
    aws_profiles: tuple  # ((purpose, profile), ...) so the record stays hashable


def operators_file_path() -> str:
    return os.path.expanduser(os.environ.get("CONSOLE_OPERATORS_FILE") or DEFAULT_OPERATORS_FILE)


def _b64_exact(value, length: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError("not a string")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != length:
        raise ValueError("wrong length")
    return raw


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_operator(entry) -> OperatorRecord:
    if not isinstance(entry, dict):
        raise ValueError("operator entry is not an object")
    keys = set(entry)
    if not _OPERATOR_KEYS_REQUIRED <= keys or not keys <= _OPERATOR_KEYS_ALLOWED:
        raise ValueError("operator entry keys")
    operator_id = entry["operator_id"]
    if not isinstance(operator_id, str) or not OPERATOR_ID_RE.fullmatch(operator_id):
        raise ValueError("operator_id")
    display_name = entry["display_name"]
    if not isinstance(display_name, str) or not 1 <= len(display_name) <= 64:
        raise ValueError("display_name")
    roles = entry["roles"]
    if (not isinstance(roles, list) or len(set(roles)) != len(roles)
            or not all(isinstance(r, str) for r in roles) or not set(roles) <= CONSOLE_ROLES):
        raise ValueError("roles")
    scrypt = entry["scrypt"]
    if not isinstance(scrypt, dict) or set(scrypt) != _SCRYPT_KEYS:
        raise ValueError("scrypt keys")
    if not all(_is_int(scrypt[k]) for k in ("n", "r", "p")):
        raise ValueError("scrypt params")
    # Fixed cost parameters: bounded CPU/memory per attempt and the same work
    # as the dummy record, so timing does not reveal which ids exist.
    if (scrypt["n"], scrypt["r"], scrypt["p"]) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise ValueError("scrypt params")
    salt = _b64_exact(scrypt["salt_b64"], SCRYPT_SALT_BYTES)
    dk = _b64_exact(scrypt["dk_b64"], SCRYPT_DKLEN)
    profiles = entry.get("aws_profiles", {})
    if not isinstance(profiles, dict) or not set(profiles) <= set(PURPOSES):
        raise ValueError("aws_profiles keys")
    for value in profiles.values():
        if not isinstance(value, str) or not AWS_PROFILE_NAME_RE.fullmatch(value):
            raise ValueError("aws_profiles value")
    return OperatorRecord(
        operator_id=operator_id,
        display_name=display_name,
        roles=frozenset(roles),
        salt=salt,
        n=scrypt["n"],
        r=scrypt["r"],
        p=scrypt["p"],
        dk=dk,
        aws_profiles=tuple(sorted(profiles.items())),
    )


def parse_operators_document(doc) -> dict:
    """{operator_id: OperatorRecord}; any schema deviation -> ValueError."""
    if not isinstance(doc, dict) or set(doc) != {"version", "operators"}:
        raise ValueError("top-level keys")
    if not _is_int(doc["version"]) or doc["version"] != 1:
        raise ValueError("version")
    entries = doc["operators"]
    if not isinstance(entries, list) or len(entries) > MAX_OPERATORS:
        raise ValueError("operators")
    records = {}
    for entry in entries:
        record = _parse_operator(entry)
        if record.operator_id in records:
            raise ValueError("duplicate operator_id")
        records[record.operator_id] = record
    return records


def _check_file_stat(st_result) -> None:
    if stat.S_ISLNK(st_result.st_mode) or not stat.S_ISREG(st_result.st_mode):
        raise ConsoleAuthConfigError(OPERATORS_FILE_PERMISSIONS)
    if st_result.st_uid != os.getuid() or st_result.st_mode & 0o077:
        raise ConsoleAuthConfigError(OPERATORS_FILE_PERMISSIONS)


def load_operators(path: str | None = None) -> dict:
    """Load and validate the operators file, failing closed on any doubt."""
    path = path or operators_file_path()
    try:
        link_stat = os.lstat(path)
    except FileNotFoundError:
        raise ConsoleAuthConfigError(OPERATORS_FILE_MISSING) from None
    except OSError:
        raise ConsoleAuthConfigError(OPERATORS_FILE_MISSING) from None
    _check_file_stat(link_stat)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise ConsoleAuthConfigError(OPERATORS_FILE_PERMISSIONS) from None
    with os.fdopen(fd, "rb") as f:
        open_stat = os.fstat(f.fileno())
        if (open_stat.st_ino, open_stat.st_dev) != (link_stat.st_ino, link_stat.st_dev):
            raise ConsoleAuthConfigError(OPERATORS_FILE_PERMISSIONS)
        _check_file_stat(open_stat)
        raw = f.read(MAX_OPERATORS_FILE_BYTES + 1)
    if len(raw) > MAX_OPERATORS_FILE_BYTES:
        raise ConsoleAuthConfigError(OPERATORS_FILE_MALFORMED)
    try:
        return parse_operators_document(json.loads(raw))
    except (ValueError, binascii.Error, TypeError):
        raise ConsoleAuthConfigError(OPERATORS_FILE_MALFORMED) from None


# ─── Password verification ────────────────────────────────────────────────────

def hash_password(password: str, salt: bytes, *, n: int = SCRYPT_N, r: int = SCRYPT_R,
                  p: int = SCRYPT_P) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=_SCRYPT_MAXMEM, dklen=SCRYPT_DKLEN)


# Fixed dummy record: an unknown operator id costs the same scrypt work as a
# known one. Its dk matches no password (it isn't derived from one).
_DUMMY_RECORD = OperatorRecord(
    operator_id="<dummy>",
    display_name="dummy",
    roles=frozenset(),
    salt=b"fsi-console-salt",
    n=SCRYPT_N,
    r=SCRYPT_R,
    p=SCRYPT_P,
    dk=hashlib.sha256(b"fsi-console-dummy-record").digest(),
    aws_profiles=(),
)


# ─── Per-identity throttle ────────────────────────────────────────────────────
# Two tables so flooding unknown ids can never evict a known operator's
# backoff: _KNOWN_THROTTLE holds only ids present in the operators file (at
# most MAX_OPERATORS entries, never evicted); _UNKNOWN_THROTTLE is a bounded
# LRU for everything else.

THROTTLE_FREE_FAILURES = 3
THROTTLE_MAX_DELAY_SECONDS = 30
UNKNOWN_THROTTLE_MAX = 1024
_MAX_THROTTLE_KEY_CHARS = 64

_THROTTLE_LOCK = threading.Lock()
_KNOWN_THROTTLE = {}
_UNKNOWN_THROTTLE = OrderedDict()


def _throttle_key(operator_id: str) -> str:
    return operator_id[:_MAX_THROTTLE_KEY_CHARS]


def _backoff_seconds(failures: int) -> float:
    if failures < THROTTLE_FREE_FAILURES:
        return 0.0
    exponent = min(failures - THROTTLE_FREE_FAILURES, 16)
    return float(min(2 ** exponent, THROTTLE_MAX_DELAY_SECONDS))


def throttle_remaining(operator_id: str, known: bool, now: float | None = None) -> float:
    now = time.time() if now is None else now
    key = _throttle_key(operator_id)
    with _THROTTLE_LOCK:
        table = _KNOWN_THROTTLE if known else _UNKNOWN_THROTTLE
        entry = table.get(key)
    if not entry:
        return 0.0
    return max(0.0, entry[1] - now)


def record_failure(operator_id: str, known: bool, now: float | None = None) -> None:
    now = time.time() if now is None else now
    key = _throttle_key(operator_id)
    with _THROTTLE_LOCK:
        table = _KNOWN_THROTTLE if known else _UNKNOWN_THROTTLE
        failures = min(table.get(key, (0, 0.0))[0] + 1, 1_000_000)
        table[key] = (failures, now + _backoff_seconds(failures))
        if not known:
            _UNKNOWN_THROTTLE.move_to_end(key)
            while len(_UNKNOWN_THROTTLE) > UNKNOWN_THROTTLE_MAX:
                _UNKNOWN_THROTTLE.popitem(last=False)


def record_success(operator_id: str) -> None:
    with _THROTTLE_LOCK:
        _KNOWN_THROTTLE.pop(_throttle_key(operator_id), None)


def _reset_throttle_for_tests() -> None:
    with _THROTTLE_LOCK:
        _KNOWN_THROTTLE.clear()
        _UNKNOWN_THROTTLE.clear()


@dataclass(frozen=True)
class SignInResult:
    principal: Principal | None
    retry_after: float = 0.0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def principal_from_record(record: OperatorRecord) -> Principal:
    return Principal(
        principal_id=f"local:{record.operator_id}",
        display_name=record.display_name,
        auth_mode=MODE_LOCAL,
        roles=record.roles,
        authenticated_at=_utc_now_iso(),
        aws_profiles=dict(record.aws_profiles),
    )


def verify_local_credentials(operator_id, password, operators: dict,
                             *, now: float | None = None) -> SignInResult:
    """Verify one sign-in attempt. A throttled attempt is refused without a
    password check; otherwise scrypt runs exactly once, known id or not."""
    operator_id = operator_id if isinstance(operator_id, str) else ""
    password = password if isinstance(password, str) else ""
    record = operators.get(operator_id)
    known = record is not None
    remaining = throttle_remaining(operator_id, known, now)
    if remaining > 0:
        return SignInResult(None, remaining)
    target = record or _DUMMY_RECORD
    derived = hash_password(password, target.salt, n=target.n, r=target.r, p=target.p)
    if hmac.compare_digest(derived, target.dk) and known:
        record_success(operator_id)
        return SignInResult(principal_from_record(record))
    record_failure(operator_id, known, now)
    return SignInResult(None)


# ─── ALB + Cognito mode ───────────────────────────────────────────────────────

ACCESS_TOKEN_HEADER = "x-amzn-oidc-accesstoken"  # nosec B105 -- HTTP header name, not a credential
REQUIRED_SCOPE = "aws.cognito.signin.user.admin"
MAX_ACCESS_TOKEN_BYTES = 8192
COGNITO_ISSUER_RE = re.compile(r"https://cognito-idp\.[a-z0-9-]+\.amazonaws\.com/[A-Za-z0-9_-]+")
COGNITO_CLIENT_ID_RE = re.compile(r"[a-z0-9]{1,128}")
AWS_REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-\d{1,2}")
COGNITO_SUB_RE = re.compile(r"[A-Za-z0-9-]{1,128}")
GROUP_ROLE_MAP = {"fsi-operator": "operator", "fsi-approver": "approver", "fsi-auditor": "auditor"}
TOKEN_CACHE_SECONDS = 60
TOKEN_CACHE_MAX = 256
_B64URL_SEGMENT_RE = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_UNAVAILABLE_CODES = frozenset({"TooManyRequestsException", "InternalErrorException"})


@dataclass(frozen=True)
class CognitoConfig:
    issuer: str
    client_id: str
    region: str


@dataclass(frozen=True)
class AlbAuthResult:
    principal: Principal | None
    unavailable: bool = False
    error_ref: str | None = None


def load_cognito_config() -> CognitoConfig:
    issuer = os.environ.get("CONSOLE_COGNITO_ISSUER", "")
    client_id = os.environ.get("CONSOLE_COGNITO_CLIENT_ID", "")
    region = os.environ.get("CONSOLE_COGNITO_REGION", "")
    if not (COGNITO_ISSUER_RE.fullmatch(issuer) and COGNITO_CLIENT_ID_RE.fullmatch(client_id)
            and AWS_REGION_RE.fullmatch(region)):
        raise ConsoleAuthConfigError(COGNITO_NOT_CONFIGURED)
    return CognitoConfig(issuer=issuer, client_id=client_id, region=region)


def _request_headers() -> dict:
    """Request-header seam (tests monkeypatch this one-liner)."""
    try:
        import streamlit as st
        return {str(k).lower(): v for k, v in st.context.headers.items()}
    except Exception:
        return {}


def _decode_claims(token: str) -> dict | None:
    segments = token.split(".")
    if len(segments) != 3 or not all(_B64URL_SEGMENT_RE.fullmatch(s) for s in segments):
        return None
    payload = segments[1]
    try:
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, binascii.Error):
        return None
    return claims if isinstance(claims, dict) else None


def _client_error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


_COGNITO_CLIENTS = {}
_COGNITO_CLIENTS_LOCK = threading.Lock()


def _cognito_client(region: str):
    """Unsigned cognito-idp client, once per process: GetUser is authorized by
    the access token itself, so host credentials are never resolved."""
    with _COGNITO_CLIENTS_LOCK:
        client = _COGNITO_CLIENTS.get(region)
        if client is None:
            import boto3
            import botocore
            from botocore.config import Config
            client = boto3.client(
                "cognito-idp",
                region_name=region,
                config=Config(signature_version=botocore.UNSIGNED, retries={"max_attempts": 2},
                              connect_timeout=3, read_timeout=5),
            )
            _COGNITO_CLIENTS[region] = client
        return client


_TOKEN_CACHE = OrderedDict()
_TOKEN_CACHE_LOCK = threading.Lock()


def _reset_alb_state_for_tests() -> None:
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE.clear()
    with _COGNITO_CLIENTS_LOCK:
        _COGNITO_CLIENTS.clear()
    with _LOGGED_ONCE_LOCK:
        _LOGGED_ONCE.clear()


def verify_alb_token(headers: dict, config: CognitoConfig, *, client=None,
                     now: float | None = None) -> AlbAuthResult:
    """Authenticate the ALB-forwarded Cognito access token. Verifies, never
    merely detects: only a token Cognito accepts via GetUser authenticates."""
    now = time.time() if now is None else now
    token = {str(k).lower(): v for k, v in (headers or {}).items()}.get(ACCESS_TOKEN_HEADER)
    if not isinstance(token, str) or not token or len(token.encode("utf-8")) > MAX_ACCESS_TOKEN_BYTES:
        return AlbAuthResult(None)
    claims = _decode_claims(token)
    if claims is None:
        logger.warning("ALB access token rejected: malformed")
        return AlbAuthResult(None)
    scopes = claims.get("scope")
    if not isinstance(scopes, str) or REQUIRED_SCOPE not in scopes.split():
        _log_once("alb-scope", logging.ERROR,
                  "ALB authenticate-cognito scope misconfigured: access token lacks %s", REQUIRED_SCOPE)
        return AlbAuthResult(None)

    cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with _TOKEN_CACHE_LOCK:
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached[1] > now:
            _TOKEN_CACHE.move_to_end(cache_key)
            return AlbAuthResult(cached[0])

    client = client or _cognito_client(config.region)
    try:
        response = client.get_user(AccessToken=token)
    except Exception as exc:
        code = _client_error_code(exc)
        if code and code not in _UNAVAILABLE_CODES:
            logger.warning("ALB access token rejected by Cognito: %s", type(exc).__name__)  # nosemgrep: python-logger-credential-disclosure -- logs only the exception class name; the access token is never formatted into the message
            return AlbAuthResult(None)
        error_id = str(uuid.uuid4())
        logger.error("Cognito GetUser unavailable [%s]: %s", error_id, type(exc).__name__)
        return AlbAuthResult(None, unavailable=True, error_ref=error_id[:8])

    sub = claims.get("sub")
    exp = claims.get("exp")
    if (claims.get("iss") != config.issuer or claims.get("client_id") != config.client_id
            or claims.get("token_use") != "access" or not isinstance(sub, str)
            or not COGNITO_SUB_RE.fullmatch(sub) or not isinstance(exp, (int, float))
            or isinstance(exp, bool) or exp <= now):
        logger.warning("ALB access token rejected: claim mismatch")
        return AlbAuthResult(None)
    attributes = {a.get("Name"): a.get("Value") for a in (response or {}).get("UserAttributes", [])
                  if isinstance(a, dict)}
    if "sub" in attributes and attributes["sub"] != sub:
        logger.warning("ALB access token rejected: subject mismatch")
        return AlbAuthResult(None)
    groups = claims.get("cognito:groups") or []
    if not isinstance(groups, list):
        groups = []
    roles = frozenset(GROUP_ROLE_MAP[g] for g in groups if isinstance(g, str) and g in GROUP_ROLE_MAP)
    principal = Principal(
        principal_id=f"cognito:{sub}",
        display_name=(response or {}).get("Username") or sub,
        auth_mode=MODE_ALB_COGNITO,
        roles=roles,
        authenticated_at=_utc_now_iso(),
    )
    with _TOKEN_CACHE_LOCK:
        _TOKEN_CACHE[cache_key] = (principal, now + min(TOKEN_CACHE_SECONDS, exp - now))
        while len(_TOKEN_CACHE) > TOKEN_CACHE_MAX:
            _TOKEN_CACHE.popitem(last=False)
    return AlbAuthResult(principal)


# ─── CONSOLE_ROLE_ARNS (alb-cognito mode) ─────────────────────────────────────

ROLE_ARN_RE = re.compile(r"arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,512}")
_HOSTED_PURPOSES = frozenset({"operator", "auditor", "audit_writer"})
_ROLE_ARNS = None
_ROLE_ARNS_LOCK = threading.Lock()


def parse_console_role_arns(raw: str | None) -> dict:
    """{purpose: role ARN} for operator / auditor / audit_writer only. An
    approver key is refused: approvals never go through the console host."""
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except ValueError:
        logger.error("CONSOLE_ROLE_ARNS is not valid JSON; hosted AWS authority disabled")
        return {}
    if not isinstance(doc, dict):
        logger.error("CONSOLE_ROLE_ARNS is not a JSON object; hosted AWS authority disabled")
        return {}
    arns = {}
    for purpose, arn in doc.items():
        if purpose == "approver":
            logger.error("CONSOLE_ROLE_ARNS: the approver key is refused; "
                         "approvals never go through the console host")
            continue
        if purpose not in _HOSTED_PURPOSES:
            logger.error("CONSOLE_ROLE_ARNS: unknown purpose key ignored")
            continue
        if not isinstance(arn, str) or not ROLE_ARN_RE.fullmatch(arn):
            logger.error("CONSOLE_ROLE_ARNS: %s is not an IAM role ARN; purpose disabled", purpose)
            continue
        arns[purpose] = arn
    return arns


def console_role_arns() -> dict:
    global _ROLE_ARNS
    with _ROLE_ARNS_LOCK:
        if _ROLE_ARNS is None:
            _ROLE_ARNS = parse_console_role_arns(os.environ.get("CONSOLE_ROLE_ARNS"))
        return dict(_ROLE_ARNS)


def _reset_role_arns_for_tests() -> None:
    global _ROLE_ARNS
    with _ROLE_ARNS_LOCK:
        _ROLE_ARNS = None


# ─── Sign-in / sign-out events ────────────────────────────────────────────────

def record_session_event(p: Principal, action: str) -> None:
    """SIGN_IN / SIGN_OUT: always to the local JSONL; in MODE=live also to
    operator-audit through the principal's own operator session. Best effort:
    no governance effect happens at sign-in, so failures never block it."""
    from app import operator_audit
    try:
        operator_audit.record_console_action(p, action, "COMPLETED", sink=operator_audit.SINK_JSONL)
    except Exception as exc:
        logger.error("Operator audit %s (local) failed [%s]: %s", action, uuid.uuid4(), type(exc).__name__)
    if os.environ.get("MODE", "local") != "live":
        return
    try:
        session = governance_session(p, audit_purpose_for(p))
        p = current_principal() or p
        operator_audit.record_console_action(p, action, "COMPLETED", session=session,
                                             sink=operator_audit.SINK_DYNAMODB)
    except Exception as exc:
        logger.error("Operator audit %s (live) failed [%s]: %s", action, uuid.uuid4(), type(exc).__name__)


def record_sign_in_failure(attempted_operator_id: str) -> None:
    """SIGN_IN_FAILED goes only to the local JSONL, never to DynamoDB and never
    through any operator's AWS profile."""
    from app import operator_audit
    if isinstance(attempted_operator_id, str) and OPERATOR_ID_RE.fullmatch(attempted_operator_id):
        logger.info("Console sign-in failed for operator_id=%s", attempted_operator_id)
    else:
        logger.info("Console sign-in failed for an invalid operator id")
    try:
        operator_audit.record_console_action(None, "SIGN_IN_FAILED", "FAILED",
                                             attempted_operator_id=attempted_operator_id)
    except Exception as exc:
        logger.error("Operator audit SIGN_IN_FAILED failed [%s]: %s", uuid.uuid4(), type(exc).__name__)


def sign_out() -> None:
    p = current_principal()
    if p is not None:
        record_session_event(p, "SIGN_OUT")
    clear_principal()


# ─── Streamlit entry point ────────────────────────────────────────────────────

def _stop(st, message: str) -> None:
    st.error(message)
    st.stop()


def authenticate_or_render_sign_in() -> Principal | None:
    """Return the signed-in principal, or render the sign-in page and stop."""
    import streamlit as st

    warn_if_dashboard_password_set()
    mode = configured_mode()
    if mode is None:
        st.title("FSI Agentic Compliance — Sign in")
        _log_once("auth-not-configured", logging.ERROR, "Console authentication is not configured")
        _stop(st, CONFIG_MESSAGES[NOT_CONFIGURED])
        return None

    if mode == MODE_ALB_COGNITO:
        return _authenticate_alb(st)

    # local mode: loopback check runs before anything renders.
    if not server_address_is_loopback():
        st.title("FSI Agentic Compliance — Sign in")
        _log_once("auth-non-loopback", logging.ERROR, "Local console mode refused a non-loopback bind")
        _stop(st, CONFIG_MESSAGES[NON_LOOPBACK])
        return None
    p = current_principal()
    if p is not None and p.auth_mode == MODE_LOCAL:
        return p
    st.title("FSI Agentic Compliance — Sign in")
    try:
        operators = load_operators()
    except ConsoleAuthConfigError as exc:
        _log_once(f"operators-{exc.code}", logging.ERROR, "Operators file refused: %s", exc.code)
        _stop(st, exc.message)
        return None
    with st.form("console_sign_in"):
        operator_id = st.text_input("Operator id")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        result = verify_local_credentials(operator_id, password, operators)
        if result.principal is not None:
            set_principal(result.principal)
            record_session_event(result.principal, "SIGN_IN")
            st.rerun()
        elif result.retry_after > 0:
            logger.debug("Console sign-in throttled")
            st.error(f"Try again in {math.ceil(result.retry_after)}s")
        else:
            record_sign_in_failure(operator_id)
            st.error(SIGN_IN_FAILED_MESSAGE)
    st.stop()
    return None


def _authenticate_alb(st) -> Principal | None:
    try:
        config = load_cognito_config()
    except ConsoleAuthConfigError as exc:
        st.title("FSI Agentic Compliance — Sign in")
        _log_once("cognito-not-configured", logging.ERROR, "Cognito console mode is not configured")
        _stop(st, exc.message)
        return None
    console_role_arns()  # parse once at startup: refuses an approver key with an ERROR log
    result = verify_alb_token(_request_headers(), config)
    if result.principal is None:
        clear_principal()
        st.title("FSI Agentic Compliance — Sign in")
        if result.unavailable:
            _stop(st, f"Sign-in temporarily unavailable (ref {result.error_ref})")
        else:
            _stop(st, ALB_SIGN_IN_REQUIRED_MESSAGE)
        return None
    previous = current_principal()
    if (previous is None or previous.principal_id != result.principal.principal_id
            or previous.roles != result.principal.roles):
        set_principal(result.principal)
        record_session_event(result.principal, "SIGN_IN")
        return current_principal() or result.principal
    return previous
