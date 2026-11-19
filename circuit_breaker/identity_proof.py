"""
Server-verified caller identity with a single-use nonce.

Shared by the breaker Lambda (verify_identity) and its human clients
(presign_identity: app/invoke_live.py, scripts/ensure_agents_enabled.py).

Client: sign an sts:GetCallerIdentity POST with the caller's OWN SigV4
credentials, with an ``x-fsi-breaker-nonce`` header present at signing time so
it lands in X-Amz-SignedHeaders. The header value binds the proof to one
action and one target and carries 32 random bytes. The caller hands the
presigned URL and the header value to the breaker instead of sending it.

Server: shape checks (no network) -> the STS POST itself (STS rejects the
signature unless the exact signed header value is sent) -> a conditional
``nonce#<sha256>`` put in governance-audit. Nothing is written before STS has
verified the caller, and the conditional put makes every proof single-use,
including under concurrent replays of the same URL + header.

Pure functions and constants only. This file is imported both as the
top-level module ``identity_proof`` (Lambda layout, circuit_breaker/handler.py)
and as ``circuit_breaker.identity_proof`` (repo-root clients); botocore is
imported lazily inside presign_identity so the server path never needs it.
"""
import hashlib
import logging
import re
import secrets
import urllib.parse
import urllib.request
from collections import namedtuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

NONCE_HEADER = "x-fsi-breaker-nonce"
PRESIGN_EXPIRES_SECONDS = 60
MAX_EXPIRES_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 300
STS_TIMEOUT_SECONDS = 5

ACTIONS = ("trip", "request_release", "approve_release")
HEADER_RE = re.compile(
    r"^v1:(trip|request_release|approve_release):([A-Za-z0-9#:_-]{1,96}):([0-9a-f]{64})$")
_REQUIRED_SINGLE_PARAMS = {
    "Action": "GetCallerIdentity",
    "Version": "2011-06-15",
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
}
_ONE_EACH = ("X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders",
             "X-Amz-Signature")
_ARN_RE = re.compile(rb"<Arn>([^<]{1,2048})</Arn>")
_USER_ID_RE = re.compile(rb"<UserId>([^<]{1,256})</UserId>")
_ACCOUNT_RE = re.compile(rb"<Account>(\d{12})</Account>")
_ROLE_USER_ID_RE = re.compile(r"^(ARO[A-Z0-9]{13,})(?::([\w+=,.@-]{1,64}))?$")

# arn, the AROA... role id from <UserId>, the 12-digit account, and the
# session-name part of <UserId> (None if absent).
VerifiedPrincipal = namedtuple("VerifiedPrincipal", "arn role_id account session")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def presign_identity(session, region: str, action: str, target: str):
    """Return (presigned_url, header_value) proving the session's identity
    for exactly one ``action`` on one ``target``.

    ``session`` is anything with ``get_credentials()`` (a boto3.Session).
    Raises ValueError for an unknown action/target and RuntimeError when the
    session has no credentials. No network call is made.
    """
    from botocore.auth import SigV4QueryAuth  # lazy: client side only
    from botocore.awsrequest import AWSRequest

    header_value = f"v1:{action}:{target}:{secrets.token_hex(32)}"
    if action not in ACTIONS or not HEADER_RE.fullmatch(header_value):
        raise ValueError("unsupported breaker identity action or target")
    credentials = session.get_credentials()
    if credentials is None:
        raise RuntimeError("no AWS credentials available to sign the identity proof")
    frozen = credentials.get_frozen_credentials()
    request = AWSRequest(
        method="POST",
        url=f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
        headers={NONCE_HEADER: header_value},
    )
    SigV4QueryAuth(frozen, "sts", region, expires=PRESIGN_EXPIRES_SECONDS).add_auth(request)
    return request.url, header_value


def _reject(reason: str):
    # Reason code only: never the URL, header value or response body.
    logger.error("Breaker identity proof rejected: %s", reason)
    return None


def _shape_problem(url, header_value, expected_action, expected_target, region, now):
    """Return a reason code if the proof is malformed, else None (no network)."""
    if not isinstance(url, str) or not isinstance(header_value, str):
        return "MISSING_PROOF"
    if len(url) > 4096:
        return "URL_TOO_LONG"
    match = HEADER_RE.fullmatch(header_value)
    if not match:
        return "BAD_NONCE_HEADER"
    if match.group(1) != expected_action or match.group(2) != expected_target:
        return "NONCE_ACTION_OR_TARGET_MISMATCH"
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "BAD_URL"
    if parts.scheme != "https":
        return "NOT_HTTPS"
    if parts.netloc != f"sts.{region}.amazonaws.com":
        return "WRONG_HOST"
    if parts.path != "/":
        return "WRONG_PATH"
    if parts.fragment:
        return "FRAGMENT"
    params = urllib.parse.parse_qs(parts.query, keep_blank_values=True, strict_parsing=False)
    for key, expected in _REQUIRED_SINGLE_PARAMS.items():
        if params.get(key) != [expected]:
            return f"BAD_PARAM_{key}"
    for key in _ONE_EACH:
        if len(params.get(key, [])) != 1:
            return f"BAD_PARAM_{key}"
    signed = params["X-Amz-SignedHeaders"][0].split(";")
    if "host" not in signed or NONCE_HEADER not in signed:
        return "NONCE_NOT_SIGNED"
    try:
        expires = int(params["X-Amz-Expires"][0])
    except ValueError:
        return "BAD_EXPIRES"
    if not 1 <= expires <= MAX_EXPIRES_SECONDS:
        return "BAD_EXPIRES"
    try:
        signed_at = datetime.strptime(params["X-Amz-Date"][0], "%Y%m%dT%H%M%SZ").replace(
            tzinfo=timezone.utc)
    except ValueError:
        return "BAD_DATE"
    if abs((now - signed_at).total_seconds()) > MAX_CLOCK_SKEW_SECONDS:
        return "STALE_DATE"
    return None


def _call_sts(url, header_value, opener_factory):
    """POST the presigned request server-side; return the parsed principal or a reason."""
    # STS only accepts a botocore query-protocol presign on an empty-body POST.
    request = urllib.request.Request(url, data=b"", method="POST",
                                     headers={NONCE_HEADER: header_value})
    try:
        # Shape-checked https://sts.<own region>.amazonaws.com/ URL; the opener
        # is HTTPS-only with redirects disabled.
        with opener_factory().open(request, timeout=STS_TIMEOUT_SECONDS) as resp:  # nosec B310 # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
            status = getattr(resp, "status", 200)
            body = resp.read(65536)
    except Exception as e:  # noqa: BLE001 - any failure is "not verified"
        return None, f"STS_FETCH_FAILED:{type(e).__name__}"
    if status != 200:
        return None, "STS_NON_200"
    arn, user_id, account = _ARN_RE.search(body), _USER_ID_RE.search(body), _ACCOUNT_RE.search(body)
    if not (arn and user_id and account):
        return None, "STS_UNPARSABLE"
    role_match = _ROLE_USER_ID_RE.fullmatch(user_id.group(1).decode("utf-8", "replace"))
    if not role_match:
        return None, "NOT_A_ROLE_SESSION"
    return VerifiedPrincipal(
        arn=arn.group(1).decode("utf-8", "replace"),
        role_id=role_match.group(1),
        account=account.group(1).decode("ascii"),
        session=role_match.group(2),
    ), None


def nonce_event_id(header_value: str) -> str:
    return "nonce#" + hashlib.sha256(header_value.encode("utf-8")).hexdigest()


def verify_identity(url, header_value, expected_action: str, expected_target: str, *,
                    region: str, nonce_table_factory, opener_factory, now: datetime = None):
    """Return a VerifiedPrincipal, or None if the proof is not valid.

    Order: shape checks -> STS verification -> conditional nonce put. A
    reused nonce (ConditionalCheckFailed) and any other nonce-table error
    both return None (fail closed).
    """
    now = now or _now()
    problem = _shape_problem(url, header_value, expected_action, expected_target, region, now)
    if problem:
        return _reject(problem)
    principal, problem = _call_sts(url, header_value, opener_factory)
    if problem:
        return _reject(problem)
    try:
        nonce_table_factory().put_item(
            Item={
                "event_id": nonce_event_id(header_value),
                "event_type": "NONCE_CONSUMED",
                "timestamp": now.isoformat(),
                "action": expected_action,
                "principal_arn": principal.arn,
            },
            ConditionExpression="attribute_not_exists(event_id)",
        )
    except Exception as e:  # noqa: BLE001
        code = ""
        response = getattr(e, "response", None)
        if isinstance(response, dict):
            code = response.get("Error", {}).get("Code", "")
        if code == "ConditionalCheckFailedException":
            return _reject("NONCE_REUSED")
        return _reject(f"NONCE_STORE_FAILED:{type(e).__name__}")
    return principal
