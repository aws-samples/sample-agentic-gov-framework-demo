"""
Safe console error rendering.

The console never renders exception text: boto3 messages carry account ids,
role/session names, table names and regions. report() logs the full
exception server-side under an error id and returns a fixed message with a
short reference; classify() exposes only a coarse class derived from the
error code, never the message.
"""
import logging
import uuid

logger = logging.getLogger(__name__)

# AgentCore drops the runtime body on non-2xx responses, so the console can
# only map the status (it can't tell DUPLICATE_DECISION from
# PROVENANCE_CHECK_FAILED, both 409). 403 keeps the SOX audit-record
# corroboration path in app/invoke_live.py and is not mapped here.
AGENTCORE_STATUS_MESSAGES = {
    400: "The request was rejected as malformed",
    409: "This detection was already decided or isn't recorded",
    411: "Request rejected (length required)",
    413: "Request too large",
    429: "Agent busy; try again shortly",
    503: "Temporarily unavailable",
    500: "Agent error",
}
DEFAULT_AGENTCORE_MESSAGE = "Agent error"

CREDENTIALS_MESSAGE = "AWS session requires MFA or has expired; refresh credentials"

_CREDENTIAL_ERROR_CLASSES = frozenset({
    "NoCredentialsError", "ProfileNotFound", "TokenRetrievalError", "SSOTokenLoadError",
    "PartialCredentialsError", "CredentialRetrievalError", "UnauthorizedSSOTokenError",
})
_CREDENTIAL_ERROR_CODES = frozenset({"ExpiredToken", "ExpiredTokenException"})
_UNAVAILABLE_CLASSES = frozenset({
    "EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError", "ConnectionClosedError",
})


def _error_code(exc) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code", "")
        return code if isinstance(code, str) else ""
    return ""


def report(exc: BaseException, context: str) -> tuple:
    """Log `exc` with an error id and return (operator_message, error_id).

    `context` must be a fixed, caller-authored string (e.g. "Audit read")."""
    error_id = str(uuid.uuid4())
    logger.error("%s failed [%s]", context, error_id, exc_info=exc)
    return f"{context} failed (ref {error_id[:8]}). Details are in the console log.", error_id


def classify(exc: BaseException) -> str:
    """Coarse class from the error code: AccessDenied / Throttling / NotFound /
    Unavailable / Error. Never derived from the message."""
    code = _error_code(exc)
    lowered = code.lower()
    if code:
        if "accessdenied" in lowered or "unauthorized" in lowered or "notauthorized" in lowered \
                or code == "AuthorizationError":
            return "AccessDenied"
        if "throttl" in lowered or "toomanyrequests" in lowered or code in (
                "ProvisionedThroughputExceededException", "RequestLimitExceeded", "LimitExceededException"):
            return "Throttling"
        if "notfound" in lowered or code in ("NoSuchEntity", "NoSuchKey", "NoSuchBucket"):
            return "NotFound"
        if code in ("ServiceUnavailable", "ServiceUnavailableException", "InternalFailure",
                    "InternalServerError", "InternalServerException"):
            return "Unavailable"
        return "Error"
    if type(exc).__name__ in _UNAVAILABLE_CLASSES:
        return "Unavailable"
    if isinstance(exc, PermissionError):   # local file read refused by the OS
        return "AccessDenied"
    return "Error"


def is_credential_error(exc: BaseException) -> bool:
    return type(exc).__name__ in _CREDENTIAL_ERROR_CLASSES or _error_code(exc) in _CREDENTIAL_ERROR_CODES


def report_credentials(exc: BaseException, context: str) -> tuple:
    """Like report(), with the fixed refresh-credentials message."""
    _, error_id = report(exc, context)
    return f"{CREDENTIALS_MESSAGE} (ref {error_id[:8]})", error_id


def agentcore_status_message(status) -> str:
    return AGENTCORE_STATUS_MESSAGES.get(status, DEFAULT_AGENTCORE_MESSAGE)
