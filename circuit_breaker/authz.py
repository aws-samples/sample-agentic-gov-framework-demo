"""
Role-based authorization for human breaker actions.

Who may trip, request a release or approve one is decided by IAM role
membership (deploy- and IdP-controlled), not by Lambda environment variables.
The rules are code constants. A rule that matches a role NAME only counts
once ``iam:GetRole`` confirms the session belongs to the role that currently
holds that name (RoleId) and that the role lives on the rule's IAM path, so a
look-alike role (wrong path, or deleted and recreated) never classifies.

Imported as top-level ``authz`` by circuit_breaker/handler.py (Lambda layout)
and as ``circuit_breaker.authz`` by scripts/break_glass_release.py.
"""
import logging
import re
import time
import uuid
from collections import namedtuple

logger = logging.getLogger(__name__)

TRIP = "trip"
REQUEST_RELEASE = "request_release"
APPROVE_RELEASE = "approve_release"

CHANNEL_IAM_USER = "iam-user"
CHANNEL_SSO = "sso"
CHANNEL_CONSOLE = "console"
CHANNEL_BREAK_GLASS = "break-glass"

BREAKER_ROLE_PATH = "/fsi-breaker/"
CONSOLE_ROLE_PATH = "/fsi-console/"
# Identity Center-provisioned roles, optionally under a regional segment.
SSO_PATH_RE = re.compile(r"/aws-reserved/sso\.amazonaws\.com/([a-z0-9-]+/)?")

BREAK_GLASS_ROLE_NAMES = frozenset({"fsi-breaker-break-glass"})

ASSUMED_ROLE_ARN_RE = re.compile(
    r"^arn:aws:sts::(\d{12}):assumed-role/([\w+=,.@-]{1,64})/([\w+=,.@-]{1,64})$")

Rule = namedtuple("Rule", "name prefix path channel capabilities")
Authz = namedtuple("Authz", "capabilities individual channel role_name")

# name: exact role name (prefix=False) or name prefix (prefix=True);
# path: exact IAM path string, or SSO_PATH_RE (fullmatch).
RULES = (
    Rule("fsi-breaker-operator", False, BREAKER_ROLE_PATH, CHANNEL_IAM_USER,
         frozenset({TRIP, REQUEST_RELEASE})),
    Rule("fsi-console-operator", False, CONSOLE_ROLE_PATH, CHANNEL_IAM_USER,
         frozenset({TRIP, REQUEST_RELEASE})),
    # Host-minted (alb-cognito) sessions can only make the system MORE
    # restrictive: a compromised console host can never release a hold.
    Rule("fsi-console-operator-hosted", False, CONSOLE_ROLE_PATH, CHANNEL_CONSOLE,
         frozenset({TRIP})),
    Rule("fsi-breaker-approver", False, BREAKER_ROLE_PATH, CHANNEL_IAM_USER,
         frozenset({TRIP, REQUEST_RELEASE, APPROVE_RELEASE})),
    Rule("AWSReservedSSO_FsiBreakerOperator_", True, SSO_PATH_RE, CHANNEL_SSO,
         frozenset({TRIP, REQUEST_RELEASE})),
    Rule("AWSReservedSSO_FsiBreakerApprover_", True, SSO_PATH_RE, CHANNEL_SSO,
         frozenset({TRIP, REQUEST_RELEASE, APPROVE_RELEASE})),
    # Used only by scripts/break_glass_release.py (classified locally).
    Rule("fsi-breaker-break-glass", False, BREAKER_ROLE_PATH, CHANNEL_BREAK_GLASS, frozenset()),
)

ROLE_CACHE_TTL_SECONDS = 300
_role_binding_cache = {}  # (role_name, role_id) -> monotonic expiry; successes only


def clear_cache() -> None:
    _role_binding_cache.clear()


def _rule_for(role_name: str):
    for rule in RULES:
        if rule.prefix:
            if role_name.startswith(rule.name) and len(role_name) > len(rule.name):
                return rule
        elif role_name == rule.name:
            return rule
    return None


def _path_ok(rule: Rule, path) -> bool:
    if not isinstance(path, str):
        return False
    if isinstance(rule.path, str):
        return path == rule.path
    return rule.path.fullmatch(path) is not None


def _role_bound(rule: Rule, role_name: str, role_id: str, iam_client, clock) -> bool:
    key = (role_name, role_id)
    expiry = _role_binding_cache.get(key)
    if expiry is not None and expiry > clock():
        return True
    try:
        role = iam_client.get_role(RoleName=role_name)["Role"]
    except Exception as e:  # noqa: BLE001 - NoSuchEntity, AccessDenied, throttling: fail closed
        error_id = str(uuid.uuid4())
        logger.error("Breaker authz: iam:GetRole failed for %s [%s] (%s)",
                     role_name, error_id, type(e).__name__)
        return False
    if role.get("RoleId") != role_id:
        logger.warning("Breaker authz: RoleId mismatch for role %s", role_name)
        return False
    if not _path_ok(rule, role.get("Path")):
        logger.warning("Breaker authz: role %s is not on the required IAM path", role_name)
        return False
    _role_binding_cache[key] = clock() + ROLE_CACHE_TTL_SECONDS
    return True


def classify(vp, account_id: str, iam_client, *, clock=time.monotonic):
    """Return Authz(capabilities, individual, channel, role_name) for a
    VerifiedPrincipal, or None if it is not an authorized breaker identity."""
    if vp is None:
        return None
    match = ASSUMED_ROLE_ARN_RE.fullmatch(vp.arn or "")
    if not match:
        logger.warning("Breaker authz: caller is not an assumed-role session: %s", vp.arn)
        return None
    arn_account, role_name, session_name = match.groups()
    if arn_account != account_id or vp.account != account_id:
        logger.warning("Breaker authz: caller is from another account: %s", vp.arn)
        return None
    if not vp.role_id or vp.session != session_name:
        logger.warning("Breaker authz: UserId does not match the session ARN: %s", vp.arn)
        return None
    rule = _rule_for(role_name)
    if rule is None:
        logger.warning("Breaker authz: role is not a breaker role: %s", vp.arn)
        return None
    if not _role_bound(rule, role_name, vp.role_id, iam_client, clock):
        return None
    return Authz(capabilities=rule.capabilities, individual=session_name.lower(),
                 channel=rule.channel, role_name=role_name)
