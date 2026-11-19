"""
Console principal model and per-purpose AWS authority.

- Principal: the frozen, per-session identity of a signed-in operator.
- require_role / actor_fields: action-level authorization and audit stamping.
- governance_session(p, purpose): the ONLY way the console obtains AWS
  credentials. Ambient host credentials are never used for a live call.
  * local mode: the operator's own named profile for that purpose, after an
    offline shape check (no MFA prompt, no Identity Center, role_session_name
    set). A missing profile -> NoAwsAuthorityError (fail closed).
  * alb-cognito mode: the host assumes CONSOLE_ROLE_ARNS[purpose] with
    RoleSessionName = SourceIdentity = "cognito-<sub>"; never for "approver",
    and only for a principal whose console roles allow the purpose
    (ConsoleAuthzError otherwise, before any STS call). Purposes map strictly
    to roles: the operator-hosted role only for operator
    principals; an auditor-only principal writes its operator-audit records
    through the PutItem-only "audit_writer" role instead.

Ownership: console_auth owns authentication, this module owns the principal
shape and AWS authority, and each page owns the role check for its action.
"""
import dataclasses
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from governance_common.aws_profile_check import check_profile

logger = logging.getLogger(__name__)

REGION = os.environ.get("AWS_REGION", "us-east-1")

PURPOSES = ("operator", "approver", "auditor")
CONSOLE_ROLES = frozenset(PURPOSES)
# Hosted-only purpose: operator-audit writes for a principal without the
# operator role (fsi-console-audit-writer-hosted, PutItem on operator-audit).
AUDIT_WRITER = "audit_writer"
GOVERNANCE_PURPOSES = PURPOSES + (AUDIT_WRITER,)
# Purposes whose session is the operator-audit writer (ARN recorded).
AUDIT_WRITING_PURPOSES = frozenset({"operator", AUDIT_WRITER})
AUTH_MODES = frozenset({"local", "alb-cognito"})

# "approver: approve release (plus everything an operator can do)".
_IMPLIED_ROLES = {"approver": frozenset({"operator"})}

_SESSION_NAME_UNSAFE = re.compile(r"[^\w+=,.@-]")
_ASSUME_ROLE_SECONDS = 900
_ASSUMED_SESSION_REFRESH_MARGIN = 60

NOT_AUTHORIZED_MESSAGE = "Not authorized for this action"
NO_AUTHORITY_MESSAGE = "No AWS authority configured for this action"


class ConsoleAuthzError(Exception):
    """The signed-in principal lacks the console role for this action."""

    def __init__(self, message: str = NOT_AUTHORIZED_MESSAGE):
        super().__init__(message)


class NoAwsAuthorityError(Exception):
    """No AWS authority is configured for this principal and purpose (fail closed)."""

    def __init__(self, message: str = NO_AUTHORITY_MESSAGE):
        super().__init__(message)


@dataclass(frozen=True)
class Principal:
    principal_id: str        # "local:<operator_id>" | "cognito:<sub>"
    display_name: str        # <=64 printable chars
    auth_mode: str           # "local" | "alb-cognito"
    roles: frozenset         # subset of CONSOLE_ROLES
    authenticated_at: str    # ISO-8601 UTC
    aws_profiles: Mapping[str, str] = field(default_factory=dict)  # local mode only
    aws_principal_arn: str | None = None

    def __post_init__(self):
        if self.auth_mode not in AUTH_MODES:
            raise ValueError("unknown auth mode")
        roles = frozenset(self.roles)
        if not roles <= CONSOLE_ROLES:
            raise ValueError("unknown console role")
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "display_name", sanitize_display(self.display_name))
        object.__setattr__(self, "aws_profiles", MappingProxyType(dict(self.aws_profiles or {})))


def sanitize_display(value) -> str:
    text = "".join(ch for ch in str(value) if ch.isprintable())
    return text[:64]


def _state():
    """Session-state seam (tests replace it with a dict)."""
    import streamlit as st
    return st.session_state


def current_principal() -> Principal | None:
    p = _state().get("principal")
    return p if isinstance(p, Principal) else None


def set_principal(p: Principal) -> None:
    _state()["principal"] = p


def clear_principal() -> None:
    state = _state()
    for key in ("principal", "aws_principal_arn"):
        if key in state:
            del state[key]


def effective_roles(p: Principal) -> frozenset:
    roles = set(p.roles)
    for role in p.roles:
        roles |= _IMPLIED_ROLES.get(role, frozenset())
    return frozenset(roles)


def require_role(role: str) -> Principal:
    if role not in CONSOLE_ROLES:
        raise ValueError("unknown console role")
    p = current_principal()
    if p is None or role not in effective_roles(p):
        raise ConsoleAuthzError()
    return p


def actor_fields(p: Principal) -> dict:
    fields = {
        "actor_id": p.principal_id,
        "actor_display": p.display_name,
        "actor_auth_mode": p.auth_mode,
    }
    if p.aws_principal_arn:
        fields["actor_aws_arn"] = p.aws_principal_arn
    return fields


def resolve_aws_principal_arn(p: Principal, session) -> Principal:
    """Record the STS-verified ARN of `session` on the principal (once).

    Failures are logged at WARNING and leave the ARN unset; the next
    successful operator session retries."""
    if p.aws_principal_arn:
        return p
    stored = _state().get("principal")
    if (isinstance(stored, Principal) and stored.principal_id == p.principal_id
            and stored.aws_principal_arn):
        return stored  # a caller holding a stale copy must not trigger a second lookup
    try:
        arn = session.client("sts", region_name=REGION).get_caller_identity()["Arn"]
        if not isinstance(arn, str) or not arn.startswith("arn:aws"):
            raise ValueError("unexpected caller identity shape")
    except Exception as exc:
        logger.warning("Operator AWS identity lookup failed [%s]: %s",
                       uuid.uuid4(), type(exc).__name__)
        return p
    updated = dataclasses.replace(p, aws_principal_arn=arn)
    state = _state()
    if isinstance(state.get("principal"), Principal) and state["principal"].principal_id == p.principal_id:
        state["principal"] = updated
    state["aws_principal_arn"] = arn
    return updated


def _boto3_session(**kwargs):
    import boto3
    return boto3.Session(**kwargs)


def audit_purpose_for(p: Principal) -> str:
    """The purpose whose session writes p's operator-audit records."""
    return "operator" if "operator" in effective_roles(p) else AUDIT_WRITER


def _local_session(p: Principal, purpose: str):
    # Local mode: the audit writer is the person's own operator profile (no
    # console-role check; unchanged behavior). The strict map is hosted-only.
    profile = p.aws_profiles.get("operator" if purpose == AUDIT_WRITER else purpose)
    if not profile:
        raise NoAwsAuthorityError()
    # Offline shape check first: never prompts, never calls AWS.
    check_profile(profile, allow_mfa_prompt=False, allow_sso=False)
    return _boto3_session(profile_name=profile)


_ASSUMED_CACHE = {}
_ASSUMED_CACHE_LOCK = threading.Lock()


def cognito_session_name(principal_id: str) -> str:
    sub = principal_id.split(":", 1)[1] if ":" in principal_id else principal_id
    return "cognito-" + _SESSION_NAME_UNSAFE.sub("", sub)[:56]


# alb-cognito: the host-wide role for a purpose is assumed only for a
# principal holding a console role that may use it (role matrix above).
# Strict: the operator-hosted role only for operator principals
# (an approver reaches operator through effective_roles); every console role
# may write its own operator-audit records through the PutItem-only
# audit_writer role. A principal in no fsi-* group gets no hosted AWS
# authority at all.
_HOSTED_PURPOSE_ROLES = {
    "operator": frozenset({"operator"}),
    "auditor": frozenset({"auditor"}),
    AUDIT_WRITER: CONSOLE_ROLES,
}


def _hosted_session(p: Principal, purpose: str):
    if purpose == "approver":
        # Approvals never go through the console host (two-person release runs from the CLI).
        raise NoAwsAuthorityError()
    from app import console_auth  # deferred: console_auth imports this module
    role_arn = console_auth.console_role_arns().get(purpose)
    if not role_arn:
        raise NoAwsAuthorityError()
    if not effective_roles(p) & _HOSTED_PURPOSE_ROLES[purpose]:
        # Checked before any STS call or cache hit: an unauthorized principal
        # never causes the host to assume a role.
        raise ConsoleAuthzError()
    key = (p.principal_id, purpose)
    now = time.time()
    with _ASSUMED_CACHE_LOCK:
        cached = _ASSUMED_CACHE.get(key)
        if cached and cached[1] - _ASSUMED_SESSION_REFRESH_MARGIN > now:
            return cached[0]
    session_name = cognito_session_name(p.principal_id)
    host_sts = _boto3_session().client("sts", region_name=REGION)
    creds = host_sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        SourceIdentity=session_name,
        DurationSeconds=_ASSUME_ROLE_SECONDS,
    )["Credentials"]
    session = _boto3_session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=REGION,
    )
    expiration = creds.get("Expiration")
    expires_at = expiration.timestamp() if hasattr(expiration, "timestamp") else now + _ASSUME_ROLE_SECONDS
    with _ASSUMED_CACHE_LOCK:
        _ASSUMED_CACHE[key] = (session, expires_at)
    return session


def governance_session(p: Principal, purpose: str):
    """boto3.Session carrying `p`'s own AWS authority for `purpose`.

    Raises NoAwsAuthorityError (no mapping) or ProfileConfigError (bad local
    profile shape). The operator and audit_writer purposes also record the
    session's ARN on the principal the first time it succeeds."""
    if purpose not in GOVERNANCE_PURPOSES:
        raise ValueError("unknown governance purpose")
    if not isinstance(p, Principal):
        raise NoAwsAuthorityError()
    if p.auth_mode == "local":
        session = _local_session(p, purpose)
    else:
        session = _hosted_session(p, purpose)
    if purpose in AUDIT_WRITING_PURPOSES:
        resolve_aws_principal_arn(p, session)
    return session
