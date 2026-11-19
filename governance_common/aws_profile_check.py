"""
Offline shape check of a named AWS CLI profile.

Reads botocore's scoped config only: no network, no credential resolution,
never prompts. Raises ProfileConfigError(code) with a fixed message per code,
so callers can render or print it without echoing profile contents.

Callers:
- console governance_session (local mode): allow_mfa_prompt=False, allow_sso=False
- breaker CLI scripts: allow_mfa_prompt=True, allow_sso=True
- sign_registry.py --kms, compliance_gate.py --sign: allow_mfa_prompt=True, allow_sso=False
"""
import re

PROFILE_NOT_FOUND = "PROFILE_NOT_FOUND"
MFA_PROMPT = "MFA_PROMPT"
SSO_NOT_SUPPORTED = "SSO_NOT_SUPPORTED"
ROLE_SESSION_NAME_MISSING = "ROLE_SESSION_NAME_MISSING"
ROLE_SESSION_NAME_INVALID = "ROLE_SESSION_NAME_INVALID"

MESSAGES = {
    PROFILE_NOT_FOUND: "The configured AWS profile was not found (see README)",
    MFA_PROMPT: "This AWS profile prompts for MFA; create an MFA session first (see README)",
    SSO_NOT_SUPPORTED: "Identity Center profiles can't be used here; use an IAM role profile (see README)",
    ROLE_SESSION_NAME_MISSING: "This AWS profile must set role_session_name to your IAM user name (see README)",
    ROLE_SESSION_NAME_INVALID: "This AWS profile's role_session_name is not a valid IAM session name (see README)",
}

SSO_KEYS = ("sso_session", "sso_start_url", "sso_account_id", "sso_role_name")
ROLE_SESSION_NAME_RE = re.compile(r"[\w+=,.@-]{2,64}")
MAX_SOURCE_PROFILE_HOPS = 5


class ProfileConfigError(Exception):
    def __init__(self, code: str):
        super().__init__(MESSAGES[code])
        self.code = code
        self.message = MESSAGES[code]


def _has_sso(config: dict) -> bool:
    return any(config.get(key) for key in SSO_KEYS)


def check_profile(profile_name: str, *, allow_mfa_prompt: bool, allow_sso: bool) -> None:
    import botocore.exceptions
    import botocore.session

    if not isinstance(profile_name, str) or not profile_name:
        raise ProfileConfigError(PROFILE_NOT_FOUND)
    session = botocore.session.Session(profile=profile_name)
    try:
        config = session.get_scoped_config()
    except botocore.exceptions.ProfileNotFound:
        raise ProfileConfigError(PROFILE_NOT_FOUND) from None

    if config.get("mfa_serial") and not allow_mfa_prompt:
        raise ProfileConfigError(MFA_PROMPT)
    if _has_sso(config) and not allow_sso:
        raise ProfileConfigError(SSO_NOT_SUPPORTED)
    session_name = config.get("role_session_name")
    if config.get("role_arn") and not session_name:
        raise ProfileConfigError(ROLE_SESSION_NAME_MISSING)
    if session_name and not ROLE_SESSION_NAME_RE.fullmatch(str(session_name)):
        raise ProfileConfigError(ROLE_SESSION_NAME_INVALID)

    if allow_sso:
        return
    # An SSO source under a role profile leaves ${aws:username} undefined, so
    # the SSO rule also applies along the source_profile chain (bounded walk).
    profiles = session.full_config.get("profiles", {})
    source = config.get("source_profile")
    hops = 0
    while source:
        hops += 1
        if hops > MAX_SOURCE_PROFILE_HOPS or source not in profiles:
            raise ProfileConfigError(PROFILE_NOT_FOUND)
        source_config = profiles[source]
        if _has_sso(source_config):
            raise ProfileConfigError(SSO_NOT_SUPPORTED)
        source = source_config.get("source_profile")
