"""
Test: governance_common.aws_profile_check.

Every error code against a temp AWS_CONFIG_FILE; the allow_mfa_prompt /
allow_sso switches; static-key profiles pass; the source_profile walk is
bounded (a 6-hop chain or a loop fails rather than spinning). No network
and no credential resolution: boto3 is never reached.
"""
import boto3
import pytest

from governance_common import aws_profile_check as apc
from governance_common.aws_profile_check import ProfileConfigError, check_profile

CONFIG = """
[profile static]
aws_access_key_id = AKIDEXAMPLE
aws_secret_access_key = secret

[profile alice-mfa]
aws_access_key_id = AKIDEXAMPLE
aws_secret_access_key = secret
aws_session_token = token

[profile good-role]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = alice-mfa
role_session_name = alice

[profile no-session-name]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = alice-mfa

[profile bad-session-name]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = alice-mfa
role_session_name = has space

[profile mfa-prompt]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = alice-mfa
role_session_name = alice
mfa_serial = arn:aws:iam::123456789012:mfa/alice

[profile sso-direct]
sso_session = example
sso_account_id = 123456789012
sso_role_name = FsiBreakerApprover

[profile sso-start-url]
sso_start_url = https://sso.example.org/start

[profile role-from-sso]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = sso-direct
role_session_name = alice

[profile role-missing-source]
role_arn = arn:aws:iam::123456789012:role/x
source_profile = does-not-exist
role_session_name = alice

[profile loop-a]
role_arn = arn:aws:iam::123456789012:role/x
source_profile = loop-b
role_session_name = alice

[profile loop-b]
role_arn = arn:aws:iam::123456789012:role/x
source_profile = loop-a
role_session_name = alice

[profile hop0]
role_arn = arn:aws:iam::123456789012:role/x
source_profile = hop1
role_session_name = alice
"""
# hop1..hop5 chain onward to hop6 (six source_profile hops from hop0).
for _i in range(1, 7):
    CONFIG += (f"\n[profile hop{_i}]\nrole_arn = arn:aws:iam::123456789012:role/x\n"
               f"role_session_name = alice\n" + (f"source_profile = hop{_i + 1}\n" if _i < 6 else
                                                "aws_access_key_id = AKID\naws_secret_access_key = s\n"))
CONFIG += """
[profile five-hops]
role_arn = arn:aws:iam::123456789012:role/x
source_profile = hop2
role_session_name = alice
"""


@pytest.fixture(autouse=True)
def aws_config(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials-absent"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    def refuse(*a, **k):
        raise AssertionError("boto3 must not be reached")
    monkeypatch.setattr(boto3, "client", refuse)
    monkeypatch.setattr(boto3, "Session", refuse)
    return path


def _code(profile, **kwargs):
    kwargs.setdefault("allow_mfa_prompt", False)
    kwargs.setdefault("allow_sso", False)
    with pytest.raises(ProfileConfigError) as info:
        check_profile(profile, **kwargs)
    assert info.value.message == apc.MESSAGES[info.value.code]
    return info.value.code


def test_static_keys_profile_passes():
    check_profile("static", allow_mfa_prompt=False, allow_sso=False)


def test_well_formed_role_profile_passes():
    check_profile("good-role", allow_mfa_prompt=False, allow_sso=False)


def test_unknown_profile():
    assert _code("nope") == apc.PROFILE_NOT_FOUND
    assert _code("") == apc.PROFILE_NOT_FOUND


def test_mfa_prompt_refused_unless_allowed():
    assert _code("mfa-prompt") == apc.MFA_PROMPT
    check_profile("mfa-prompt", allow_mfa_prompt=True, allow_sso=False)


@pytest.mark.parametrize("profile", ["sso-direct", "sso-start-url", "role-from-sso"])
def test_sso_refused_unless_allowed(profile):
    assert _code(profile) == apc.SSO_NOT_SUPPORTED
    check_profile(profile, allow_mfa_prompt=False, allow_sso=True)


def test_role_session_name_missing():
    assert _code("no-session-name") == apc.ROLE_SESSION_NAME_MISSING
    assert _code("no-session-name", allow_mfa_prompt=True, allow_sso=True) == apc.ROLE_SESSION_NAME_MISSING


def test_role_session_name_invalid():
    assert _code("bad-session-name") == apc.ROLE_SESSION_NAME_INVALID


def test_missing_source_profile():
    assert _code("role-missing-source") == apc.PROFILE_NOT_FOUND


def test_source_profile_loop_terminates():
    assert _code("loop-a") == apc.PROFILE_NOT_FOUND


def test_six_hop_chain_stops_at_five():
    assert _code("hop0") == apc.PROFILE_NOT_FOUND


def test_five_hop_chain_passes():
    check_profile("five-hops", allow_mfa_prompt=False, allow_sso=False)


def test_messages_never_include_profile_contents():
    for code in apc.MESSAGES:
        assert "AKID" not in apc.MESSAGES[code] and "arn:" not in apc.MESSAGES[code]
