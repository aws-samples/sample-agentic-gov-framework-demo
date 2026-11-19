"""
Test: console authentication (per-operator sign-in and lockout). Unit cases
plus the dashboard AppTest cases (app/dashboard.py wired to console_auth).

- Operators file: 0600, owned, regular file (no symlink), strict schema.
- scrypt verification: unknown ids cost one scrypt call against a dummy
  record; non-ASCII passwords work.
- Per-identity throttle: no global lockout, known operators' backoff can't
  be evicted by flooding unknown ids, the unknown table stays bounded.
- alb-cognito: the token is verified by Cognito GetUser (mocked), not merely
  detected; scope pre-check, claim checks and the 60 s cache.
- console_identity: per-purpose AWS authority, fail closed, never prompts.
"""
import base64
import json
import logging
import os
import stat
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from app import console_auth, console_identity
from app.console_identity import ConsoleAuthzError, NoAwsAuthorityError, Principal
from governance_common.aws_profile_check import ProfileConfigError
from scripts import console_add_operator

PASSWORDS = {"alice": "correct horse battery", "bob": "bob-password-123", "carol": "pässwörd-ünïcode-✓"}


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    console_auth._reset_throttle_for_tests()
    console_auth._reset_alb_state_for_tests()
    console_auth._reset_role_arns_for_tests()
    console_identity._ASSUMED_CACHE.clear()
    state = {}
    monkeypatch.setattr(console_identity, "_state", lambda: state)
    yield state
    console_auth._reset_throttle_for_tests()


@pytest.fixture(scope="module")
def operator_entries():
    return [
        console_add_operator.build_entry("alice", "Alice", ["operator"], {"operator": "fsi-operator"},
                                         PASSWORDS["alice"]),
        console_add_operator.build_entry("bob", "Bob", ["approver"], {}, PASSWORDS["bob"]),
        console_add_operator.build_entry("carol", "Carol", ["auditor"], {}, PASSWORDS["carol"]),
    ]


@pytest.fixture
def operators_file(tmp_path, operator_entries, monkeypatch):
    path = tmp_path / "console" / "operators.json"
    console_add_operator.write_operators_file(str(path), operator_entries)
    monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(path))
    return path


@pytest.fixture
def operators(operators_file):
    return console_auth.load_operators()


@pytest.fixture
def scrypt_calls(monkeypatch):
    calls = []
    real = console_auth.hashlib.scrypt

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)
    monkeypatch.setattr(console_auth.hashlib, "scrypt", counting)
    return calls


@pytest.fixture
def fast_hash(monkeypatch):
    """Throttle-flood tests exercise the tables, not scrypt cost."""
    monkeypatch.setattr(console_auth, "hash_password", lambda pw, salt, **k: b"\x00" * 32)


# ─── Operators file ──────────────────────────────────────────────────────────

class TestOperatorsFile:
    def test_written_file_is_0600_in_0700_dir_and_loads(self, operators_file, operators):
        assert stat.S_IMODE(os.stat(operators_file).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(operators_file.parent).st_mode) == 0o700
        assert set(operators) == {"alice", "bob", "carol"}
        assert dict(operators["alice"].aws_profiles) == {"operator": "fsi-operator"}

    def test_permissions_too_open_refused(self, operators_file):
        os.chmod(operators_file, 0o644)
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_PERMISSIONS
        assert info.value.message == "operators file permissions too open"

    def test_symlink_refused(self, operators_file, tmp_path, monkeypatch):
        link = tmp_path / "link.json"
        link.symlink_to(operators_file)
        monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(link))
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_PERMISSIONS

    def test_other_owner_refused(self, operators_file, monkeypatch):
        other_uid = os.getuid() + 1
        monkeypatch.setattr(console_auth.os, "getuid", lambda: other_uid)
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_PERMISSIONS

    def test_missing_refused(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(tmp_path / "absent.json"))
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_MISSING

    def test_directory_refused(self, tmp_path, monkeypatch):
        d = tmp_path / "dir"
        d.mkdir(mode=0o700)
        monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(d))
        with pytest.raises(console_auth.ConsoleAuthConfigError):
            console_auth.load_operators()

    @pytest.mark.parametrize("mutate", [
        lambda d: d.update(extra=1),
        lambda d: d.update(version=2),
        lambda d: d["operators"][0].update(unknown="x"),
        lambda d: d["operators"][0].update(operator_id="Alice"),
        lambda d: d["operators"][0].update(roles=["root"]),
        lambda d: d["operators"][0].update(roles="operator"),
        lambda d: d["operators"][0]["scrypt"].update(n=1024),
        lambda d: d["operators"][0]["scrypt"].update(salt_b64="AAAA"),
        lambda d: d["operators"][0].update(aws_profiles={"admin": "x"}),
        lambda d: d["operators"][0].update(aws_profiles={"operator": "bad profile"}),
        lambda d: d["operators"].append(dict(d["operators"][0])),
        lambda d: d["operators"].extend(
            [dict(d["operators"][0], operator_id=f"op{i:03d}") for i in range(20)]),
        lambda d: d["operators"][0].update(display_name="x" * 65),
    ])
    def test_malformed_refused(self, operators_file, mutate):
        doc = json.loads(operators_file.read_text())
        mutate(doc)
        operators_file.write_text(json.dumps(doc))
        os.chmod(operators_file, 0o600)
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_MALFORMED

    def test_not_json_refused(self, operators_file):
        operators_file.write_text("{not json")
        with pytest.raises(console_auth.ConsoleAuthConfigError) as info:
            console_auth.load_operators()
        assert info.value.code == console_auth.OPERATORS_FILE_MALFORMED


class TestAddOperatorScript:
    def _run(self, monkeypatch, path, passwords, *extra):
        answers = iter(passwords)
        monkeypatch.setattr(console_add_operator.getpass, "getpass", lambda prompt="": next(answers))
        return console_add_operator.main(["--operator-id", "dave", "--display-name", "Dave",
                                          "--roles", "operator,auditor", "--file", str(path), *extra])

    def test_creates_file_and_credentials_verify(self, tmp_path, monkeypatch):
        path = tmp_path / "new" / "operators.json"
        pw = "dave-secret-pass"
        assert self._run(monkeypatch, path, [pw, pw], "--aws-profile", "operator=fsi-operator") == 0
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert pw not in path.read_text()
        ops = console_auth.load_operators(str(path))
        assert console_auth.verify_local_credentials("dave", pw, ops).principal.principal_id == "local:dave"

    def test_update_replaces_entry(self, operators_file, monkeypatch):
        pw = "dave-secret-pass"
        assert self._run(monkeypatch, operators_file, [pw, pw]) == 0
        assert self._run(monkeypatch, operators_file, ["another-pass-1", "another-pass-1"]) == 0
        ops = console_auth.load_operators(str(operators_file))
        assert set(ops) == {"alice", "bob", "carol", "dave"}
        assert console_auth.verify_local_credentials("dave", pw, ops).principal is None

    @pytest.mark.parametrize("passwords", [["a-long-password", "b-long-password"], ["short", "short"]])
    def test_bad_password_input_exits_2(self, tmp_path, monkeypatch, passwords):
        path = tmp_path / "operators.json"
        assert self._run(monkeypatch, path, passwords) == 2
        assert not path.exists()

    def test_refuses_to_update_a_too_open_file(self, operators_file, monkeypatch):
        os.chmod(operators_file, 0o644)
        before = operators_file.read_bytes()
        assert self._run(monkeypatch, operators_file, ["dave-secret-pass"] * 2) == 2
        assert operators_file.read_bytes() == before


# ─── Local credential verification ───────────────────────────────────────────

class TestLocalVerification:
    def test_correct_password(self, operators):
        result = console_auth.verify_local_credentials("alice", PASSWORDS["alice"], operators)
        p = result.principal
        assert p.principal_id == "local:alice" and p.auth_mode == "local"
        assert p.roles == frozenset({"operator"})
        assert dict(p.aws_profiles) == {"operator": "fsi-operator"}

    def test_wrong_password(self, operators, scrypt_calls):
        assert console_auth.verify_local_credentials("alice", "nope", operators).principal is None
        assert len(scrypt_calls) == 1

    def test_unknown_operator_still_runs_scrypt_once(self, operators, scrypt_calls):
        assert console_auth.verify_local_credentials("mallory", PASSWORDS["alice"], operators).principal is None
        assert len(scrypt_calls) == 1

    def test_non_ascii_password(self, operators):
        assert console_auth.verify_local_credentials("carol", PASSWORDS["carol"], operators).principal
        assert console_auth.verify_local_credentials("carol", "pässwörd", operators).principal is None

    @pytest.mark.parametrize("operator_id,password", [(None, None), (7, b"x"), ("", "")])
    def test_odd_inputs_fail_without_crashing(self, operators, operator_id, password):
        assert console_auth.verify_local_credentials(operator_id, password, operators).principal is None

    def test_dummy_record_never_authenticates(self, operators):
        assert console_auth.verify_local_credentials("<dummy>", "", operators).principal is None


class TestThrottle:
    def test_fourth_attempt_inside_backoff_refused_without_password_check(self, operators, scrypt_calls):
        for _ in range(3):
            assert console_auth.verify_local_credentials("alice", "bad", operators, now=1000.0).principal is None
        scrypt_calls.clear()
        result = console_auth.verify_local_credentials("alice", PASSWORDS["alice"], operators, now=1000.5)
        assert result.principal is None and result.retry_after > 0
        assert scrypt_calls == []

    def test_no_global_lockout(self, operators):
        for _ in range(5):
            console_auth.verify_local_credentials("alice", "bad", operators, now=1000.0)
        assert console_auth.verify_local_credentials("bob", PASSWORDS["bob"], operators, now=1000.1).principal

    def test_backoff_grows_and_caps_at_30s(self):
        for i in range(10):
            console_auth.record_failure("alice", True, now=0.0)
        assert console_auth.throttle_remaining("alice", True, now=0.0) == 30.0
        assert console_auth._backoff_seconds(3) == 1 and console_auth._backoff_seconds(4) == 2
        assert console_auth._backoff_seconds(2) == 0

    def test_success_resets_only_that_operator(self, operators):
        for name in ("alice", "bob"):
            for _ in range(3):
                console_auth.verify_local_credentials(name, "bad", operators, now=1000.0)
        assert console_auth.verify_local_credentials("alice", PASSWORDS["alice"], operators, now=1002.0).principal
        assert console_auth.throttle_remaining("alice", True, now=1002.0) == 0
        assert "alice" not in console_auth._KNOWN_THROTTLE
        assert console_auth._KNOWN_THROTTLE["bob"][0] == 3

    def test_unknown_table_bounded(self, operators, fast_hash):
        for i in range(2000):
            console_auth.verify_local_credentials(f"unknown{i}", "x", operators, now=1000.0)
        assert len(console_auth._UNKNOWN_THROTTLE) <= console_auth.UNKNOWN_THROTTLE_MAX

    def test_unknown_flood_cannot_reset_known_backoff(self, operators, fast_hash):
        for _ in range(3):
            console_auth.verify_local_credentials("alice", "bad", operators, now=1000.0)
        for i in range(2000):
            console_auth.verify_local_credentials(f"flood{i}", "x", operators, now=1000.0)
        result = console_auth.verify_local_credentials("alice", PASSWORDS["alice"], operators, now=1000.2)
        assert result.principal is None and result.retry_after > 0

    def test_new_session_does_not_reset_throttle(self, operators, _reset_state):
        for _ in range(3):
            console_auth.verify_local_credentials("alice", "bad", operators, now=1000.0)
        _reset_state.clear()  # a brand-new browser session has fresh session state
        assert console_auth.verify_local_credentials("alice", PASSWORDS["alice"], operators,
                                                     now=1000.1).retry_after > 0


# ─── Mode, loopback, legacy password ─────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [(None, None), ("", None), ("LOCAL", None), ("password", None),
                                            ("local", "local"), ("alb-cognito", "alb-cognito")])
def test_configured_mode(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv("CONSOLE_AUTH_MODE", raising=False)
    else:
        monkeypatch.setenv("CONSOLE_AUTH_MODE", value)
    assert console_auth.configured_mode() == expected


@pytest.mark.parametrize("address,ok", [("127.0.0.1", True), ("::1", True), ("localhost", True),
                                        ("0.0.0.0", False), ("", False), (None, False), ("10.0.0.5", False),  # nosec B104 -- asserts the loopback check REFUSES 0.0.0.0; nothing binds
                                        (" 127.0.0.1", False)])
def test_loopback_check(monkeypatch, address, ok):
    monkeypatch.setattr(console_auth, "_server_address", lambda: address)
    assert console_auth.server_address_is_loopback() is ok


def test_dashboard_password_ignored_with_one_warning(monkeypatch, caplog):
    monkeypatch.setenv("DASHBOARD_PASSWORD", "legacy")
    with caplog.at_level(logging.WARNING, logger="app.console_auth"):
        console_auth.warn_if_dashboard_password_set()
        console_auth.warn_if_dashboard_password_set()
    msgs = [r.getMessage() for r in caplog.records if "DASHBOARD_PASSWORD" in r.getMessage()]
    assert msgs == ["DASHBOARD_PASSWORD is ignored; set CONSOLE_AUTH_MODE"]


# ─── Sign-in rendering (fail closed) ─────────────────────────────────────────

_SIGN_IN_SCRIPT = """
import sys
sys.path.insert(0, {root!r})
from app import console_auth
console_auth.authenticate_or_render_sign_in()
import streamlit as st
st.button("governance action")
"""


def _apptest():
    from streamlit.testing.v1 import AppTest
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return AppTest.from_string(_SIGN_IN_SCRIPT.format(root=root), default_timeout=30)


def test_unset_mode_renders_only_not_configured(monkeypatch):
    monkeypatch.delenv("CONSOLE_AUTH_MODE", raising=False)
    monkeypatch.setenv("DASHBOARD_PASSWORD", "legacy")  # must not authenticate anything
    at = _apptest().run()
    assert not at.exception
    assert [e.value for e in at.error] == ["Console authentication is not configured"]
    assert len(at.button) == 0 and len(at.text_input) == 0


def test_local_mode_without_loopback_bind_refuses(monkeypatch, operators_file):
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    at = _apptest().run()  # server.address unset: Streamlit would bind every interface
    assert not at.exception
    assert "loopback" in at.error[0].value
    assert len(at.button) == 0 and len(at.text_input) == 0


# ─── alb-cognito ─────────────────────────────────────────────────────────────

ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEf123"
CLIENT_ID = "abc123clientid"
SUB = "3f2b8c1e-9a4d-4c2b-8f1e-0123456789ab"
CONFIG = console_auth.CognitoConfig(issuer=ISSUER, client_id=CLIENT_ID, region="us-east-1")


def _b64(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _token(**overrides):
    claims = {"iss": ISSUER, "client_id": CLIENT_ID, "token_use": "access", "sub": SUB, "exp": 2000.0,
              "scope": "openid aws.cognito.signin.user.admin", "cognito:groups": ["fsi-operator", "fsi-auditor"]}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return f"{_b64({'alg': 'RS256'})}.{_b64(claims)}.c2lnbmF0dXJl"


def _cognito(error=None):
    client = MagicMock()
    if error is not None:
        client.get_user.side_effect = error
    else:
        client.get_user.return_value = {"Username": "alice", "UserAttributes": [{"Name": "sub", "Value": SUB}]}
    return client


def _headers(token):
    return {"X-Amzn-Oidc-Accesstoken": token}


class TestAlbCognito:
    def test_valid_token_authenticates_and_maps_groups(self):
        client = _cognito()
        result = console_auth.verify_alb_token(_headers(_token()), CONFIG, client=client, now=1000.0)
        assert result.principal.principal_id == f"cognito:{SUB}"
        assert result.principal.auth_mode == "alb-cognito"
        assert result.principal.display_name == "alice"
        assert result.principal.roles == frozenset({"operator", "auditor"})
        client.get_user.assert_called_once()

    def test_no_header(self):
        client = _cognito()
        assert console_auth.verify_alb_token({}, CONFIG, client=client).principal is None
        client.get_user.assert_not_called()

    @pytest.mark.parametrize("value", ["anything", "a.b", "x" * 9000, "a.b.c.d", "!!.@@.##"])
    def test_arbitrary_header_value_never_authenticates(self, value):
        client = _cognito()
        assert console_auth.verify_alb_token(_headers(value), CONFIG, client=client).principal is None
        client.get_user.assert_not_called()

    def test_getuser_not_authorized(self):
        error = ClientError({"Error": {"Code": "NotAuthorizedException", "Message": "Invalid token"}}, "GetUser")
        result = console_auth.verify_alb_token(_headers(_token()), CONFIG, client=_cognito(error), now=1000.0)
        assert result.principal is None and not result.unavailable

    def test_cognito_unreachable_is_unavailable(self):
        error = EndpointConnectionError(endpoint_url="https://cognito-idp.us-east-1.amazonaws.com")
        result = console_auth.verify_alb_token(_headers(_token()), CONFIG, client=_cognito(error), now=1000.0)
        assert result.principal is None and result.unavailable and len(result.error_ref) == 8

    @pytest.mark.parametrize("overrides", [
        {"client_id": "otherclient"},
        {"iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Other"},
        {"token_use": "id"},
        {"exp": 999.0},
        {"exp": None},
        {"sub": "bad sub!"},
    ])
    def test_claim_mismatch(self, overrides):
        client = _cognito()
        assert console_auth.verify_alb_token(_headers(_token(**overrides)), CONFIG, client=client,
                                             now=1000.0).principal is None

    def test_subject_mismatch_with_getuser(self):
        client = _cognito()
        client.get_user.return_value = {"Username": "x", "UserAttributes": [{"Name": "sub", "Value": "other"}]}
        assert console_auth.verify_alb_token(_headers(_token()), CONFIG, client=client,
                                             now=1000.0).principal is None

    def test_missing_scope_logs_once_and_skips_getuser(self, caplog):
        client = _cognito()
        with caplog.at_level(logging.ERROR, logger="app.console_auth"):
            for _ in range(2):
                assert console_auth.verify_alb_token(_headers(_token(scope="openid")), CONFIG,
                                                     client=client, now=1000.0).principal is None
        client.get_user.assert_not_called()
        assert sum("scope misconfigured" in r.getMessage() for r in caplog.records) == 1

    def test_result_cached_for_60s(self):
        client = _cognito()
        token = _token()
        for now in (1000.0, 1059.0):
            assert console_auth.verify_alb_token(_headers(token), CONFIG, client=client, now=now).principal
        assert client.get_user.call_count == 1
        assert console_auth.verify_alb_token(_headers(token), CONFIG, client=client, now=1061.0).principal
        assert client.get_user.call_count == 2

    def test_request_headers_seam(self, monkeypatch):
        monkeypatch.setattr(console_auth, "_request_headers", lambda: _headers(_token()))
        client = _cognito()
        assert console_auth.verify_alb_token(console_auth._request_headers(), CONFIG, client=client,
                                             now=1000.0).principal

    def test_cognito_client_is_unsigned(self, monkeypatch):
        captured = {}
        monkeypatch.setattr(boto3, "client", lambda service, **kw: captured.update(service=service, **kw) or "c")
        assert console_auth._cognito_client("us-east-1") == "c"
        import botocore
        assert captured["service"] == "cognito-idp"
        assert captured["config"].signature_version is botocore.UNSIGNED

    def test_cognito_config_required(self, monkeypatch):
        for key in ("CONSOLE_COGNITO_ISSUER", "CONSOLE_COGNITO_CLIENT_ID", "CONSOLE_COGNITO_REGION"):
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(console_auth.ConsoleAuthConfigError):
            console_auth.load_cognito_config()
        monkeypatch.setenv("CONSOLE_COGNITO_ISSUER", ISSUER)
        monkeypatch.setenv("CONSOLE_COGNITO_CLIENT_ID", CLIENT_ID)
        monkeypatch.setenv("CONSOLE_COGNITO_REGION", "us-east-1")
        assert console_auth.load_cognito_config() == CONFIG
        monkeypatch.setenv("CONSOLE_COGNITO_ISSUER", "https://evil.example.com/pool")
        with pytest.raises(console_auth.ConsoleAuthConfigError):
            console_auth.load_cognito_config()


class TestConsoleRoleArns:
    def test_approver_key_refused(self, caplog):
        raw = json.dumps({"operator": "arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator-hosted",
                          "auditor": "arn:aws:iam::123456789012:role/fsi-compliance-reader",
                          "approver": "arn:aws:iam::123456789012:role/fsi-breaker/fsi-breaker-approver"})
        with caplog.at_level(logging.ERROR, logger="app.console_auth"):
            arns = console_auth.parse_console_role_arns(raw)
        assert set(arns) == {"operator", "auditor"}
        assert any("approver key is refused" in r.getMessage() for r in caplog.records)

    @pytest.mark.parametrize("raw", [None, "", "not json", "[]", json.dumps({"operator": "not-an-arn"}),
                                     json.dumps({"admin": "arn:aws:iam::123456789012:role/x"})])
    def test_invalid_mappings_disable_purposes(self, raw):
        assert console_auth.parse_console_role_arns(raw) == {}


# ─── console_identity ────────────────────────────────────────────────────────

def _principal(**kw):
    base = dict(principal_id="local:alice", display_name="Alice", auth_mode="local",
                roles=frozenset({"operator"}), authenticated_at="2026-01-01T00:00:00+00:00",
                aws_profiles={"operator": "good-role", "auditor": "mfa-prompt"})
    base.update(kw)
    return Principal(**base)


@pytest.fixture
def aws_config(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text("""
[profile src]
aws_access_key_id = AKIDEXAMPLE
aws_secret_access_key = secret
[profile good-role]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = src
role_session_name = alice
[profile mfa-prompt]
role_arn = arn:aws:iam::123456789012:role/fsi-compliance-reader
source_profile = src
role_session_name = alice
mfa_serial = arn:aws:iam::123456789012:mfa/alice
""", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))


class FakeSession:
    def __init__(self, arn="arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice", fail=False):
        self.sts = MagicMock()
        if fail:
            self.sts.get_caller_identity.side_effect = RuntimeError("boom")
        else:
            self.sts.get_caller_identity.return_value = {"Arn": arn}
        self.clients = []

    def client(self, service, **kw):
        self.clients.append((service, kw))
        return self.sts


class TestConsoleIdentity:
    def test_principal_is_frozen(self):
        p = _principal()
        with pytest.raises(Exception):
            p.roles = frozenset({"approver"})
        with pytest.raises(TypeError):
            p.aws_profiles["approver"] = "x"

    def test_require_role(self, _reset_state):
        with pytest.raises(ConsoleAuthzError):
            console_identity.require_role("operator")
        _reset_state["principal"] = _principal()
        assert console_identity.require_role("operator").principal_id == "local:alice"
        for role in ("approver", "auditor"):
            with pytest.raises(ConsoleAuthzError):
                console_identity.require_role(role)
        _reset_state["principal"] = _principal(roles=frozenset({"approver"}))
        assert console_identity.require_role("approver") and console_identity.require_role("operator")

    def test_actor_fields(self):
        assert console_identity.actor_fields(_principal()) == {
            "actor_id": "local:alice", "actor_display": "Alice", "actor_auth_mode": "local"}
        p = _principal(aws_principal_arn="arn:aws:sts::123456789012:assumed-role/r/alice")
        assert console_identity.actor_fields(p)["actor_aws_arn"].endswith("/alice")

    def test_missing_purpose_profile_is_no_authority_without_boto3(self, monkeypatch, aws_config):
        monkeypatch.setattr(console_identity, "_boto3_session",
                            lambda **k: (_ for _ in ()).throw(AssertionError("no session")))
        with pytest.raises(NoAwsAuthorityError) as info:
            console_identity.governance_session(_principal(), "approver")
        assert str(info.value) == "No AWS authority configured for this action"

    def test_mfa_prompt_profile_refused_without_boto3(self, monkeypatch, aws_config):
        monkeypatch.setattr(console_identity, "_boto3_session",
                            lambda **k: (_ for _ in ()).throw(AssertionError("no session")))
        monkeypatch.setattr("getpass.getpass", lambda *a, **k: (_ for _ in ()).throw(AssertionError("prompt")))
        with pytest.raises(ProfileConfigError) as info:
            console_identity.governance_session(_principal(), "auditor")
        assert info.value.code == "MFA_PROMPT"

    def test_operator_session_resolves_arn_once(self, monkeypatch, aws_config, _reset_state):
        session = FakeSession()
        made = []
        monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: made.append(k) or session)
        p = _principal()
        _reset_state["principal"] = p
        assert console_identity.governance_session(p, "operator") is session
        assert made == [{"profile_name": "good-role"}]
        assert _reset_state["principal"].aws_principal_arn.endswith("/alice")
        console_identity.governance_session(p, "operator")  # stale copy: no second lookup
        assert session.sts.get_caller_identity.call_count == 1
        assert session.clients[0] == ("sts", {"region_name": console_identity.REGION})

    def test_failed_arn_lookup_is_non_fatal_and_retried(self, monkeypatch, aws_config, _reset_state, caplog):
        sessions = [FakeSession(fail=True), FakeSession()]
        monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: sessions.pop(0))
        p = _principal()
        _reset_state["principal"] = p
        with caplog.at_level(logging.WARNING, logger="app.console_identity"):
            console_identity.governance_session(p, "operator")
        assert _reset_state["principal"].aws_principal_arn is None
        assert any("identity lookup failed" in r.getMessage() for r in caplog.records)
        console_identity.governance_session(p, "operator")
        assert _reset_state["principal"].aws_principal_arn

    def test_hosted_approver_never_assumed(self, monkeypatch):
        monkeypatch.setattr(console_identity, "_boto3_session",
                            lambda **k: (_ for _ in ()).throw(AssertionError("no session")))
        p = _principal(principal_id=f"cognito:{SUB}", auth_mode="alb-cognito", aws_profiles={})
        with pytest.raises(NoAwsAuthorityError):
            console_identity.governance_session(p, "approver")

    def test_hosted_operator_assumes_mapped_role_with_source_identity(self, monkeypatch, _reset_state):
        monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps(
            {"operator": "arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator-hosted"}))
        host_sts = MagicMock()
        host_sts.assume_role.return_value = {"Credentials": {
            "AccessKeyId": "AKID", "SecretAccessKey": "s", "SessionToken": "t"}}
        operator_session = FakeSession()
        calls = []

        def fake_session(**kw):
            calls.append(kw)
            if not kw:
                host = MagicMock()
                host.client.return_value = host_sts
                return host
            return operator_session
        monkeypatch.setattr(console_identity, "_boto3_session", fake_session)
        p = _principal(principal_id=f"cognito:{SUB}", auth_mode="alb-cognito", aws_profiles={})
        _reset_state["principal"] = p
        assert console_identity.governance_session(p, "operator") is operator_session
        kwargs = host_sts.assume_role.call_args.kwargs
        assert kwargs["RoleSessionName"] == kwargs["SourceIdentity"] == f"cognito-{SUB}"
        assert kwargs["DurationSeconds"] == 900
        console_identity.governance_session(p, "operator")
        assert host_sts.assume_role.call_count == 1  # cached
        with pytest.raises(NoAwsAuthorityError):
            console_identity.governance_session(p, "auditor")  # no mapping -> fail closed

    @pytest.mark.parametrize("roles,purpose,allowed", [
        ((), "operator", False),
        ((), "auditor", False),
        (("operator",), "auditor", False),
        (("approver",), "auditor", False),
        (("auditor",), "auditor", True),
        (("auditor",), "operator", False),  # strict map (audit_writer instead)
        (("approver",), "operator", True),  # approver implies operator
        (("operator",), "operator", True),
    ])
    def test_hosted_session_requires_a_console_role_for_the_purpose(self, monkeypatch, _reset_state,
                                                                    roles, purpose, allowed):
        monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps({
            "operator": "arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator-hosted",
            "auditor": "arn:aws:iam::123456789012:role/fsi-compliance-reader"}))
        monkeypatch.setattr(console_identity, "_ASSUMED_CACHE", {})
        host_sts = MagicMock()
        host_sts.assume_role.return_value = {"Credentials": {
            "AccessKeyId": "AKID", "SecretAccessKey": "s", "SessionToken": "t"}}
        def fake_session(**kw):
            if not kw:
                host = MagicMock()
                host.client.return_value = host_sts
                return host
            return FakeSession()
        monkeypatch.setattr(console_identity, "_boto3_session", fake_session)
        p = _principal(principal_id=f"cognito:{SUB}", auth_mode="alb-cognito", aws_profiles={},
                       roles=frozenset(roles))
        _reset_state["principal"] = p
        if allowed:
            console_identity.governance_session(p, purpose)
            assert host_sts.assume_role.call_count == 1
        else:
            with pytest.raises(ConsoleAuthzError):
                console_identity.governance_session(p, purpose)
            host_sts.assume_role.assert_not_called()

    def test_unknown_purpose(self):
        with pytest.raises(ValueError):
            console_identity.governance_session(_principal(), "admin")


# ═════════════════════════════════════════════════════════════════════════════
# Dashboard AppTest cases. The request-header seam is
# console_auth._request_headers; AppTest has no server, so server.address is
# supplied by monkeypatching streamlit.get_option.
# ═════════════════════════════════════════════════════════════════════════════

import time  # noqa: E402

import streamlit  # noqa: E402
from botocore.exceptions import NoCredentialsError  # noqa: E402

import app.invoke_live as invoke_live  # noqa: E402
from app import operator_audit  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD = os.path.join(ROOT, "app", "dashboard.py")
_REAL_STATE = console_identity._state
PIPELINE = "Run Pipeline (Happy Path)"
PAN_PAGE = "1.1 Data & Access Controls — PAN Filter"
AUDIT_PAGE = "2.1 Decision Explainability — Audit Trail"
CHALLENGER_PAGE = "3.1 Deliberative Challenge — Champion/Challenger"
CB_PAGE = "4.1 Drift Control — Circuit Breaker"
SIGN_IN_TITLE = "FSI Agentic Compliance — Sign in"
ARN = "arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice"
REQUEST_ID = "0" * 8 + "-0000-4000-8000-" + "0" * 12


def _refuse(*a, **k):
    raise AssertionError("no boto3 session/client may be constructed here")


class Dash:
    def __init__(self, monkeypatch, out_dir):
        self.monkeypatch, self.out_dir = monkeypatch, out_dir
        self.address = "127.0.0.1"

    def app(self):
        from streamlit.testing.v1 import AppTest
        return AppTest.from_file(DASHBOARD, default_timeout=60)

    def run(self, principal=None, page=None):
        at = self.app()
        if principal is not None:
            at.session_state["principal"] = principal
        at.run()
        assert not at.exception, at.exception
        if page is not None:
            at.sidebar.radio[0].set_value(page).run()
            assert not at.exception, at.exception
        return at

    def sign_in(self, operator_id, password):
        at = self.app().run()
        at.text_input[0].set_value(operator_id)
        at.text_input[1].set_value(password)
        at.button[0].click().run()
        assert not at.exception, at.exception
        return at

    def jsonl(self):
        path = self.out_dir / operator_audit.JSONL_NAME
        return [json.loads(l) for l in path.read_text().splitlines()] if path.exists() else []

    def forbid_boto3(self):
        for name in ("client", "resource", "Session"):
            self.monkeypatch.setattr(boto3, name, _refuse)
        self.monkeypatch.setattr(console_identity, "_boto3_session", _refuse)


@pytest.fixture
def dash(monkeypatch, tmp_path, operators_file):
    monkeypatch.setattr(console_identity, "_state", _REAL_STATE)  # real st.session_state
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    monkeypatch.setenv("MODE", "local")
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0")
    monkeypatch.delenv("DASHBOARD_PASSWORD", raising=False)
    out = tmp_path / "out"
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(out))
    d = Dash(monkeypatch, out)
    real_get_option = streamlit.get_option
    monkeypatch.setattr(streamlit, "get_option",
                        lambda key: d.address if key == "server.address" else real_get_option(key))
    return d


def _p(roles=("operator",), profiles=None, arn=None, **kw):
    return _principal(roles=frozenset(roles), aws_profiles=profiles or {}, aws_principal_arn=arn, **kw)


def _click(at, label):
    [b for b in at.button if b.label == label][0].click().run()
    assert not at.exception, at.exception
    return at


def _texts(at, *kinds):
    kinds = kinds or ("error", "warning", "info", "success", "markdown", "caption")
    return " ".join(str(e.value) for k in kinds for e in getattr(at, k))


def _assert_fail_closed(at, message):
    assert [e.value for e in at.error] == [message]
    assert [t.value for t in at.title] == [SIGN_IN_TITLE]
    assert len(at.sidebar.radio) == 0 and len(at.button) == 0 and len(at.text_input) == 0


# ─── Fail closed ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("mode", [None, "password", "LOCAL", "none"])
def test_dashboard_unset_or_unknown_mode_fails_closed(dash, monkeypatch, mode):
    if mode is None:
        monkeypatch.delenv("CONSOLE_AUTH_MODE")
    else:
        monkeypatch.setenv("CONSOLE_AUTH_MODE", mode)
    monkeypatch.setenv("DASHBOARD_PASSWORD", PASSWORDS["alice"])  # ignored, never authenticates
    _assert_fail_closed(dash.run(), "Console authentication is not configured")


@pytest.mark.parametrize("address", ["0.0.0.0", "10.0.0.5", "::", "", None])  # nosec B104 -- asserts the console refuses to render on 0.0.0.0; nothing binds
def test_dashboard_local_mode_refuses_non_loopback_before_rendering(dash, address):
    dash.address = address
    at = dash.run(principal=_p())  # even an existing session principal renders nothing
    assert "loopback" in at.error[0].value
    assert len(at.error) == 1 and len(at.sidebar.radio) == 0 and len(at.button) == 0


def test_dashboard_local_mode_reads_the_real_server_address_option(dash, monkeypatch):
    from streamlit import config
    monkeypatch.setattr(streamlit, "get_option", config.get_option)
    original = config.get_option("server.address")
    try:
        config.set_option("server.address", "0.0.0.0")  # nosec B104 -- sets a streamlit option in-process to assert the console refuses it; nothing binds
        assert "loopback" in dash.run().error[0].value
        config.set_option("server.address", "127.0.0.1")
        assert [b.label for b in dash.run().button] == ["Sign in"]
    finally:
        config.set_option("server.address", original)


@pytest.mark.parametrize("problem", ["mode_0644", "symlink", "missing"])
def test_dashboard_refuses_unsafe_operators_file(dash, operators_file, tmp_path, monkeypatch, problem):
    if problem == "mode_0644":
        os.chmod(operators_file, 0o644)
        expected = "operators file permissions too open"
    elif problem == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(operators_file)
        monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(link))
        expected = "operators file permissions too open"
    else:
        monkeypatch.setenv("CONSOLE_OPERATORS_FILE", str(tmp_path / "absent.json"))
        expected = console_auth.CONFIG_MESSAGES[console_auth.OPERATORS_FILE_MISSING]
    _assert_fail_closed(dash.run(), expected)


# ─── Sign-in ─────────────────────────────────────────────────────────────────

def test_dashboard_sign_in_reaches_the_pipeline_page(dash):
    at = dash.app().run()
    assert [t.label for t in at.text_input] == ["Operator id", "Password"]
    at = dash.sign_in("alice", PASSWORDS["alice"])
    assert at.session_state["principal"].principal_id == "local:alice"
    assert "Run Full Pipeline — Happy Path" in [t.value for t in at.title]
    assert len(at.sidebar.radio) == 1
    assert [(l["action"], l["actor_id"]) for l in dash.jsonl()] == [("SIGN_IN", "local:alice")]


def test_dashboard_wrong_password_and_unknown_id(dash, scrypt_calls):
    at = dash.sign_in("alice", "wrong-password")
    assert "principal" not in at.session_state
    assert "Incorrect operator id or password" in _texts(at, "error")
    scrypt_calls.clear()
    at = dash.sign_in("mallory", PASSWORDS["alice"])
    assert "principal" not in at.session_state and len(scrypt_calls) == 1
    assert "Incorrect operator id or password" in _texts(at, "error")
    lines = dash.jsonl()
    assert [l["action"] for l in lines] == ["SIGN_IN_FAILED", "SIGN_IN_FAILED"]
    assert [l["attempted_operator_id"] for l in lines] == ["alice", "mallory"]
    assert PASSWORDS["alice"] not in json.dumps(lines) and "wrong-password" not in json.dumps(lines)


def test_dashboard_throttle_message_after_three_failures(dash):
    for _ in range(3):
        dash.sign_in("alice", "wrong-password")
    at = dash.sign_in("alice", PASSWORDS["alice"])
    assert "principal" not in at.session_state
    assert "Try again in" in _texts(at, "error")
    assert dash.sign_in("bob", PASSWORDS["bob"]).session_state["principal"].principal_id == "local:bob"


def test_dashboard_non_ascii_password_signs_in(dash):
    assert dash.sign_in("carol", PASSWORDS["carol"]).session_state["principal"].principal_id == "local:carol"


def test_dashboard_sign_out_clears_the_principal(dash):
    at = dash.sign_in("alice", PASSWORDS["alice"])
    [b for b in at.sidebar.button if b.label == "Sign out"][0].click().run()
    assert "principal" not in at.session_state
    assert [t.value for t in at.title] == [SIGN_IN_TITLE]
    assert [l["action"] for l in dash.jsonl()] == ["SIGN_IN", "SIGN_OUT"]


# ─── AWS authority ───────────────────────────────────────────────────────────

@pytest.fixture
def profiles(tmp_path, monkeypatch):
    path = tmp_path / "aws-config"
    path.write_text("""
[profile src]
aws_access_key_id = AKIDEXAMPLE
aws_secret_access_key = secret
[profile good-role]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = src
role_session_name = alice
[profile no-rsn]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = src
[profile mfa-prompt]
role_arn = arn:aws:iam::123456789012:role/fsi-compliance-reader
source_profile = src
role_session_name = alice
mfa_serial = arn:aws:iam::123456789012:mfa/alice
[profile sso]
sso_session = example
sso_account_id = 123456789012
sso_role_name = Operator
[profile sso-start]
sso_start_url = https://sso.example.com/start
[profile role-with-sso-source]
role_arn = arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator
source_profile = sso-start
role_session_name = alice
""", encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(path))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)


class AwsFake:
    """A governance session: STS identity, an operator-audit table and
    per-service clients, all recorded."""

    def __init__(self, arn=ARN, fail_identity=False):
        self.sts = MagicMock()
        if fail_identity:
            self.sts.get_caller_identity.side_effect = RuntimeError("sts down")
        else:
            self.sts.get_caller_identity.return_value = {"Arn": arn, "Account": "123456789012"}
        self.table = MagicMock()
        self.clients = {}

    def client(self, service, **kw):
        if service == "sts":
            return self.sts
        return self.clients.setdefault(service, MagicMock(name=service))

    def resource(self, service, **kw):
        resource = MagicMock()
        resource.Table.return_value = self.table
        return resource


def test_missing_auditor_profile_renders_no_authority_without_boto3(dash, monkeypatch, profiles):
    monkeypatch.setenv("MODE", "live")
    dash.forbid_boto3()
    at = dash.run(principal=_p(profiles={"operator": "good-role"}, arn=ARN), page=AUDIT_PAGE)
    at = _click(at, "Load Live Audit Records")
    assert "No AWS authority configured for this action" in _texts(at, "error")


def test_mfa_prompt_profile_renders_mfa_message_without_prompt(dash, monkeypatch, profiles):
    monkeypatch.setenv("MODE", "live")
    dash.forbid_boto3()
    monkeypatch.setattr("getpass.getpass", _refuse)
    at = dash.run(principal=_p(profiles={"auditor": "mfa-prompt"}), page=AUDIT_PAGE)
    at = _click(at, "Load Live Audit Records")
    assert "This AWS profile prompts for MFA; create an MFA session first (see README)" in _texts(at, "error")


@pytest.mark.parametrize("profile,message", [
    ("no-rsn", "This AWS profile must set role_session_name to your IAM user name (see README)"),
    ("sso", "Identity Center profiles can't be used here"),
    ("sso-start", "Identity Center profiles can't be used here"),
    ("role-with-sso-source", "Identity Center profiles can't be used here"),
])
def test_profile_shape_refused_before_any_aws_call(dash, monkeypatch, profiles, profile, message):
    monkeypatch.setenv("MODE", "live")
    dash.forbid_boto3()
    monkeypatch.setattr(invoke_live, "_invoke_lambda", _refuse)
    at = dash.run(principal=_p(profiles={"operator": profile}), page=PAN_PAGE)
    at = [b for b in at.button if b.label.startswith("Run PAN Filter")][0].click().run()
    assert message in _texts(at, "error")


def test_well_formed_role_profile_passes_the_shape_check(dash, monkeypatch, profiles):
    fake = AwsFake()
    made = []
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: made.append(k) or fake)
    p = _p(profiles={"operator": "good-role"})
    monkeypatch.setattr(console_identity, "_state", lambda: {"principal": p})
    assert console_identity.governance_session(p, "operator") is fake
    assert made == [{"profile_name": "good-role"}]


def test_credential_error_renders_generic_refresh_message(dash, monkeypatch):
    monkeypatch.setenv("MODE", "live")

    def no_creds(p, purpose):
        raise NoCredentialsError()
    monkeypatch.setattr(console_identity, "governance_session", no_creds)
    at = dash.run(principal=_p(arn=ARN), page=PAN_PAGE)
    at = [b for b in at.button if b.label.startswith("Run PAN Filter")][0].click().run()
    errors = _texts(at, "error")
    assert "AWS session requires MFA or has expired; refresh credentials (ref " in errors
    assert "Unable to locate credentials" not in errors


def test_live_sign_in_stores_verified_arn_and_stamps_sign_in(dash, monkeypatch, profiles, operator_entries,
                                                            operators_file):
    monkeypatch.setenv("MODE", "live")
    console_add_operator.write_operators_file(str(operators_file), [
        console_add_operator.build_entry("alice", "Alice", ["operator"], {"operator": "good-role"},
                                         PASSWORDS["alice"])])
    fake = AwsFake()
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: fake)
    at = dash.sign_in("alice", PASSWORDS["alice"])
    assert at.session_state["principal"].aws_principal_arn == ARN
    item = fake.table.put_item.call_args.kwargs["Item"]
    assert item["action"] == "SIGN_IN" and item["actor_aws_arn"] == ARN
    assert [l["action"] for l in dash.jsonl()] == ["SIGN_IN"]


def test_live_sign_in_identity_failure_signs_in_but_disables_live_actions(dash, monkeypatch, profiles,
                                                                          operators_file):
    monkeypatch.setenv("MODE", "live")
    console_add_operator.write_operators_file(str(operators_file), [
        console_add_operator.build_entry("alice", "Alice", ["operator"], {"operator": "good-role"},
                                         PASSWORDS["alice"])])
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: AwsFake(fail_identity=True))
    monkeypatch.setattr(invoke_live, "_invoke_lambda", _refuse)
    at = dash.sign_in("alice", PASSWORDS["alice"])
    assert at.session_state["principal"].principal_id == "local:alice"
    assert at.session_state["principal"].aws_principal_arn is None
    at.sidebar.radio[0].set_value(PAN_PAGE).run()
    at = [b for b in at.button if b.label.startswith("Run PAN Filter")][0].click().run()
    assert "No AWS authority configured for this action" in _texts(at, "error")


def test_failed_live_sign_in_constructs_no_session_and_writes_one_jsonl_line(dash, monkeypatch):
    monkeypatch.setenv("MODE", "live")
    dash.forbid_boto3()
    at = dash.sign_in("alice", "wrong-password")
    assert "principal" not in at.session_state
    assert [l["action"] for l in dash.jsonl()] == ["SIGN_IN_FAILED"]


def test_live_sign_in_audit_put_failure_still_signs_in(dash, monkeypatch, profiles, operators_file, caplog):
    monkeypatch.setenv("MODE", "live")
    console_add_operator.write_operators_file(str(operators_file), [
        console_add_operator.build_entry("alice", "Alice", ["operator"], {"operator": "good-role"},
                                         PASSWORDS["alice"])])
    fake = AwsFake()
    fake.table.put_item.side_effect = RuntimeError("AccessDenied")
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: fake)
    with caplog.at_level(logging.ERROR, logger="app.console_auth"):
        at = dash.sign_in("alice", PASSWORDS["alice"])
    assert at.session_state["principal"].principal_id == "local:alice"
    assert sum("Operator audit SIGN_IN (live) failed" in r.getMessage() for r in caplog.records) == 1
    assert [l["action"] for l in dash.jsonl()] == ["SIGN_IN"]


# ─── In-process compliance (run_compliance_local) ────────────────────────────

def test_run_compliance_local_uses_the_given_session_only(monkeypatch, cached_detection):
    monkeypatch.setattr(boto3, "client", _refuse)
    session = AwsFake()
    seen = {}
    import lambdas.compliance_agent.handler as ch

    def fake_handler(event, context=None, *, bedrock_client=None):
        seen.update(event=event, client=bedrock_client)
        return {"clusters_assessed": []}
    monkeypatch.setattr(ch, "handler", fake_handler)
    invoke_live.run_compliance_local(cached_detection, session=session)
    assert seen["client"] is session.clients["bedrock-runtime"]
    assert seen["event"] == {"mode": "live", "detection_output": cached_detection}


def test_run_compliance_local_without_session_is_no_authority(monkeypatch, cached_detection):
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, _refuse)
    with pytest.raises(NoAwsAuthorityError):
        invoke_live.run_compliance_local(cached_detection, session=None)
    with pytest.raises(NoAwsAuthorityError):
        invoke_live.run_compliance_local({}, session=None)  # `is None`, not truthiness
    cached = invoke_live.run_compliance_local()
    assert cached["clusters_assessed"]


def test_compliance_handler_bedrock_client_is_keyword_only():
    import inspect
    import lambdas.compliance_agent.handler as ch
    param = inspect.signature(ch.handler).parameters["bedrock_client"]
    assert param.kind is inspect.Parameter.KEYWORD_ONLY and param.default is None


# ─── MODE=local without AWS authority ────────────────────────────────────────

def test_local_pipeline_without_authority_completes_on_cached_compliance(dash, monkeypatch):
    dash.forbid_boto3()
    at = dash.run(principal=_p(), page=PIPELINE)
    at = _click(at, "Run Full Pipeline")
    text = _texts(at)
    assert "No AWS authority configured — showing cached compliance output (Bedrock not called)" in text
    assert "Executor complete" in text
    assert at.session_state["pipeline_executor"] is not None
    requested = [l for l in dash.jsonl() if l["action"] == "PIPELINE_RUN" and l["phase"] == "REQUESTED"]
    assert [l["details"]["compliance_source"] for l in requested] == ["cached"]


def test_local_dispute_breach_without_authority_does_nothing(dash, monkeypatch):
    dash.forbid_boto3()
    calls = []
    real = invoke_live.run_compliance_local
    monkeypatch.setattr(invoke_live, "run_compliance_local",
                        lambda *a, **k: calls.append((a, k)) or real(*a, **k))
    at = dash.run(principal=_p(), page=CB_PAGE)
    at = _click(at, "Dispute Rate Breach\n(3 clusters, 2 disputes)")
    assert "Requires an operator AWS profile (see README)" in _texts(at, "warning")
    assert [c for c in calls if c[0] or c[1].get("session")] == []
    assert [l for l in dash.jsonl() if l["action"] == "DRIFT_INJECTION"] == []


def test_local_challenger_page_still_renders_cached_result(dash):
    dash.forbid_boto3()
    at = _click(dash.run(principal=_p(), page=CHALLENGER_PAGE), "Run Challenger Analysis")
    assert "Champion vs Challenger Results" in [s.value for s in at.subheader]


def test_local_challenger_never_calls_live_agents(dash, monkeypatch):
    dash.forbid_boto3()
    monkeypatch.setattr(invoke_live, "run_detection_live", _refuse)
    monkeypatch.setattr(invoke_live, "run_compliance_live", _refuse)
    at = _click(dash.run(principal=_p(), page=CHALLENGER_PAGE), "Run Challenger Analysis")
    assert "Champion vs Challenger Results" in [s.value for s in at.subheader]
    assert not [l for l in dash.jsonl() if l["action"] == "PIPELINE_RUN"]


# ─── Lazy actor_aws_arn (MODE=local) ─────────────────────────────────────────

def _cached_compliance_spy(monkeypatch, calls):
    real = invoke_live.run_compliance_local

    def spy(detection_output=None, *, session=None):
        calls.append(session)
        return real()  # cached output; no Bedrock in tests
    monkeypatch.setattr(invoke_live, "run_compliance_local", spy)


def test_lazy_arn_resolved_once_and_stamped_on_later_records(dash, monkeypatch, profiles):
    fake = AwsFake()
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: fake)
    calls = []
    _cached_compliance_spy(monkeypatch, calls)
    at = dash.run(principal=_p(profiles={"operator": "good-role"}), page=PIPELINE)
    at = _click(at, "Run Full Pipeline")
    at = _click(at, "Run Full Pipeline")
    assert calls == [fake, fake]  # the operator's own session reached the in-process agent
    assert fake.sts.get_caller_identity.call_count == 1
    runs = [l for l in dash.jsonl() if l["action"] == "PIPELINE_RUN"]
    assert [l["phase"] for l in runs] == ["REQUESTED", "COMPLETED"] * 2
    assert all(l["actor_aws_arn"] == ARN for l in runs)
    assert {l["details"].get("compliance_source") for l in runs if l["phase"] == "REQUESTED"} == {"bedrock"}


def test_lazy_arn_failure_is_non_fatal_and_retried(dash, monkeypatch, profiles, caplog):
    fake = AwsFake(fail_identity=True)
    monkeypatch.setattr(console_identity, "_boto3_session", lambda **k: fake)
    _cached_compliance_spy(monkeypatch, [])
    at = dash.run(principal=_p(profiles={"operator": "good-role"}), page=PIPELINE)
    with caplog.at_level(logging.WARNING, logger="app.console_identity"):
        at = _click(at, "Run Full Pipeline")
    assert sum("identity lookup failed" in r.getMessage() for r in caplog.records) == 1
    runs = [l for l in dash.jsonl() if l["action"] == "PIPELINE_RUN"]
    assert [l["phase"] for l in runs] == ["REQUESTED", "COMPLETED"]
    assert all("actor_aws_arn" not in l for l in runs)
    _click(at, "Run Full Pipeline")
    assert fake.sts.get_caller_identity.call_count == 2  # retried on the next operator session


# ─── Makefile listeners ──────────────────────────────────────────────────────

def test_makefile_binds_loopback_only_and_never_alb_mode():
    import re
    with open(os.path.join(ROOT, "Makefile"), encoding="utf-8") as f:
        text = f.read()
    addresses = re.findall(r"--server\.address[ =](\S+)", text)
    assert addresses and set(addresses) == {"127.0.0.1"}
    assert "CONSOLE_AUTH_MODE=alb-cognito" not in text and "alb-cognito" not in text
    for target in ("ui", "ui-live"):
        recipe = text.split(f"\n{target}:")[1].split("\n\n")[0]
        assert "CONSOLE_AUTH_MODE=local" in recipe and "--server.address 127.0.0.1" in recipe
    assert "\nconsole-operator:" in text and "scripts/console_add_operator.py" in text


# ─── alb-cognito at the dashboard ────────────────────────────────────────────

@pytest.fixture
def alb(dash, monkeypatch):
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "alb-cognito")
    monkeypatch.setenv("CONSOLE_COGNITO_ISSUER", ISSUER)
    monkeypatch.setenv("CONSOLE_COGNITO_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("CONSOLE_COGNITO_REGION", "us-east-1")
    client = _cognito()
    monkeypatch.setattr(console_auth, "_cognito_client", lambda region: client)
    dash.cognito = client
    return dash


def test_alb_dashboard_arbitrary_header_never_authenticates(alb, monkeypatch):
    monkeypatch.setattr(console_auth, "_request_headers", lambda: _headers("anything-at-all"))
    at = alb.run()
    _assert_fail_closed(at, console_auth.ALB_SIGN_IN_REQUIRED_MESSAGE)
    alb.cognito.get_user.assert_not_called()


def test_alb_dashboard_approver_role_arn_refused_and_no_approve_control(alb, monkeypatch, caplog):
    monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps({
        "operator": "arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator-hosted",
        "approver": "arn:aws:iam::123456789012:role/fsi-breaker/fsi-breaker-approver"}))
    monkeypatch.setattr(console_auth, "_request_headers",
                        lambda: _headers(_token(exp=time.time() + 600,
                                                **{"cognito:groups": ["fsi-operator", "fsi-approver"]})))
    with caplog.at_level(logging.ERROR, logger="app.console_auth"):
        at = alb.run(page=CB_PAGE)
    assert at.session_state["principal"].principal_id == f"cognito:{SUB}"
    assert any("approver key is refused" in r.getMessage() for r in caplog.records)
    assert "Approve release" not in [b.label for b in at.button]
    assert "make release-approve REQUEST_ID=" in _texts(at, "info")


@pytest.mark.parametrize("groups", [[], ["fsi-operator"]])
def test_alb_live_audit_read_refused_without_auditor_group_and_no_assume_role(alb, monkeypatch, groups):
    monkeypatch.setenv("MODE", "live")
    monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps({
        "operator": "arn:aws:iam::123456789012:role/fsi-console/fsi-console-operator-hosted",
        "auditor": "arn:aws:iam::123456789012:role/fsi-compliance-reader"}))
    monkeypatch.setattr(console_identity, "_ASSUMED_CACHE", {})
    host_sts = MagicMock()
    host_sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "AKID", "SecretAccessKey": "s", "SessionToken": "t"}}
    def fake_session(**kw):
        if kw:
            return AwsFake()
        host = MagicMock()
        host.client.return_value = host_sts
        return host
    monkeypatch.setattr(console_identity, "_boto3_session", fake_session)
    reads = []
    monkeypatch.setattr(invoke_live, "read_audit_trail_live", lambda *a, **k: reads.append(k) or {})
    monkeypatch.setattr(console_auth, "_request_headers",
                        lambda: _headers(_token(exp=time.time() + 600, **{"cognito:groups": groups})))
    at = alb.run(page=AUDIT_PAGE)
    assert at.session_state["principal"].roles == frozenset(
        console_auth.GROUP_ROLE_MAP[g] for g in groups)
    at = _click(at, "Load Live Audit Records")
    assert "Not authorized for this action" in _texts(at, "error")
    assert reads == []
    assert [c for c in host_sts.assume_role.call_args_list
            if c.kwargs["RoleArn"].endswith("/fsi-compliance-reader")] == []
    if not groups:
        host_sts.assume_role.assert_not_called()


# ─── Role gating ─────────────────────────────────────────────────────────────

def test_operator_cannot_approve_release(dash, monkeypatch):
    called = []
    monkeypatch.setattr(invoke_live, "approve_release_local", lambda *a, **k: called.append(a))
    monkeypatch.setattr(invoke_live, "approve_release_live", lambda *a, **k: called.append(a))
    at = dash.run(principal=_p(roles=("operator",)), page=CB_PAGE)
    at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    at = _click(at, "Approve release")
    assert "Not authorized for this action" in _texts(at, "error")
    assert called == []
    assert [l for l in dash.jsonl() if l["action"] == "RELEASE_APPROVE"] == []


def test_auditor_cannot_run_the_pipeline(dash, monkeypatch):
    monkeypatch.setattr(invoke_live, "run_detection_local", _refuse)
    at = _click(dash.run(principal=_p(roles=("auditor",)), page=PIPELINE), "Run Full Pipeline")
    assert "Not authorized for this action" in _texts(at, "error")
    assert dash.jsonl() == []


@pytest.mark.parametrize("roles,visible", [(("operator",), False), (("auditor",), True)])
def test_audit_page_shows_narratives_only_to_auditors(dash, roles, visible):
    dash.out_dir.mkdir(parents=True, exist_ok=True)
    (dash.out_dir / "compliance_result.json").write_text(json.dumps(
        {"compliance_id": "c1", "clusters_assessed": [{"cluster_id": "x", "sar_narrative": "NARRATIVE-XYZ"}]}))
    at = _click(dash.run(principal=_p(roles=roles), page=AUDIT_PAGE), "Load Local Audit Records")
    rendered = json.dumps([json.loads(j.value) for j in at.json], ensure_ascii=False)
    assert ("NARRATIVE-XYZ" in rendered) is visible
    assert (invoke_live.REDACTED_NARRATIVE in rendered) is not visible
