"""
Breaker identity proof (identity_proof.py) and role classification (authz.py).

presign_identity uses real botocore with static fake credentials (no network).
verify_identity runs with the HTTPS opener and the nonce table mocked; the
opener's call count proves which proofs never reach STS.
"""
import io
import os
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from botocore.credentials import Credentials

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import ACCOUNT, ROLES, FakeBreakerAws, cb, client_error, principal  # noqa: E402

ip = cb.identity_proof
authz = cb.authz
REGION = cb.REGION
OPERATOR_ID = ROLES["fsi-breaker-operator"][0]


class _Session:
    def get_credentials(self):
        return Credentials("AKIDEXAMPLE", "secret")


def _presign(action="trip", target="trip"):
    return ip.presign_identity(_Session(), REGION, action, target)


def _sts_body(role="fsi-breaker-operator", session="alice", role_id=OPERATOR_ID, account=ACCOUNT):
    return (f"<GetCallerIdentityResponse><GetCallerIdentityResult>"
            f"<Arn>arn:aws:sts::{account}:assumed-role/{role}/{session}</Arn>"
            f"<UserId>{role_id}:{session}</UserId><Account>{account}</Account>"
            f"</GetCallerIdentityResult></GetCallerIdentityResponse>").encode()


class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    def __init__(self, body=None, exc=None, status=200):
        self.body, self.exc, self.status, self.requests = body, exc, status, []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        if self.exc:
            raise self.exc
        resp = _Resp(self.body)
        resp.status = self.status
        return resp


def _verify(url, header, opener, table=None, action="trip", target="trip", now=None):
    table = table if table is not None else MagicMock()
    return ip.verify_identity(url, header, action, target, region=REGION,
                              nonce_table_factory=lambda: table, opener_factory=lambda: opener,
                              now=now)


def _with_params(url, drop=(), append=(), **replace):
    parts = urllib.parse.urlsplit(url)
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
             if k not in drop]
    pairs = [(k, replace.get(k, v)) for k, v in pairs] + list(append)
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(pairs)))


# ─── presign_identity ────────────────────────────────────────────────────────

def test_presign_signs_the_nonce_header_and_expires_in_60():
    url, header = _presign("approve_release", "0" * 8 + "-0000-4000-8000-" + "0" * 12)
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert params["X-Amz-SignedHeaders"] == ["host;x-fsi-breaker-nonce"]
    assert params["X-Amz-Expires"] == ["60"]
    assert params["Action"] == ["GetCallerIdentity"] and params["Version"] == ["2011-06-15"]
    assert urllib.parse.urlsplit(url).netloc == f"sts.{REGION}.amazonaws.com"
    assert ip.HEADER_RE.fullmatch(header) and header.startswith("v1:approve_release:")
    assert _presign()[1] != _presign()[1]  # fresh nonce each time


def test_presign_rejects_unknown_action_and_missing_credentials():
    with pytest.raises(ValueError):
        ip.presign_identity(_Session(), REGION, "re_enable", "x")
    with pytest.raises(ValueError):
        ip.presign_identity(_Session(), REGION, "trip", "bad target/with slash")

    class _NoCreds:
        def get_credentials(self):
            return None
    with pytest.raises(RuntimeError):
        ip.presign_identity(_NoCreds(), REGION, "trip", "trip")


# ─── verify_identity: shape checks never reach STS ───────────────────────────

def _bad_proofs():
    url, header = _presign()
    other_region = "us-west-2" if REGION != "us-west-2" else "us-east-1"
    host = f"sts.{REGION}.amazonaws.com"
    return [
        ("http", url.replace("https://", "http://", 1), header),
        ("other region", url.replace(host, f"sts.{other_region}.amazonaws.com"), header),
        ("evil", url.replace(host, "evil.com"), header),
        ("suffix", url.replace(host, f"{host}.evil.com"), header),
        ("path", url.replace(f"{host}/", f"{host}/x"), header),
        ("action", _with_params(url, Action="AssumeRole"), header),
        ("dup action", _with_params(url, append=[("Action", "GetCallerIdentity")]), header),
        ("expires 3600", _with_params(url, **{"X-Amz-Expires": "3600"}), header),
        ("old date", _with_params(url, **{"X-Amz-Date": (datetime.now(timezone.utc) - timedelta(minutes=10))
                                         .strftime("%Y%m%dT%H%M%SZ")}), header),
        ("unsigned nonce", _with_params(url, **{"X-Amz-SignedHeaders": "host"}), header),
        ("wrong action", url, header.replace("v1:trip:", "v1:request_release:")),
        ("wrong target", url, header.replace(":trip:", ":other:")),
        ("malformed nonce", url, header[:-1] + "Z"),
        ("missing", None, header),
        ("missing header", url, None),
    ]


@pytest.mark.parametrize("name,url,header", _bad_proofs(), ids=[p[0] for p in _bad_proofs()])
def test_malformed_proof_rejected_without_sts_fetch(name, url, header):
    opener, table = _Opener(_sts_body()), MagicMock()
    assert _verify(url, header, opener, table) is None
    assert opener.requests == []
    table.put_item.assert_not_called()


def test_valid_proof_posts_to_sts_with_header_and_consumes_nonce():
    url, header = _presign()
    opener, table = _Opener(_sts_body()), MagicMock()
    vp = _verify(url, header, opener, table)
    assert vp == ip.VerifiedPrincipal(
        arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/fsi-breaker-operator/alice",
        role_id=OPERATOR_ID, account=ACCOUNT, session="alice")
    ((request, timeout),) = opener.requests
    assert request.full_url == url and request.get_method() == "POST" and request.data == b""
    assert request.get_header("X-fsi-breaker-nonce") == header and timeout == 5
    kwargs = table.put_item.call_args.kwargs
    assert kwargs["ConditionExpression"] == "attribute_not_exists(event_id)"
    item = kwargs["Item"]
    assert item["event_id"] == ip.nonce_event_id(header) and item["event_id"].startswith("nonce#")
    assert item["event_type"] == "NONCE_CONSUMED" and item["action"] == "trip"
    assert item["principal_arn"] == vp.arn and header not in str(item)


@pytest.mark.parametrize("opener", [_Opener(exc=OSError("down")), _Opener(_sts_body(), status=403),
                                    _Opener(b"<html>nope</html>"),
                                    _Opener(_sts_body(role_id="AIDAUSER00000000001"))])
def test_sts_failure_returns_none_and_writes_nothing(opener):
    url, header = _presign()
    table = MagicMock()
    assert _verify(url, header, opener, table) is None
    assert len(opener.requests) == 1
    table.put_item.assert_not_called()


def test_nonce_table_error_fails_closed():
    url, header = _presign()
    table = MagicMock()
    table.put_item.side_effect = client_error("ProvisionedThroughputExceededException")
    assert _verify(url, header, _Opener(_sts_body()), table) is None


def test_reused_nonce_rejected_and_action_runs_once(monkeypatch):
    """End to end through handler(): both calls pass STS, only one wins the
    conditional nonce put, so the trip happens exactly once."""
    aws = FakeBreakerAws().install(monkeypatch, stub_identity=False)
    opener = _Opener(_sts_body())
    monkeypatch.setattr(cb, "_sts_https_opener", lambda: opener)
    url, header = _presign()
    event = {"action": "invoke", "trigger_reason_code": "OPERATOR_PRECAUTION",
             "caller_identity_presigned_url": url, "caller_identity_nonce": header}
    assert cb.handler(dict(event))["status"] == "GOVERNANCE_HOLD"
    second = cb.handler(dict(event))
    assert second["http_status"] == 403
    assert len(opener.requests) == 2
    assert [e for e in aws.log if e[0] == "attach"] == [("attach", r) for r in cb.AGENT_ROLES]
    assert len(aws.gov.by_type("NONCE_CONSUMED")) == 1


def test_no_write_before_identity_through_handler(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, stub_identity=False)
    monkeypatch.setattr(cb, "_sts_https_opener", lambda: _Opener(exc=OSError("down")))
    url, header = _presign("request_release", "active-hold")
    aws.record_hold()
    result = cb.handler({"action": "request_release", "caller_identity_presigned_url": url,
                         "caller_identity_nonce": header})
    assert result["http_status"] == 403
    assert not [e for e in aws.log if e[0] == "put"]


# ─── authz.classify ──────────────────────────────────────────────────────────

class _Iam:
    def __init__(self, role=None, error=None):
        self.role, self.error, self.calls = role, error, 0

    def get_role(self, RoleName):
        self.calls += 1
        if self.error:
            raise self.error
        return {"Role": dict(self.role, RoleName=RoleName)}


@pytest.fixture(autouse=True)
def _clear_authz_cache():
    authz.clear_cache()
    yield
    authz.clear_cache()


def _classify(role, session, path, role_id=None, iam=None):
    vp = principal(role, session, role_id=role_id or "AROATESTROLE000000001")
    iam = iam or _Iam({"RoleId": "AROATESTROLE000000001", "Path": path})
    return authz.classify(vp, ACCOUNT, iam)


def test_operator_capabilities_and_channel():
    result = _classify("fsi-breaker-operator", "Alice", "/fsi-breaker/")
    assert result.capabilities == {"trip", "request_release"}
    assert result.channel == "iam-user" and result.individual == "alice"


def test_sso_approver_includes_approve():
    result = _classify("AWSReservedSSO_FsiBreakerApprover_abc123", "bob@example.com",
                       "/aws-reserved/sso.amazonaws.com/")
    assert "approve_release" in result.capabilities and result.channel == "sso"


@pytest.mark.parametrize("path", ["/aws-reserved/sso.amazonaws.com/", "/aws-reserved/sso.amazonaws.com/eu-west-1/"])
def test_sso_path_regex_accepts(path):
    assert _classify("AWSReservedSSO_FsiBreakerApprover_x", "bob", path) is not None


@pytest.mark.parametrize("path", ["/aws-reserved/sso.amazonaws.com/a/b/", "/aws-reserved/sso.amazonaws.com.evil/",
                                  "/aws-reserved/sso.amazonaws.com", "/attacker/"])
def test_sso_path_regex_rejects(path):
    assert _classify("AWSReservedSSO_FsiBreakerApprover_x", "bob", path) is None


def test_right_name_wrong_path_is_rejected():
    assert _classify("fsi-breaker-approver", "bob", "/") is None


def test_role_id_mismatch_is_rejected():
    iam = _Iam({"RoleId": "AROADIFFERENTROLE0001", "Path": "/fsi-breaker/"})
    assert _classify("fsi-breaker-approver", "bob", "/fsi-breaker/", iam=iam) is None


@pytest.mark.parametrize("code", ["NoSuchEntity", "AccessDenied", "Throttling"])
def test_get_role_error_is_rejected(code):
    iam = _Iam(error=client_error(code, "GetRole"))
    assert _classify("fsi-breaker-approver", "bob", "/fsi-breaker/", iam=iam) is None


def test_hosted_console_session_can_only_trip():
    result = _classify("fsi-console-operator-hosted", "cognito-abc", "/fsi-console/")
    assert result.capabilities == {"trip"} and result.channel == "console"


@pytest.mark.parametrize("arn", [
    f"arn:aws:iam::{ACCOUNT}:user/alice",
    f"arn:aws:sts::999999999999:assumed-role/fsi-breaker-operator/alice",
    f"arn:aws:sts::{ACCOUNT}:assumed-role/some-other-role/alice",
    f"arn:aws:iam::{ACCOUNT}:root",
])
def test_non_breaker_identities_are_rejected(arn):
    vp = ip.VerifiedPrincipal(arn=arn, role_id="AROATESTROLE000000001", account=arn.split(":")[4],
                              session="alice")
    iam = _Iam({"RoleId": "AROATESTROLE000000001", "Path": "/fsi-breaker/"})
    assert authz.classify(vp, ACCOUNT, iam) is None


def test_session_must_match_user_id():
    vp = principal("fsi-breaker-operator", "alice")._replace(session="mallory", role_id="AROATESTROLE000000001")
    assert authz.classify(vp, ACCOUNT, _Iam({"RoleId": "AROATESTROLE000000001", "Path": "/fsi-breaker/"})) is None


def test_successful_binding_is_cached_failures_are_not():
    iam = _Iam({"RoleId": "AROATESTROLE000000001", "Path": "/fsi-breaker/"})
    for _ in range(3):
        assert _classify("fsi-breaker-operator", "alice", "/fsi-breaker/", iam=iam)
    assert iam.calls == 1
    bad = _Iam({"RoleId": "AROATESTROLE000000001", "Path": "/"})
    for _ in range(2):
        assert _classify("fsi-breaker-approver", "alice", "/", iam=bad) is None
    assert bad.calls == 2


def test_break_glass_role_has_no_in_band_capabilities():
    result = _classify("fsi-breaker-break-glass", "alice", "/fsi-breaker/")
    assert result.capabilities == frozenset() and result.role_name in authz.BREAK_GLASS_ROLE_NAMES
