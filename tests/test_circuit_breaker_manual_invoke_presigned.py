"""
Test: Circuit Breaker — manual action=="invoke" (fsi-circuit-breaker-human)
resolves the caller ONLY from a presigned sts:GetCallerIdentity proof that the
breaker POSTs to STS itself, and records the verified
principal in the GOVERNANCE_HOLD audit event.

The STS fetch is mocked at circuit_breaker.handler._sts_https_opener; nothing
reaches AWS. urllib.request.urlopen is patched to fail so any regression back
to the default (all-schemes, redirect-following) opener is caught.
"""
import email.message
import io
import os
import sys
import urllib.error
import urllib.request
import urllib.response
from unittest.mock import MagicMock

import pytest
from botocore.credentials import Credentials

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import circuit_breaker.handler as cb  # noqa: E402
from _breaker_fixtures import ACCOUNT, ROLES, FakeBreakerAws  # noqa: E402

TRUSTED = f"arn:aws:sts::{ACCOUNT}:assumed-role/fsi-breaker-operator/alice"
OTHER = f"arn:aws:sts::{ACCOUNT}:assumed-role/someone-else/mallory"
_USER_IDS = {TRUSTED: ROLES["fsi-breaker-operator"][0] + ":alice",
             OTHER: "AROASOMEONEELSE000001:mallory"}


class _Session:
    def get_credentials(self):
        return Credentials("AKIDEXAMPLE", "secret")


def _good_proof():
    return cb.identity_proof.presign_identity(_Session(), cb.REGION, "trip", "trip")


def _no_identity_ctx():
    ctx = MagicMock()
    ctx.identity = None
    return ctx


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeOpener:
    """Stands in for the HTTPS-only opener; records (request, timeout)."""

    def __init__(self, seen, body=None, exc=None):
        self.seen, self.body, self.exc = seen, body, exc

    def open(self, request, timeout=None):
        self.seen.append((request, timeout))
        if self.exc is not None:
            raise self.exc
        return _Resp(self.body)


def _forbid_urlopen(monkeypatch):
    def _no_urlopen(*a, **k):
        raise AssertionError("urlopen must not be used for the presigned STS fetch")
    monkeypatch.setattr(cb.urllib.request, "urlopen", _no_urlopen)


def _sts_returns(monkeypatch, arn):
    """Mock the server-side STS fetch; record the request it was given."""
    seen = []
    body = (f"<GetCallerIdentityResponse><Arn>{arn}</Arn><UserId>{_USER_IDS[arn]}</UserId>"
            f"<Account>{ACCOUNT}</Account></GetCallerIdentityResponse>").encode()
    monkeypatch.setattr(cb, "_sts_https_opener", lambda: _FakeOpener(seen, body=body))
    _forbid_urlopen(monkeypatch)
    return seen


@pytest.fixture
def live(monkeypatch):
    FakeBreakerAws().install(monkeypatch, entry="human", stub_identity=False)
    trips = []
    monkeypatch.setattr(
        cb, "invoke_circuit_breaker",
        lambda reason, mode="local", triggered_by=None, **k: trips.append(
            {"reason": reason, "mode": mode, "triggered_by": triggered_by})
        or {"status": "GOVERNANCE_HOLD", "http_status": 503, "triggered_by": triggered_by},
    )
    return trips


def _invoke(proof="good", code="OPERATOR_PRECAUTION", ctx=None):
    event = {"action": "invoke", "trigger_reason_code": code}
    if proof == "good":
        proof = _good_proof()
    if proof is not None:
        event["caller_identity_presigned_url"], event["caller_identity_nonce"] = proof
    return cb.handler(event, ctx or _no_identity_ctx()), event


def test_valid_presigned_url_and_authorized_role_trips(monkeypatch, live):
    seen = _sts_returns(monkeypatch, TRUSTED)
    result, event = _invoke()
    assert result["status"] == "GOVERNANCE_HOLD"
    assert live == [{"reason": cb.KNOWN_MANUAL_TRIGGER_REASONS["OPERATOR_PRECAUTION"],
                     "mode": "live", "triggered_by": TRUSTED}]
    # Server-side fetch: empty-body POST to the given URL, signed nonce header sent.
    assert len(seen) == 1
    request, timeout = seen[0]
    assert request.full_url == event["caller_identity_presigned_url"]
    assert request.get_method() == "POST" and request.data == b""
    assert request.get_header("X-fsi-breaker-nonce") == event["caller_identity_nonce"]
    assert timeout == 5


def test_unauthorized_role_rejected(monkeypatch, live):
    _sts_returns(monkeypatch, OTHER)
    result, _ = _invoke()
    assert result["status"] == "REJECTED" and result["http_status"] == 403
    assert live == []


@pytest.mark.parametrize("proof", [
    None,
    ("", ""),
    ("https://evil.example.com/?Action=GetCallerIdentity", "v1:trip:trip:" + "0" * 64),
    ("http://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity", "v1:trip:trip:" + "0" * 64),
    ("https://sts.us-east-1.amazonaws.com/?Action=AssumeRole", "v1:trip:trip:" + "0" * 64),
])
def test_missing_or_bad_url_rejected_without_fetch(monkeypatch, live, proof):
    seen = _sts_returns(monkeypatch, TRUSTED)
    result, _ = _invoke(proof=proof)
    assert result["status"] == "REJECTED" and result["http_status"] == 403
    assert seen == []
    assert live == []


def test_sts_fetch_failure_rejected(monkeypatch, live):
    seen = []
    monkeypatch.setattr(cb, "_sts_https_opener",
                        lambda: _FakeOpener(seen, exc=OSError("network down")))
    _forbid_urlopen(monkeypatch)
    result, _ = _invoke()
    assert result["status"] == "REJECTED" and result["http_status"] == 403
    assert len(seen) == 1
    assert live == []


def test_sts_opener_has_only_https_handlers():
    allowed = (urllib.request.HTTPSHandler, urllib.request.HTTPDefaultErrorHandler,
               urllib.request.HTTPErrorProcessor, urllib.request.UnknownHandler)
    forbidden = (urllib.request.HTTPHandler, urllib.request.FileHandler,
                 urllib.request.FTPHandler, urllib.request.DataHandler,
                 urllib.request.ProxyHandler, urllib.request.HTTPRedirectHandler)
    handlers = cb._sts_https_opener().handlers
    assert handlers
    assert all(type(h) in allowed for h in handlers)
    assert not any(isinstance(h, forbidden) for h in handlers)


@pytest.mark.parametrize("url", ["file:///etc/hosts", "http://127.0.0.1:9/",
                                 "ftp://127.0.0.1/x", "data:text/plain,hi"])
def test_sts_opener_refuses_non_https_schemes(url):
    # UnknownHandler raises before any socket is opened.
    with pytest.raises(urllib.error.URLError):
        cb._sts_https_opener().open(url, timeout=1)


def test_sts_opener_does_not_follow_redirects(monkeypatch):
    calls = []

    def fake_https_open(self, req):
        calls.append(req.full_url)
        headers = email.message.Message()
        headers["Location"] = "https://evil.example.com/"
        resp = urllib.response.addinfourl(io.BytesIO(b""), headers, req.full_url, 302)
        resp.msg = "Found"
        return resp

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", fake_https_open)
    good_url, header = _good_proof()
    request = urllib.request.Request(good_url, data=b"", method="POST")
    with pytest.raises(urllib.error.HTTPError) as info:
        cb._sts_https_opener().open(request, timeout=5)
    assert info.value.code == 302
    # Fail closed: the identity verification returns None, and only the STS URL was contacted.
    table = MagicMock()
    assert cb.identity_proof.verify_identity(
        good_url, header, "trip", "trip", region=cb.REGION,
        nonce_table_factory=lambda: table, opener_factory=cb._sts_https_opener) is None
    table.put_item.assert_not_called()
    assert calls == [good_url, good_url]


@pytest.mark.parametrize("code", [None, "DEMO", "Manual override: demo trigger"])
def test_unknown_reason_code_rejected(monkeypatch, live, code):
    _sts_returns(monkeypatch, TRUSTED)
    result, _ = _invoke(code=code)
    assert result["status"] == "REJECTED" and result["http_status"] == 400
    assert live == []


def test_context_identity_is_never_trusted(monkeypatch, live):
    """A Lambda context identity is not an identity proof: without a valid
    presigned proof the trip is refused, whatever context claims."""
    seen = _sts_returns(monkeypatch, TRUSTED)
    ctx = MagicMock()
    ctx.identity.arn = TRUSTED
    ctx.identity.cognito_identity_id = None
    result, _ = _invoke(proof=None, ctx=ctx)
    assert result["status"] == "REJECTED" and result["http_status"] == 403
    assert seen == [] and live == []


def test_hold_audit_event_records_triggered_by(monkeypatch):
    table = MagicMock()
    resource = MagicMock()
    resource.Table.return_value = table
    monkeypatch.setattr(cb.boto3, "resource", lambda *a, **k: resource)
    cb.write_governance_hold_event("e1", "t", "r", roles_revoked=[], triggered_by=TRUSTED)
    assert table.put_item.call_args.kwargs["Item"]["triggered_by"] == TRUSTED

    cb.write_governance_hold_event("e2", "t", "r", roles_revoked=[])
    assert "triggered_by" not in table.put_item.call_args.kwargs["Item"]


def test_alarm_path_trip_has_no_triggered_by(monkeypatch):
    """invoke_circuit_breaker's default stays None for alarm/auto trips."""
    import inspect
    assert inspect.signature(cb.invoke_circuit_breaker).parameters["triggered_by"].default is None
