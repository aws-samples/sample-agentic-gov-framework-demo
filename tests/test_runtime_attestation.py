"""
Test: governance_common.runtime_attestation state machine.

Mocked KMS client and a monkeypatched time.monotonic:
- a valid artifact verifies once and is cached;
- definitive failures (missing/malformed artifact, hash mismatch, invalid
  signature, registry mismatch) latch INVALID with exactly one KMS verify;
- transient failures return UNVERIFIED, retry no more than once per 30 s,
  and recover to VERIFIED;
- outside a deployed runtime it is a no-op unless REQUIRE_GATE_ARTIFACT=true,
  and the default factory never builds a KMS client there;
- the signature is checked against the bundled pinned gate key
  (data/signing_key_pins.json, never an alias), the envelope must sign the
  artifact's registry_version, and (ComplianceAgent) that version must equal
  the bundled registry's.
"""
import hashlib
import json
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from governance_common import runtime_attestation as ra
from governance_common import signing
from _signing_fixtures import GATE_KEY_ARN, kms_client as _fake_kms, pins as _pins, write_pins

KEY_ARN = GATE_KEY_ARN
VERSION = "2026-Q3"
REGISTRY = b'{"approved_models": [], "registry_version": "2026-Q3"}\n'
PINS_ARCNAME = "data/signing_key_pins.json"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(ra.time, "monotonic", c)
    return c


@pytest.fixture(autouse=True)
def _forced(monkeypatch):
    monkeypatch.setenv("REQUIRE_GATE_ARTIFACT", "true")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)


def _kms(valid=True):
    return _fake_kms(valid)


def _write_bundle(root, monkeypatch, *, registry=REGISTRY, artifact_extra=None, envelope_version=VERSION,
                  bundled_registry=REGISTRY):
    artifact = {"schema": "fsi-gate-artifact/v2", "registry_sha256": hashlib.sha256(registry).hexdigest(),
                "registry_version": VERSION}
    artifact.update(artifact_extra or {})
    artifact_bytes = signing.canonical_json(artifact)
    envelope = signing.sign(signing.PURPOSE_GATE, artifact_bytes, kms_client=_kms(), signed_by="ci",
                            version=envelope_version, pins=_pins())
    (root / "governance").mkdir(parents=True, exist_ok=True)
    (root / "governance" / "gate-artifact.json").write_bytes(artifact_bytes)
    (root / "governance" / "gate-artifact.json.sig").write_text(json.dumps(envelope))
    (root / "data").mkdir(exist_ok=True)
    (root / "data" / "approved_models.json").write_bytes(bundled_registry)
    write_pins(root / "data" / "signing_key_pins.json")
    monkeypatch.setenv("GATE_ARTIFACT_SHA256", hashlib.sha256(artifact_bytes).hexdigest())
    return artifact_bytes


def _attestation(root, client, registry=True):
    return ra.RuntimeAttestation(str(root), registry_relpath="data/approved_models.json" if registry else None,
                                 kms_client_factory=lambda: client, pins_path=str(root / PINS_ARCNAME))


def test_valid_artifact_verifies_once_and_is_cached(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms()
    att = _attestation(tmp_path, client)
    assert att.check() is None and att.state == ra.STATE_VERIFIED
    assert att.check() is None
    assert client.verify.call_count == 1


def test_missing_artifact_latches_invalid(tmp_path, clock):
    client = _kms()
    att = _attestation(tmp_path, client)
    assert [att.check() for _ in range(3)] == [ra.ERROR_INVALID] * 3
    assert att.state == ra.STATE_INVALID
    client.verify.assert_not_called()


def test_invalid_signature_latches_with_exactly_one_verify(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms(valid=False)
    att = _attestation(tmp_path, client)
    results = []
    for _ in range(3):
        results.append(att.check())
        clock.now += 60
    assert results == [ra.ERROR_INVALID] * 3
    assert client.verify.call_count == 1


def test_hash_mismatch_latches_without_kms(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    monkeypatch.setenv("GATE_ARTIFACT_SHA256", "0" * 64)
    client = _kms()
    att = _attestation(tmp_path, client)
    assert att.check() == ra.ERROR_INVALID
    client.verify.assert_not_called()


@pytest.mark.parametrize("value", [None, "", "abc", "G" * 64])
def test_missing_or_malformed_expected_hash_is_invalid(tmp_path, monkeypatch, clock, value):
    _write_bundle(tmp_path, monkeypatch)
    if value is None:
        monkeypatch.delenv("GATE_ARTIFACT_SHA256")
    else:
        monkeypatch.setenv("GATE_ARTIFACT_SHA256", value)
    assert _attestation(tmp_path, _kms()).check() == ra.ERROR_INVALID


def test_registry_mismatch_is_invalid(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch, registry=b"other registry")
    assert _attestation(tmp_path, _kms()).check() == ra.ERROR_INVALID
    # Without a registry check (detection/executor) the same artifact verifies.
    assert _attestation(tmp_path, _kms(), registry=False).check() is None


def test_malformed_envelope_is_invalid(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    (tmp_path / "governance" / "gate-artifact.json.sig").write_text("not json")
    assert _attestation(tmp_path, _kms()).check() == ra.ERROR_INVALID


def test_local_dev_envelope_is_invalid(tmp_path, monkeypatch, clock):
    artifact_bytes = _write_bundle(tmp_path, monkeypatch)
    monkeypatch.setenv("ALLOW_LOCAL_DEV_SIGNING", "true")
    envelope = signing.sign(signing.PURPOSE_GATE, artifact_bytes, local_dev=True, signed_by="x", version=VERSION)
    (tmp_path / "governance" / "gate-artifact.json.sig").write_text(json.dumps(envelope))
    assert _attestation(tmp_path, _kms()).check() == ra.ERROR_INVALID


def test_unavailable_then_success_after_31s(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms()
    client.verify.side_effect = [
        ClientError({"Error": {"Code": "AccessDeniedException", "Message": "hold"}}, "Verify"),
        {"SignatureValid": True},
    ]
    att = _attestation(tmp_path, client)
    assert att.check() == ra.ERROR_UNVERIFIED and att.state == ra.STATE_UNVERIFIED
    clock.now += 10
    assert att.check() == ra.ERROR_UNVERIFIED  # inside the back-off window: no KMS call
    assert client.verify.call_count == 1
    clock.now += 21
    assert att.check() is None and att.state == ra.STATE_VERIFIED
    assert client.verify.call_count == 2
    assert att.check() is None
    assert client.verify.call_count == 2


def test_client_factory_failure_is_transient(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    calls = []

    def factory():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("no region")
        return _kms()

    att = ra.RuntimeAttestation(str(tmp_path), kms_client_factory=factory,
                                pins_path=str(tmp_path / PINS_ARCNAME))
    assert att.check() == ra.ERROR_UNVERIFIED
    clock.now += 31
    assert att.check() is None


def test_noop_outside_runtime_unless_forced(tmp_path, monkeypatch, clock):
    monkeypatch.delenv("REQUIRE_GATE_ARTIFACT")
    monkeypatch.setattr(signing.os.path, "isdir", lambda p: False)
    client = _kms()
    att = _attestation(tmp_path, client)
    assert att.check() is None and att.state == ra.STATE_UNCHECKED
    client.verify.assert_not_called()


def test_default_factory_never_builds_kms_client_outside_runtime(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    monkeypatch.setattr(signing.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(boto3, "client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("boto3")))
    att = ra.RuntimeAttestation(str(tmp_path))
    assert att.check() == ra.ERROR_UNVERIFIED


def test_attestation_verifies_against_the_pinned_gate_key(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms()
    assert _attestation(tmp_path, client).check() is None
    assert client.verify.call_args.kwargs["KeyId"] == KEY_ARN
    client.describe_key.assert_not_called()


def test_attestation_with_unpinned_bundle_latches_invalid(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    (tmp_path / PINS_ARCNAME).write_text(
        '{"format": "fsi-signing-key-pins/v1", "account": null, "region": null, "keys": {}, '
        '"max_signature_age_seconds": {}}')
    client = _kms()
    assert _attestation(tmp_path, client).check() == ra.ERROR_INVALID
    client.verify.assert_not_called()


@pytest.mark.parametrize("registry", [False, True], ids=["detection-executor", "compliance"])
def test_envelope_version_must_equal_artifact_registry_version(tmp_path, monkeypatch, clock, registry):
    _write_bundle(tmp_path, monkeypatch, envelope_version="2026-Q2")
    assert _attestation(tmp_path, _kms(), registry=registry).check() == ra.ERROR_INVALID


def test_compliance_artifact_version_must_equal_bundled_registry(tmp_path, monkeypatch, clock):
    other = b'{"approved_models": [], "registry_version": "2026-Q4"}\n'
    _write_bundle(tmp_path, monkeypatch, registry=other, bundled_registry=other)
    assert _attestation(tmp_path, _kms()).check() == ra.ERROR_INVALID
    # Detection / executor don't read the registry, so the same bundle verifies.
    assert _attestation(tmp_path, _kms(), registry=False).check() is None


def test_artifact_without_registry_version_is_invalid(tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch, artifact_extra={"registry_version": None})
    assert _attestation(tmp_path, _kms(), registry=False).check() == ra.ERROR_INVALID


def test_check_once_reads_pins_from_the_bundle_root(tmp_path, monkeypatch, clock):
    monkeypatch.setattr(ra, "_DEFAULT", None)
    ra.check_once(str(tmp_path))
    assert ra._DEFAULT._pins_path == str(tmp_path / PINS_ARCNAME)


def test_check_once_uses_one_process_instance(tmp_path, monkeypatch, clock):
    monkeypatch.setattr(ra, "_DEFAULT", None)
    assert ra.check_once(str(tmp_path)) == ra.ERROR_INVALID
    first = ra._DEFAULT
    assert ra.check_once(str(tmp_path / "other")) == ra.ERROR_INVALID
    assert ra._DEFAULT is first


# ─── Shim integration: first /invocations runs the attestation ──────────────

import importlib.util  # noqa: E402
import io  # noqa: E402
import os  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SHIMS = {name: os.path.join(_PROJECT_ROOT, "agentcore", f"{name}_agent", "main.py")
          for name in ("detection", "compliance", "executor")}


@pytest.fixture(params=sorted(_SHIMS))
def shim(request, monkeypatch):
    spec = importlib.util.spec_from_file_location(f"_attestation_shim_{request.param}", _SHIMS[request.param])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "_get_handler", lambda: (lambda event: calls.append(event) or {"ok": True}))
    module.handler_calls = calls
    module.shim_name = request.param
    return module


def _request(shim, method, path, body=b"{}"):
    req = object.__new__(shim.AgentHandler)
    req.path = path
    req.headers = {"Content-Length": str(len(body))}
    req.rfile = io.BytesIO(body)
    req.wfile = io.BytesIO()
    statuses = []
    req.send_response = statuses.append
    req.send_header = lambda k, v: None
    req.end_headers = lambda: None
    getattr(req, method)()
    raw = req.wfile.getvalue()
    return statuses, (json.loads(raw) if raw else None)


def _install(monkeypatch, root, client, shim):
    registry = "data/approved_models.json" if shim.shim_name == "compliance" else None
    att = ra.RuntimeAttestation(str(root), registry_relpath=registry, kms_client_factory=lambda: client,
                                pins_path=str(root / PINS_ARCNAME))
    monkeypatch.setattr(ra, "_DEFAULT", att)
    return att


def test_shim_missing_artifact_is_503_invalid_and_ping_stays_up(shim, tmp_path, monkeypatch, clock):
    _install(monkeypatch, tmp_path, _kms(), shim)
    for _ in range(2):
        statuses, body = _request(shim, "do_POST", "/invocations")
        assert statuses == [503] and body == {"error": ra.ERROR_INVALID}
    assert shim.handler_calls == []
    statuses, body = _request(shim, "do_GET", "/ping")
    assert statuses == [200] and body == {"status": "Healthy"}


def test_shim_valid_artifact_serves(shim, tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms()
    _install(monkeypatch, tmp_path, client, shim)
    statuses, _ = _request(shim, "do_POST", "/invocations")
    assert statuses == [200]
    _request(shim, "do_POST", "/invocations")
    assert len(shim.handler_calls) == 2 and client.verify.call_count == 1


def test_shim_unavailable_then_success_after_backoff(shim, tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms()
    client.verify.side_effect = [ClientError({"Error": {"Code": "ThrottlingException"}}, "Verify"),
                                 {"SignatureValid": True}]
    _install(monkeypatch, tmp_path, client, shim)
    assert _request(shim, "do_POST", "/invocations") == ([503], {"error": ra.ERROR_UNVERIFIED})
    clock.now += 5
    assert _request(shim, "do_POST", "/invocations") == ([503], {"error": ra.ERROR_UNVERIFIED})
    assert client.verify.call_count == 1           # inside the 30 s window: no KMS call
    clock.now += 31
    statuses, _ = _request(shim, "do_POST", "/invocations")
    assert statuses == [200] and client.verify.call_count == 2
    assert len(shim.handler_calls) == 1


def test_shim_invalid_signature_latches(shim, tmp_path, monkeypatch, clock):
    _write_bundle(tmp_path, monkeypatch)
    client = _kms(valid=False)
    _install(monkeypatch, tmp_path, client, shim)
    for _ in range(3):
        assert _request(shim, "do_POST", "/invocations") == ([503], {"error": ra.ERROR_INVALID})
        clock.now += 60
    assert client.verify.call_count == 1 and shim.handler_calls == []


def test_shims_call_check_once_with_their_own_root():
    for name, path in _SHIMS.items():
        with open(path, encoding="utf-8") as f:
            src = f.read()
        assert "runtime_attestation.check_once(" in src, name
        assert ('registry_relpath="data/approved_models.json"' in src) is (name == "compliance"), name
