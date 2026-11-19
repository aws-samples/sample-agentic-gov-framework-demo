"""
Pinned signing keys, envelope v2 (signed_at + version signed),
freshness, the registry version latch and the runtime registry expiry.
KMS is a mock whose describe_key fails the test; no AWS call is made.
"""
import importlib.util
import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

import model_assurance
from governance_common import signing
from _signing_fixtures import (
    ACCOUNT, ATTACKER_KEY_ARN, GATE_KEY_ARN, REGISTRY_KEY_ARN, kms_client, pins, pins_document, write_pins,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAYLOAD = b'{"x": 1}'
VERSION = "2026-Q3"
T0 = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _not_in_runtime(monkeypatch):
    real_isdir = signing.os.path.isdir
    monkeypatch.setattr(signing.os.path, "isdir", lambda p: False if p == "/var/task" else real_isdir(p))


def _kms_env(purpose=signing.PURPOSE_REGISTRY, payload=PAYLOAD, version=VERSION, now=T0, client=None):
    return signing.sign(purpose, payload, kms_client=client or kms_client(), signed_by="x", version=version,
                        pins=pins(), now=now)


def _verify(env, payload=PAYLOAD, client=None, **kwargs):
    return signing.verify(signing.PURPOSE_REGISTRY, payload, env, kms_client=client or kms_client(),
                          require_kms=True, pins=pins(), **kwargs)


# ─── Pins file ───────────────────────────────────────────────────────────────

def test_shipped_pins_file_is_exact_and_loads():
    path = os.path.join(PROJECT_ROOT, "data", "signing_key_pins.json")
    with open(path, encoding="utf-8") as f:
        assert json.load(f) == {"format": "fsi-signing-key-pins/v1", "account": None, "region": None,
                                "keys": {}, "max_signature_age_seconds": {}}
    loaded = signing.load_key_pins(path)
    assert loaded.key_arn(signing.PURPOSE_REGISTRY) is None
    assert loaded.max_signature_age(signing.PURPOSE_REGISTRY) == 120 * 86400
    assert loaded.max_signature_age(signing.PURPOSE_GATE) == 3600


def test_default_pins_path_sits_next_to_governance_common():
    assert signing.DEFAULT_PINS_PATH.endswith(os.path.join("data", "signing_key_pins.json"))
    assert os.path.dirname(os.path.dirname(signing.DEFAULT_PINS_PATH)) == os.path.dirname(
        os.path.dirname(signing.__file__))


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(account=None, region=None),                       # null account, non-empty keys
    lambda d: d.update(account=ACCOUNT, region=None),
    lambda d: d.pop("max_signature_age_seconds"),
    lambda d: d.update(extra=1),
    lambda d: d.update(format="fsi-signing-key-pins/v0"),
    lambda d: d["keys"].update({"deploy-gate-artifact": ATTACKER_KEY_ARN}),    # other account
    lambda d: d["keys"].update({"deploy-gate-artifact": GATE_KEY_ARN.replace("us-east-1", "eu-west-1")}),
    lambda d: d["keys"].update({"deploy-gate-artifact": "alias/fsi-deploy-gate-signing"}),
    lambda d: d["keys"].update({"other": GATE_KEY_ARN}),
    lambda d: d.update(account="12345"),
    lambda d: d.update(region="US-EAST-1"),
    lambda d: d["max_signature_age_seconds"].update({"approved-models-registry": 401 * 86400}),
    lambda d: d["max_signature_age_seconds"].update({"deploy-gate-artifact": 8 * 86400}),
    lambda d: d["max_signature_age_seconds"].update({"deploy-gate-artifact": 0}),
    lambda d: d["max_signature_age_seconds"].update({"deploy-gate-artifact": True}),
    lambda d: d["max_signature_age_seconds"].update({"deploy-gate-artifact": "3600"}),
])
def test_pin_rules(tmp_path, mutate):
    doc = pins_document()
    mutate(doc)
    path = tmp_path / "pins.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(signing.SignatureInvalidError):
        signing.load_key_pins(str(path))


def test_missing_or_oversized_pins_are_invalid(tmp_path):
    with pytest.raises(signing.SignatureInvalidError, match="missing"):
        signing.load_key_pins(str(tmp_path / "absent.json"))
    big = tmp_path / "big.json"
    big.write_text(" " * (17 * 1024), encoding="utf-8")
    with pytest.raises(signing.SignatureInvalidError):
        signing.load_key_pins(str(big))


def test_valid_pins_with_ages(tmp_path):
    loaded = signing.load_key_pins(write_pins(tmp_path / "p.json", ages={"deploy-gate-artifact": 7200}))
    assert loaded.key_arn(signing.PURPOSE_GATE) == GATE_KEY_ARN
    assert loaded.max_signature_age(signing.PURPOSE_GATE) == 7200


# ─── Alias repointing ────────────────────────────────────────────────────────

def test_alias_repoint_yields_no_accepted_signature():
    """KMS says valid for any KeyId and the alias now resolves to the
    attacker's key: an envelope signed with that key is still refused, and
    neither sign nor verify ever calls DescribeKey."""
    client = kms_client()
    client.describe_key.side_effect = lambda **k: {"KeyMetadata": {"Arn": ATTACKER_KEY_ARN}}
    env = dict(_kms_env(client=client), key_id=ATTACKER_KEY_ARN)
    with pytest.raises(signing.SignatureInvalidError):
        _verify(env, client=client)
    client.describe_key.assert_not_called()
    client.verify.assert_not_called()
    assert client.sign.call_args.kwargs["KeyId"] == REGISTRY_KEY_ARN


def test_sign_with_default_pins_reads_the_default_path(tmp_path, monkeypatch):
    monkeypatch.setattr(signing, "DEFAULT_PINS_PATH", write_pins(tmp_path / "p.json"))
    client = kms_client()
    env = signing.sign(signing.PURPOSE_GATE, PAYLOAD, kms_client=client, signed_by="x", version=VERSION)
    assert env["key_id"] == GATE_KEY_ARN and client.sign.call_args.kwargs["KeyId"] == GATE_KEY_ARN
    signing.verify(signing.PURPOSE_GATE, PAYLOAD, env, kms_client=client, require_kms=True)


def test_kms_sign_without_a_pinned_key_is_refused(monkeypatch):
    monkeypatch.setattr(signing, "DEFAULT_PINS_PATH", os.path.join(PROJECT_ROOT, "data", "signing_key_pins.json"))
    client = kms_client()
    with pytest.raises(signing.SignatureInvalidError, match="no pinned signing key"):
        signing.sign(signing.PURPOSE_GATE, PAYLOAD, kms_client=client, signed_by="x", version=VERSION)
    client.sign.assert_not_called()


# ─── Envelope v2 ─────────────────────────────────────────────────────────────

def test_signed_at_and_version_are_in_the_signed_message():
    client = kms_client()
    env = _kms_env(client=client)
    _verify(env, client=client)
    base = client.verify.call_args.kwargs["Message"]
    for field, value in (("signed_at", (T0 + timedelta(seconds=1)).isoformat()), ("version", "2026-Q4")):
        client = kms_client()
        _verify(dict(env, **{field: value}), client=client)  # KMS mock says valid; the bytes differ
        assert client.verify.call_args.kwargs["Message"] != base, field


def test_v1_envelope_is_refused():
    env = _kms_env()
    v1 = {k: v for k, v in env.items() if k != "version"}
    v1["format"] = "fsi-governance-signature/v1"
    with pytest.raises(signing.SignatureInvalidError, match="v1"):
        _verify(v1)


@pytest.mark.parametrize("algorithm", ["kms", "local"])
@pytest.mark.parametrize("field,value", [
    ("version", "a b"), ("version", "x\ny"), ("version", "x" * 33),
    ("signed_at", "2026-06-01T12:00:00"), ("signed_at", "yesterday"),
])
@pytest.mark.parametrize("with_max_age", [False, True])
def test_malformed_version_or_signed_at_is_invalid(algorithm, field, value, with_max_age):
    if algorithm == "kms":
        env = _kms_env()
    else:
        env = signing.sign(signing.PURPOSE_REGISTRY, PAYLOAD, local_dev=True, signed_by="x", version=VERSION)
    env[field] = value
    kwargs = {"max_age_seconds": 3600, "now": T0} if with_max_age else {}
    with pytest.raises(signing.SignatureInvalidError):
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=kms_client(),
                       require_kms=algorithm == "kms", pins=pins(), **kwargs)


def test_empty_version_is_invalid_and_refused_at_sign():
    env = _kms_env()
    env["version"] = ""
    with pytest.raises(signing.SignatureInvalidError):
        _verify(env)
    for bad in ("", "a b", "x" * 33, None):
        with pytest.raises(signing.SignatureInvalidError):
            signing.sign(signing.PURPOSE_REGISTRY, PAYLOAD, local_dev=True, signed_by="x", version=bad)


def test_expected_version_binding():
    env = _kms_env()
    assert _verify(env, expected_version=VERSION) == T0
    with pytest.raises(signing.SignatureInvalidError, match="version"):
        _verify(env, expected_version="2026-Q4")


# ─── Freshness ───────────────────────────────────────────────────────────────

def test_stale_and_future_signatures_are_refused():
    env = _kms_env()
    _verify(env, max_age_seconds=3600, now=T0 + timedelta(seconds=3599))
    with pytest.raises(signing.SignatureInvalidError, match="stale"):
        _verify(env, max_age_seconds=3600, now=T0 + timedelta(seconds=3601))
    with pytest.raises(signing.SignatureInvalidError, match="future-dated"):
        _verify(env, max_age_seconds=3600, now=T0 - timedelta(seconds=301))
    _verify(env, max_age_seconds=3600, now=T0 - timedelta(seconds=299))


def test_old_local_dev_envelope_still_verifies():
    env = signing.sign(signing.PURPOSE_REGISTRY, PAYLOAD, local_dev=True, signed_by="x", version=VERSION,
                       now=T0 - timedelta(days=3650))
    signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False, max_age_seconds=60,
                   expected_version=VERSION)


# ─── Registry: strict reads, the latch, runtime expiry ──────────────────────

def _registry(tmp_path, version="2026-Q3", extra=None, signed_at=T0, name="approved_models.json"):
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    reg = data_dir / name
    doc = json.loads(open(os.path.join(PROJECT_ROOT, "data", "approved_models.json"), encoding="utf-8").read())
    doc["registry_version"] = version
    doc.update(extra or {})
    reg.write_text(json.dumps(doc), encoding="utf-8")
    env = signing.sign(signing.PURPOSE_REGISTRY, reg.read_bytes(), kms_client=kms_client(), signed_by="x",
                       version=version, pins=pins(), now=signed_at)
    (data_dir / (name + ".kms.sig")).write_text(json.dumps(env), encoding="utf-8")
    return str(reg)


def _strict(path, now, client=None):
    return model_assurance.verified_registry_bytes(path, require_kms=True, kms_client=client or kms_client(),
                                                   pins=pins(), now=now)


def test_registry_accepted_then_refused_after_max_age(tmp_path):
    path = _registry(tmp_path)
    registry, _data, signed_at = _strict(path, T0 + timedelta(days=119))
    assert signed_at == T0 and registry["registry_version"] == VERSION
    with pytest.raises(signing.SignatureInvalidError, match="stale"):
        _strict(path, T0 + timedelta(days=121))


def test_registry_envelope_version_must_equal_registry_version(tmp_path):
    path = _registry(tmp_path)
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    # A different registry_version with the same bytes can't be produced, so
    # re-sign the same bytes claiming another version.
    env = signing.sign(signing.PURPOSE_REGISTRY, open(path, "rb").read(), kms_client=kms_client(), signed_by="x",
                       version="2026-Q4", pins=pins(), now=T0)
    with open(path + ".kms.sig", "w", encoding="utf-8") as f:
        json.dump(env, f)
    assert doc["registry_version"] == VERSION
    with pytest.raises(signing.SignatureInvalidError, match="version"):
        _strict(path, T0)


def test_strict_read_refuses_a_malformed_registry_version(tmp_path):
    path = _registry(tmp_path, version="test-1")
    with pytest.raises(signing.SignatureInvalidError, match="registry_version"):
        _strict(path, T0)


@pytest.mark.parametrize("value,parsed", [("2026-Q3", (2026, 3, 0)), ("2026-Q3.12", (2026, 3, 12))])
def test_parse_registry_version(value, parsed):
    assert model_assurance.parse_registry_version(value) == parsed


@pytest.mark.parametrize("value", ["2026-Q5", "2026-Q0", "26-Q1", "2026-Q1.1234", "2026Q1", None, 2026])
def test_parse_registry_version_rejects(value):
    with pytest.raises(ValueError):
        model_assurance.parse_registry_version(value)


def test_latch_refuses_lower_version_or_same_version_with_other_bytes(tmp_path):
    q3 = _registry(tmp_path, version="2026-Q3", name="q3.json")
    q2 = _registry(tmp_path, version="2026-Q2", name="q2.json")
    q3_changed = _registry(tmp_path, version="2026-Q3", name="q3b.json", extra={"note": "swapped"})
    _strict(q3, T0)
    with pytest.raises(signing.SignatureInvalidError, match="older"):
        _strict(q2, T0)
    with pytest.raises(signing.SignatureInvalidError, match="without a registry_version bump"):
        _strict(q3_changed, T0)
    _strict(q3, T0)                                                # same bytes: fine
    _strict(_registry(tmp_path, version="2026-Q3.1", name="q31.json"), T0)  # higher: fine


def test_local_dev_reads_do_not_latch(tmp_path):
    shutil.copyfile(os.path.join(PROJECT_ROOT, "data", "approved_models.json"), tmp_path / "a.json")
    model_assurance.load_verified_registry()
    assert model_assurance._ACCEPTED_REGISTRY is None


def test_committed_local_dev_sig_is_v3_and_binds_the_version():
    with open(os.path.join(PROJECT_ROOT, "data", "approved_models.json.sig"), encoding="utf-8") as f:
        env = json.load(f)
    assert env["format"] == "fsi-governance-signature/v3" and env["version"] == "2026-Q3"


class TestRuntimeRegistryExpiry:
    @pytest.fixture
    def runtime(self, tmp_path, monkeypatch):
        import lambdas.compliance_agent.handler as h
        path = _registry(tmp_path)
        shutil.copyfile(path + ".kms.sig", path + ".sig")  # inside a runtime the .sig holds the KMS envelope
        monkeypatch.setattr(model_assurance, "DEFAULT_REGISTRY_PATH", path)
        monkeypatch.setattr(h, "_VERIFIED_REGISTRY_CACHE", {})
        monkeypatch.setattr(signing.os.path, "isdir", lambda p: p == "/var/task")
        client = kms_client()
        monkeypatch.setattr(model_assurance, "_RUNTIME_KMS_CLIENT", client)
        monkeypatch.setattr(signing, "DEFAULT_PINS_PATH", write_pins(tmp_path / "pins.json"))
        return h, client

    def test_cache_expires_and_stale_registry_refuses(self, runtime):
        h, client = runtime
        assert h._verified_registry(now=T0 + timedelta(days=1))["registry_version"] == VERSION
        h._verified_registry(now=T0 + timedelta(days=100))      # cached, still valid
        assert client.verify.call_count == 1
        with pytest.raises(h.UnapprovedModelError, match="signature invalid"):
            h._verified_registry(now=T0 + timedelta(days=121))  # past valid_until: re-verified, stale
        assert client.verify.call_count == 1                    # stale is refused before KMS


# ─── Tools ───────────────────────────────────────────────────────────────────

def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(PROJECT_ROOT, rel))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sign_registry_refuses_a_malformed_registry_version(tmp_path):
    reg = tmp_path / "approved_models.json"
    reg.write_text(json.dumps({"approved_models": [], "registry_version": "test-1"}), encoding="utf-8")
    tool = _load("_sign_registry_pins", "scripts/sign_registry.py")
    assert tool.main(["--local-dev", "--registry", str(reg)]) == 1
    assert not (tmp_path / "approved_models.json.sig").exists()


def test_sign_registry_kms_refuses_without_pins(tmp_path, monkeypatch):
    reg = tmp_path / "approved_models.json"
    shutil.copyfile(os.path.join(PROJECT_ROOT, "data", "approved_models.json"), reg)
    monkeypatch.setattr(signing, "DEFAULT_PINS_PATH", os.path.join(PROJECT_ROOT, "data", "signing_key_pins.json"))
    tool = _load("_sign_registry_pins2", "scripts/sign_registry.py")
    monkeypatch.setattr(tool, "_session", lambda: (_ for _ in ()).throw(AssertionError("no session")))
    assert tool.main(["--kms", "--registry", str(reg)]) == 1
    assert not (tmp_path / "approved_models.json.kms.sig").exists()


def _session(outputs):
    sts, cfn = MagicMock(), MagicMock()
    sts.get_caller_identity.return_value = {"Account": ACCOUNT}
    cfn.describe_stacks.return_value = {"Stacks": [{"Outputs": [
        {"OutputKey": k, "OutputValue": v} for k, v in outputs.items()]}]}
    session = MagicMock()
    session.client.side_effect = lambda name, region_name=None: {"sts": sts, "cloudformation": cfn}[name]
    return session, cfn


def test_pin_signing_keys_writes_check_and_keeps_ages(tmp_path, monkeypatch):
    tool = _load("_pin_signing_keys", "scripts/pin_signing_keys.py")
    path = tmp_path / "signing_key_pins.json"
    write_pins(path, ages={"approved-models-registry": 86400})
    outputs = {"RegistrySigningKeyArn": REGISTRY_KEY_ARN, "GateSigningKeyArn": GATE_KEY_ARN}
    session, cfn = _session(outputs)
    monkeypatch.setattr(tool, "_session", lambda: session)
    assert tool.main(["--pins", str(path), "--check"]) == 0
    assert tool.main(["--pins", str(path)]) == 0
    written = json.loads(path.read_text(encoding="utf-8"))
    assert written["keys"] == {"approved-models-registry": REGISTRY_KEY_ARN, "deploy-gate-artifact": GATE_KEY_ARN}
    assert written["max_signature_age_seconds"] == {"approved-models-registry": 86400}
    assert cfn.describe_stacks.call_args.kwargs == {"StackName": "FsiComplianceAgents"}
    outputs["GateSigningKeyArn"] = GATE_KEY_ARN.replace("6666", "7777")
    session, _ = _session(outputs)
    monkeypatch.setattr(tool, "_session", lambda: session)
    before = path.read_bytes()
    assert tool.main(["--pins", str(path), "--check"]) == 1
    assert path.read_bytes() == before
