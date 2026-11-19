"""
Test: governance_common.signing.

Local-dev HMAC envelopes round-trip only under ALLOW_LOCAL_DEV_SIGNING=true
outside a deployed runtime and never where KMS is required; KMS envelopes
verify only through an explicitly passed (mocked) KMS client against the
PINNED key ARN (no alias is ever resolved), and no code path
constructs a KMS client implicitly. Envelopes are v3 (signed_at, version
and signed_by signed; v1 and v2 refused). Pin rules, freshness and the registry floor: test_signing_pins.py.
"""
import base64
import copy
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from governance_common import signing
from _signing_fixtures import ATTACKER_KEY_ARN, REGISTRY_KEY_ARN, kms_client as _fake_kms, write_pins

KEY_ARN = REGISTRY_KEY_ARN
PAYLOAD = b'{"models": ["a", "b"]}'
VERSION = "2026-Q3"


@pytest.fixture(autouse=True)
def _local_dev_env(monkeypatch):
    monkeypatch.setenv("ALLOW_LOCAL_DEV_SIGNING", "true")
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    real_isdir = signing.os.path.isdir
    monkeypatch.setattr(signing.os.path, "isdir",
                        lambda p: False if p == "/var/task" else real_isdir(p))


@pytest.fixture(autouse=True)
def _pins(monkeypatch, tmp_path_factory):
    path = write_pins(tmp_path_factory.mktemp("pins") / "signing_key_pins.json")
    monkeypatch.setattr(signing, "DEFAULT_PINS_PATH", path)
    return path


@pytest.fixture
def no_boto3(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("boto3 must not be reached")
    monkeypatch.setattr(boto3, "client", refuse)
    monkeypatch.setattr(boto3, "Session", refuse)
    monkeypatch.setattr(boto3, "resource", refuse)


def _local_envelope(purpose=signing.PURPOSE_REGISTRY, payload=PAYLOAD):
    return signing.sign(purpose, payload, local_dev=True, signed_by="local:alice", version=VERSION)


def _kms_client(valid=True):
    return _fake_kms(valid)


def _kms_envelope(client=None, payload=PAYLOAD, purpose=signing.PURPOSE_REGISTRY, version=VERSION):
    return signing.sign(purpose, payload, kms_client=client or _kms_client(),
                        signed_by="arn:aws:sts::123456789012:assumed-role/fsi-model-risk-approver/alice",
                        version=version)


class TestLocalDev:
    def test_round_trip(self, no_boto3):
        env = _local_envelope()
        assert set(env) == signing.ENVELOPE_KEYS
        assert env["algorithm"] == signing.ALG_LOCAL_DEV and env["key_id"] == "local-dev"
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_flipped_payload_byte_is_invalid(self):
        env = _local_envelope()
        tampered = bytearray(PAYLOAD)
        tampered[3] ^= 0x01
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, bytes(tampered), env, require_kms=False)

    def test_flipped_signature_is_invalid(self):
        env = _local_envelope()
        sig = bytearray(base64.b64decode(env["signature_b64"]))
        sig[0] ^= 0x01
        env["signature_b64"] = base64.b64encode(bytes(sig)).decode()
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_wrong_purpose_is_invalid(self):
        env = _local_envelope(purpose=signing.PURPOSE_GATE)
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_extra_or_missing_envelope_key_is_invalid(self):
        env = _local_envelope()
        extra = dict(env, note="x")
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, extra, require_kms=False)
        missing = dict(env)
        del missing["signed_by"]
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, missing, require_kms=False)

    @pytest.mark.parametrize("envelope", [None, [], "x", 7])
    def test_non_dict_envelope_is_invalid(self, envelope):
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, envelope, require_kms=False)

    def test_non_string_field_is_invalid(self):
        env = _local_envelope()
        env["signed_at"] = 12
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_unknown_algorithm_is_invalid(self):
        env = _local_envelope()
        env["algorithm"] = "NONE"
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_require_kms_refuses_local_dev(self):
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, _local_envelope(), require_kms=True)

    def test_deployed_runtime_refuses_local_dev(self, monkeypatch):
        env = _local_envelope()
        monkeypatch.setattr(signing.os.path, "isdir", lambda p: p == "/var/task")
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_lambda_env_refuses_local_dev(self, monkeypatch):
        env = _local_envelope()
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "fn")
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    @pytest.mark.parametrize("value", [None, "false", "TRUE", "1"])
    def test_opt_in_must_be_exactly_true(self, monkeypatch, value):
        env = _local_envelope()
        if value is None:
            monkeypatch.delenv("ALLOW_LOCAL_DEV_SIGNING", raising=False)
        else:
            monkeypatch.setenv("ALLOW_LOCAL_DEV_SIGNING", value)
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_local_dev_signing_refused_in_runtime(self, monkeypatch):
        monkeypatch.setattr(signing.os.path, "isdir", lambda p: p == "/var/task")
        with pytest.raises(signing.SignatureError):
            _local_envelope()


class TestKms:
    def test_round_trip_with_mocked_client(self, no_boto3):
        client = _kms_client()
        env = _kms_envelope(client)
        assert env["algorithm"] == signing.ALG_KMS and env["key_id"] == KEY_ARN
        sign_kwargs = client.sign.call_args.kwargs
        assert sign_kwargs["MessageType"] == "DIGEST"
        assert sign_kwargs["SigningAlgorithm"] == "ECDSA_SHA_256"
        assert sign_kwargs["Message"] == signing.digest(signing.PURPOSE_REGISTRY, PAYLOAD,
                                                        env["signed_at"], env["version"],
                                                        env["signed_by"])
        assert sign_kwargs["KeyId"] == KEY_ARN and env["version"] == VERSION
        assert env["format"] == "fsi-governance-signature/v3"
        client.describe_key.assert_not_called()
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=client, require_kms=True)
        verify_kwargs = client.verify.call_args.kwargs
        assert verify_kwargs["KeyId"] == KEY_ARN and verify_kwargs["MessageType"] == "DIGEST"

    def test_key_id_not_the_pinned_key_is_invalid(self):
        env = dict(_kms_envelope(), key_id=ATTACKER_KEY_ARN)
        other = _kms_client()
        with pytest.raises(signing.SignatureInvalidError, match="pinned"):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=other, require_kms=True)
        other.verify.assert_not_called()

    def test_signature_valid_false_is_invalid(self):
        env = _kms_envelope()
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env,
                           kms_client=_kms_client(valid=False), require_kms=True)

    def test_kms_invalid_signature_exception_is_invalid(self):
        env = _kms_envelope()
        client = _kms_client()
        client.verify.side_effect = ClientError(
            {"Error": {"Code": "KMSInvalidSignatureException", "Message": "bad"}}, "Verify")
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=client, require_kms=True)

    @pytest.mark.parametrize("code", ["AccessDeniedException", "ThrottlingException"])
    def test_other_client_errors_are_unavailable(self, code):
        env = _kms_envelope()
        client = _kms_client()
        client.verify.side_effect = ClientError({"Error": {"Code": code, "Message": "m"}}, "Verify")
        with pytest.raises(signing.SignatureVerificationUnavailableError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=client, require_kms=True)

    def test_verify_uses_the_pinned_arn_not_an_alias(self):
        env = _kms_envelope()
        client = _kms_client()
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=client, require_kms=True)
        assert client.verify.call_args.kwargs["KeyId"] == KEY_ARN
        client.describe_key.assert_not_called()

    def test_kms_envelope_without_client_is_unavailable_and_builds_no_client(self, no_boto3):
        env = _kms_envelope()
        with pytest.raises(signing.SignatureVerificationUnavailableError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)
        with pytest.raises(signing.SignatureVerificationUnavailableError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=None, require_kms=True)

    def test_kms_sign_without_client_builds_no_client(self, no_boto3):
        with pytest.raises(signing.SignatureVerificationUnavailableError):
            signing.sign(signing.PURPOSE_GATE, PAYLOAD, signed_by="x", version=VERSION)

    def test_payload_mismatch_detected_before_kms(self):
        env = _kms_envelope()
        client = _kms_client()
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD + b" ", env, kms_client=client,
                           require_kms=True)
        client.verify.assert_not_called()


def test_canonical_json_is_stable():
    assert signing.canonical_json({"b": 1, "a": [1, "é"]}) == b'{"a":[1,"\\u00e9"],"b":1}'


def test_digest_is_domain_separated_by_purpose():
    ts = "2026-01-01T00:00:00+00:00"
    assert signing.digest(signing.PURPOSE_REGISTRY, PAYLOAD, ts, VERSION, "x") != \
        signing.digest(signing.PURPOSE_GATE, PAYLOAD, ts, VERSION, "x")


def test_digest_binds_signed_by():
    ts = "2026-01-01T00:00:00+00:00"
    assert signing.digest(signing.PURPOSE_REGISTRY, PAYLOAD, ts, VERSION, "arn:a") != \
        signing.digest(signing.PURPOSE_REGISTRY, PAYLOAD, ts, VERSION, "arn:b")


class TestSignedByIsSigned:
    """signed_by is inside the signed digest (envelope v3)."""

    def test_local_dev_round_trip_keeps_signed_by(self):
        env = _local_envelope()
        assert env["format"] == signing.FORMAT_V3 and env["signed_by"] == "local:alice"
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_tampered_signed_by_fails_local_dev(self):
        env = dict(_local_envelope(), signed_by="local:mallory")
        with pytest.raises(signing.SignatureInvalidError, match="does not verify"):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    def test_tampered_signed_by_changes_the_kms_digest(self):
        client = _kms_client()
        env = _kms_envelope(client)
        signed_message = client.sign.call_args.kwargs["Message"]
        tampered = dict(env, signed_by="arn:aws:sts::123456789012:assumed-role/other/mallory")
        verifier = _kms_client(valid=False)  # KMS rejects a digest it did not sign
        with pytest.raises(signing.SignatureInvalidError):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, tampered, kms_client=verifier,
                           require_kms=True)
        assert verifier.verify.call_args.kwargs["Message"] != signed_message
        signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, kms_client=_kms_client(), require_kms=True)

    def test_v2_envelope_is_refused(self):
        env = dict(_local_envelope(), format=signing.FORMAT_V2)
        with pytest.raises(signing.SignatureInvalidError, match="v2"):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)

    @pytest.mark.parametrize("bad", ["a\nb", "x\x00", "x" * 513])
    def test_signed_by_with_control_characters_is_refused(self, bad):
        with pytest.raises(signing.SignatureInvalidError):
            signing.sign(signing.PURPOSE_REGISTRY, PAYLOAD, local_dev=True, signed_by=bad, version=VERSION)
        env = dict(_local_envelope(), signed_by=bad)
        with pytest.raises(signing.SignatureInvalidError, match="signed_by"):
            signing.verify(signing.PURPOSE_REGISTRY, PAYLOAD, env, require_kms=False)


def test_unknown_purpose_rejected():
    with pytest.raises(ValueError):
        signing.sign("other", PAYLOAD, local_dev=True, signed_by="x", version=VERSION)
    with pytest.raises(ValueError):
        signing.verify("other", PAYLOAD, copy.deepcopy(_local_envelope()), require_kms=False)


def test_no_alias_is_resolved_anywhere_in_signing():
    """The alias table is gone and signing never calls DescribeKey."""
    assert not hasattr(signing, "ALIASES")
    assert signing.PURPOSES == {"approved-models-registry", "deploy-gate-artifact"}
    with open(signing.__file__, encoding="utf-8") as f:
        source = f.read()
    assert "describe_key(" not in source and "alias/" not in source


# ─── Signed registry (two-file layout) ───────

import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402

import model_assurance  # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REGISTRY = os.path.join(_PROJECT_ROOT, "data", "approved_models.json")
_COMMITTED_SIG = _REGISTRY + ".sig"


def _registry_copy(tmp_path, *, with_sig=True):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    reg = data_dir / "approved_models.json"
    shutil.copyfile(_REGISTRY, reg)
    if with_sig:
        shutil.copyfile(_COMMITTED_SIG, str(reg) + ".sig")
    return reg


def _load_sign_registry():
    spec = importlib.util.spec_from_file_location(
        "_sign_registry_under_test", os.path.join(_PROJECT_ROOT, "scripts", "sign_registry.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestRegistry:
    def test_committed_sig_verifies(self, no_boto3):
        registry = model_assurance.load_verified_registry()
        assert registry["approved_models"]
        with open(_COMMITTED_SIG, encoding="utf-8") as f:
            assert json.load(f)["algorithm"] == signing.ALG_LOCAL_DEV

    def test_kms_sig_is_not_shipped_and_is_ignored(self):
        # The KMS signature is deploy-only: never committed on main, so the
        # .gitignore must name it.
        assert not os.path.exists(_REGISTRY + ".kms.sig")
        with open(os.path.join(_PROJECT_ROOT, ".gitignore"), encoding="utf-8") as f:
            assert "data/approved_models.json.kms.sig" in f.read().splitlines()

    def test_committed_sig_requires_the_opt_in(self, monkeypatch):
        monkeypatch.delenv("ALLOW_LOCAL_DEV_SIGNING")
        with pytest.raises(signing.SignatureInvalidError):
            model_assurance.load_verified_registry()

    def test_added_model_with_old_sig_is_refused(self, tmp_path):
        reg = _registry_copy(tmp_path)
        data = json.loads(reg.read_text(encoding="utf-8"))
        data["approved_models"].append({"model_id": "us.meta.llama3-3-70b-instruct-v1:0", "status": "approved"})
        reg.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(signing.SignatureInvalidError):
            model_assurance.load_verified_registry(str(reg))

    def test_missing_sig_is_refused(self, tmp_path):
        reg = _registry_copy(tmp_path, with_sig=False)
        with pytest.raises(signing.SignatureInvalidError, match="missing"):
            model_assurance.load_verified_registry(str(reg))

    def test_load_registry_stays_a_pure_parse(self, tmp_path):
        reg = _registry_copy(tmp_path, with_sig=False)
        assert model_assurance.load_registry(str(reg))["approved_models"]


class TestTwoSignatureFiles:
    def test_sig_path_defaults(self, monkeypatch):
        path = "/x/data/approved_models.json"
        assert model_assurance.default_signature_path(path, False) == path + ".sig"
        assert model_assurance.default_signature_path(path, True) == path + ".kms.sig"
        monkeypatch.setattr(signing.os.path, "isdir", lambda p: p == "/var/task")
        assert model_assurance.default_signature_path(path, False) == path + ".sig"
        assert model_assurance.default_signature_path(path, True) == path + ".sig"

    def test_require_kms_reads_the_kms_sig(self, tmp_path):
        reg = _registry_copy(tmp_path)          # only the local-dev .sig exists
        with pytest.raises(signing.SignatureInvalidError, match="kms.sig"):
            model_assurance.load_verified_registry(str(reg), require_kms=True, kms_client=_kms_client())

    def test_sign_registry_kms_writes_only_kms_sig(self, tmp_path, monkeypatch):
        reg = _registry_copy(tmp_path)
        before = (tmp_path / "data" / "approved_models.json.sig").read_bytes()
        kms = _kms_client()
        sts = MagicMock()
        sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:sts::123456789012:assumed-role/fsi-model-risk-approver/alice"}
        session = MagicMock()
        session.client.side_effect = lambda name, region_name=None: {"kms": kms, "sts": sts}[name]
        tool = _load_sign_registry()
        monkeypatch.setattr(tool, "_session", lambda: session)
        assert tool.main(["--kms", "--registry", str(reg)]) == 0
        envelope = json.loads((tmp_path / "data" / "approved_models.json.kms.sig").read_text())
        assert envelope["algorithm"] == signing.ALG_KMS
        assert envelope["signed_by"].endswith("fsi-model-risk-approver/alice")
        assert (tmp_path / "data" / "approved_models.json.sig").read_bytes() == before
        signing.verify(signing.PURPOSE_REGISTRY, reg.read_bytes(), envelope,
                       kms_client=kms, require_kms=True)

    def test_sign_registry_local_dev_writes_only_sig(self, tmp_path, no_boto3):
        reg = _registry_copy(tmp_path, with_sig=False)
        tool = _load_sign_registry()
        assert tool.main(["--local-dev", "--registry", str(reg)]) == 0
        assert not (tmp_path / "data" / "approved_models.json.kms.sig").exists()
        assert model_assurance.load_verified_registry(str(reg))["approved_models"]

    def test_sign_registry_local_dev_refused_in_runtime(self, tmp_path, monkeypatch):
        reg = _registry_copy(tmp_path, with_sig=False)
        tool = _load_sign_registry()
        monkeypatch.setattr(signing.os.path, "isdir", lambda p: p == "/var/task")
        assert tool.main(["--local-dev", "--registry", str(reg)]) == 1
        assert not (tmp_path / "data" / "approved_models.json.sig").exists()

    def test_sign_registry_requires_exactly_one_mode(self):
        tool = _load_sign_registry()
        for argv in ([], ["--kms", "--local-dev"]):
            with pytest.raises(SystemExit) as info:
                tool.main(argv)
            assert info.value.code == 2

    def test_console_loader_never_builds_a_kms_client(self, tmp_path, no_boto3):
        assert model_assurance.load_verified_registry()["approved_models"]
        reg = _registry_copy(tmp_path)
        (tmp_path / "data" / "approved_models.json.sig").write_text(
            json.dumps(_kms_envelope(payload=reg.read_bytes(), version="2026-Q3")), encoding="utf-8")
        with pytest.raises(signing.SignatureVerificationUnavailableError, match="not verifiable in console"):
            model_assurance.load_verified_registry(str(reg))


class TestComplianceRegistryCache:
    @pytest.fixture
    def handler(self, monkeypatch):
        import lambdas.compliance_agent.handler as h
        monkeypatch.setattr(h, "GUARDRAIL_ID", "gr")
        monkeypatch.setattr(h, "GUARDRAIL_VERSION", "1")
        monkeypatch.setattr(h, "_VERIFIED_REGISTRY_CACHE", {})
        return h

    @staticmethod
    def _call(h, client):
        return h.invoke_bedrock(client, [(h.TRUSTED, "i"), (h.UNTRUSTED, "d")], "system", "sar",
                                use_guardrail=True, model_id="us.anthropic.claude-sonnet-4-5-20250929-v1:0")

    @staticmethod
    def _client():
        client = MagicMock()
        client.converse.return_value = {"stopReason": "end_turn",
                                        "output": {"message": {"content": [{"text": "{}"}]}}}
        return client

    def test_tampered_registry_blocks_bedrock(self, handler, tmp_path, monkeypatch):
        reg = _registry_copy(tmp_path)
        data = json.loads(reg.read_text(encoding="utf-8"))
        data["approved_models"].append({"model_id": "us.meta.llama3-3-70b-instruct-v1:0", "status": "approved"})
        reg.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(model_assurance, "DEFAULT_REGISTRY_PATH", str(reg))
        client = self._client()
        with pytest.raises(handler.UnapprovedModelError, match="signature invalid"):
            self._call(handler, client)
        client.converse.assert_not_called()

    def test_unavailable_is_not_cached_and_success_is(self, handler, monkeypatch):
        real = model_assurance.verified_registry_bytes
        calls = []

        def flaky(path, **kwargs):
            calls.append(path)
            if len(calls) == 1:
                raise signing.SignatureVerificationUnavailableError("KMS throttled")
            return real(path, **kwargs)

        monkeypatch.setattr(model_assurance, "verified_registry_bytes", flaky)
        client = self._client()
        with pytest.raises(handler.UnapprovedModelError, match="could not be verified"):
            self._call(handler, client)
        client.converse.assert_not_called()
        self._call(handler, client)          # re-verified, proceeds
        self._call(handler, client)          # cached: no further verification
        assert len(calls) == 2
        assert client.converse.call_count == 2
