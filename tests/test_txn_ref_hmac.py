"""
Test: PAN filter txn_ref — HMAC-SHA256, full digest, keyed, with
the key read from AWS Secrets Manager.

txn_ref previously was `hashlib.sha256(raw_value).hexdigest()[:12]` — unsalted
(no secret) and truncated to 12 hex characters (48 bits), so it was
brute-forceable offline against any guessable/short raw_value space (e.g.
sequential txn_ids). It must be an HMAC-SHA256 over a per-deployment secret,
returning the full, untruncated 64-hex-char digest. The secret is no longer
plaintext runtime configuration (TXN_REF_HMAC_KEY is refused); it is fetched
from the Secrets Manager secret named by TXN_REF_HMAC_SECRET_ARN through the
``_fetch_secret_string`` seam, which these tests stub (no network, no AWS).
Parametrized across all 3 duplicated pan_filter.py copies.
"""
import hashlib
import logging
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.pan_filter.pan_filter as pan_filter_copy
import lambdas.detection_agent.pan_filter as detection_agent_pan_filter_copy
import lambdas.executor_agent.pan_filter.pan_filter as executor_agent_pan_filter_copy

_PAN_FILTER_MODULES = [
    pan_filter_copy,
    detection_agent_pan_filter_copy,
    executor_agent_pan_filter_copy,
]
_PAN_FILTER_MODULE_IDS = [
    "lambdas.pan_filter.pan_filter",
    "lambdas.detection_agent.pan_filter",
    "lambdas.executor_agent.pan_filter.pan_filter",
]

_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:txn-ref-AbCdEf"
_KEY_ONE = "k1-" + "a" * 61  # 64 bytes
_KEY_TWO = "k2-" + "b" * 61


@pytest.fixture
def reset_txn_ref_key_cache(monkeypatch):
    """Each module caches its resolved HMAC key in a module-level global —
    reset it before/after each test so env var changes actually take
    effect and don't leak between tests."""
    for mod in _PAN_FILTER_MODULES:
        monkeypatch.setattr(mod, "_resolved_txn_ref_key", None)
    yield
    for mod in _PAN_FILTER_MODULES:
        monkeypatch.setattr(mod, "_resolved_txn_ref_key", None)


def _stub_secret(monkeypatch, mod, secret=_KEY_ONE, arn=_ARN):
    """Point the module at ARN and stub the fetch seam; returns the call log."""
    calls = []

    def fake(requested_arn):
        calls.append(requested_arn)
        return secret

    monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", arn)
    monkeypatch.setattr(mod, "_fetch_secret_string", fake)
    return calls


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
class TestTxnRefHmac:
    def test_txn_ref_is_not_the_old_plain_truncated_sha256(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """Regression guard against reverting to the weak hash."""
        _stub_secret(monkeypatch, mod)
        value = "dirty-1"
        old_weak_value = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        new_value = mod._txn_ref(value)
        assert new_value != old_weak_value
        assert not new_value.startswith(old_weak_value)

    def test_txn_ref_is_full_64_hex_char_digest(self, mod, monkeypatch, reset_txn_ref_key_cache):
        _stub_secret(monkeypatch, mod)
        value = mod._txn_ref("some-txn-id")
        assert len(value) == 64
        assert all(c in "0123456789abcdef" for c in value)

    def test_txn_ref_changes_when_secret_changes(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """Proves txn_ref is actually keyed, not just a relabeled plain
        hash — the same input must produce a different digest under a
        different key."""
        _stub_secret(monkeypatch, mod, secret=_KEY_ONE)
        value_with_key_one = mod._txn_ref("same-input")

        monkeypatch.setattr(mod, "_resolved_txn_ref_key", None)
        _stub_secret(monkeypatch, mod, secret=_KEY_TWO)
        value_with_key_two = mod._txn_ref("same-input")

        assert value_with_key_one != value_with_key_two

    def test_different_inputs_produce_different_refs(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """No collision regression: two different txn_ids still produce
        different refs under the same key."""
        _stub_secret(monkeypatch, mod)
        assert mod._txn_ref("txn-id-a") != mod._txn_ref("txn-id-b")

    def test_same_input_and_key_is_deterministic(self, mod, monkeypatch, reset_txn_ref_key_cache):
        _stub_secret(monkeypatch, mod)
        assert mod._txn_ref("txn-id-a") == mod._txn_ref("txn-id-a")

    def test_filter_transactions_rejection_uses_hmac_txn_ref(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """End-to-end: filter_transactions's rejection_details txn_ref is
        the new keyed HMAC value, not the old weak hash."""
        _stub_secret(monkeypatch, mod)
        txns = [{"txn_id": "dirty-1", "card": "4532015112830366", "amount": 500}]
        clean, rejected, details = mod.filter_transactions(txns)
        assert rejected == 1
        assert details[0]["txn_ref"] == mod._txn_ref("dirty-1")
        old_weak_value = hashlib.sha256(b"dirty-1").hexdigest()[:12]
        assert details[0]["txn_ref"] != old_weak_value

    # ---- Secrets Manager key resolution ----

    def test_seam_called_once_across_two_calls(self, mod, monkeypatch, reset_txn_ref_key_cache):
        calls = _stub_secret(monkeypatch, mod)
        first = mod._txn_ref("x")
        second = mod._txn_ref("y")
        assert len(first) == len(second) == 64
        assert calls == [_ARN]

    def test_seam_exception_raises_and_is_not_cached(self, mod, monkeypatch, reset_txn_ref_key_cache, caplog):
        calls = []

        def boom(arn):
            calls.append(arn)
            raise ConnectionError("secret-material-should-not-be-logged")

        monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", _ARN)
        monkeypatch.setattr(mod, "_fetch_secret_string", boom)
        with caplog.at_level(logging.WARNING):
            with pytest.raises(RuntimeError, match="txn_ref HMAC key unavailable") as info:
                mod._txn_ref_key()
        assert isinstance(info.value.__cause__, ConnectionError)
        assert mod._resolved_txn_ref_key is None
        # Only the exception class name is logged, never its message.
        assert "ConnectionError" in caplog.text
        assert any(r.levelno == logging.WARNING and "ConnectionError" in r.getMessage()
                   for r in caplog.records)
        assert "secret-material-should-not-be-logged" not in caplog.text
        # Not cached: the next call retries the seam.
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert len(calls) == 2

    def test_failure_then_recovery(self, mod, monkeypatch, reset_txn_ref_key_cache):
        state = {"n": 0}

        def flaky(arn):
            state["n"] += 1
            if state["n"] == 1:
                raise TimeoutError("transient")
            return _KEY_ONE

        monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", _ARN)
        monkeypatch.setattr(mod, "_fetch_secret_string", flaky)
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert mod._txn_ref_key() == _KEY_ONE.encode("utf-8")

    def test_short_secret_raises(self, mod, monkeypatch, reset_txn_ref_key_cache):
        _stub_secret(monkeypatch, mod, secret="k" * 31)
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert mod._resolved_txn_ref_key is None

    def test_exactly_32_byte_secret_is_accepted(self, mod, monkeypatch, reset_txn_ref_key_cache):
        _stub_secret(monkeypatch, mod, secret="k" * 32)
        assert mod._txn_ref_key() == b"k" * 32

    def test_non_str_secret_raises(self, mod, monkeypatch, reset_txn_ref_key_cache):
        _stub_secret(monkeypatch, mod, secret=None)
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()

    def test_plaintext_key_env_is_refused_even_with_arn(self, mod, monkeypatch, reset_txn_ref_key_cache):
        calls = _stub_secret(monkeypatch, mod)
        monkeypatch.setenv("TXN_REF_HMAC_KEY", "legacy-plaintext-key")
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert calls == []

    def test_plaintext_key_env_is_refused_without_arn(self, mod, monkeypatch, reset_txn_ref_key_cache):
        monkeypatch.setenv("TXN_REF_HMAC_KEY", "legacy-plaintext-key")
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()

    def test_dev_flag_in_deployed_runtime_raises(self, mod, monkeypatch, reset_txn_ref_key_cache):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", "true")
        monkeypatch.setattr(mod, "_in_deployed_runtime", lambda: True)
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert mod._resolved_txn_ref_key is None

    def test_neither_arn_nor_flag_raises(self, mod, monkeypatch, reset_txn_ref_key_cache):
        monkeypatch.delenv("TXN_REF_HMAC_SECRET_ARN", raising=False)
        monkeypatch.delenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", raising=False)
        with pytest.raises(RuntimeError):
            mod._txn_ref("some-value")

    def test_non_true_flag_value_still_raises(self, mod, monkeypatch, reset_txn_ref_key_cache):
        monkeypatch.setenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", "1")
        with pytest.raises(RuntimeError):
            mod._txn_ref("some-value")

    def test_missing_key_raises_regardless_of_lambda_env(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """Fail-closed whether or not AWS_LAMBDA_FUNCTION_NAME is set."""
        monkeypatch.delenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", raising=False)
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "fsi-pan-filter")
        with pytest.raises(RuntimeError):
            mod._txn_ref("some-value")
        monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
        with pytest.raises(RuntimeError):
            mod._txn_ref("some-value")

    def test_flag_only_not_deployed_uses_dev_key(self, mod, monkeypatch, reset_txn_ref_key_cache, caplog):
        monkeypatch.delenv("TXN_REF_HMAC_SECRET_ARN", raising=False)
        monkeypatch.setenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", "TRUE")
        monkeypatch.setattr(mod, "_in_deployed_runtime", lambda: False)
        with caplog.at_level(logging.WARNING):
            value = mod._txn_ref("some-value")
        assert len(value) == 64
        assert mod._txn_ref_key() == mod._LOCAL_DEV_ONLY_TXN_REF_KEY
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    def test_arn_path_wins_over_dev_flag(self, mod, monkeypatch, reset_txn_ref_key_cache):
        calls = _stub_secret(monkeypatch, mod)
        monkeypatch.setenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", "true")
        assert mod._txn_ref_key() == _KEY_ONE.encode("utf-8")
        assert calls == [_ARN]

    @pytest.mark.parametrize(
        "bad_arn",
        [
            "txn-ref",
            "arn:aws:secretsmanager:us-east-1:123456789012",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:",
            " " + _ARN,
            _ARN + " ",
            "arn:aws:s3:::bucket",
        ],
        ids=["name-only", "partial", "empty-name", "leading-space", "trailing-space", "wrong-service"],
    )
    def test_bad_arn_raises_without_calling_seam(self, mod, monkeypatch, reset_txn_ref_key_cache, bad_arn):
        calls = _stub_secret(monkeypatch, mod, arn=bad_arn)
        with pytest.raises(RuntimeError):
            mod._txn_ref_key()
        assert calls == []

    def test_key_value_is_never_logged(self, mod, monkeypatch, reset_txn_ref_key_cache, caplog):
        _stub_secret(monkeypatch, mod)
        with caplog.at_level(logging.DEBUG):
            mod._txn_ref_key()
        assert _KEY_ONE not in caplog.text

    def test_fetch_secret_string_with_botocore_stubber(self, mod, monkeypatch, reset_txn_ref_key_cache):
        """The real _fetch_secret_string against a Stubber-wrapped client;
        boto3.client is patched, so no network is used."""
        import boto3
        from botocore.stub import Stubber

        client = boto3.client(
            "secretsmanager",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        built = []

        def fake_client(service, **kwargs):
            built.append((service, kwargs))
            return client

        monkeypatch.setattr(boto3, "client", fake_client)
        with Stubber(client) as stubber:
            stubber.add_response(
                "get_secret_value",
                {
                    "ARN": _ARN,
                    "Name": "txn-ref",
                    "VersionId": "a" * 32,
                    "SecretString": "k" * 64,
                },
                {"SecretId": _ARN},
            )
            monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", _ARN)
            assert mod._txn_ref_key() == b"k" * 64
            stubber.assert_no_pending_responses()

        assert built[0][0] == "secretsmanager"
        assert built[0][1]["region_name"] == "us-east-1"
        cfg = built[0][1]["config"]
        assert cfg.connect_timeout == 2
        assert cfg.read_timeout == 2
        assert cfg.retries == {"max_attempts": 2, "mode": "standard"}
