"""
PAN filter — entry validation and robustness.

Module part, parametrized over all three module copies:
non-list input raises TypeError before any HMAC work, and no element (lone
surrogates, non-dict values) can abort a batch.
"""
import os
import re
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

P = "4532015112830366"
_HEX64 = re.compile(r"[0-9a-f]{64}")


@pytest.fixture
def key_calls(monkeypatch):
    """Count calls to every copy's _txn_ref_key seam."""
    calls = []
    for mod in _PAN_FILTER_MODULES:
        original = mod._txn_ref_key

        def counted(_orig=original):
            calls.append(1)
            return _orig()

        monkeypatch.setattr(mod, "_txn_ref_key", counted)
    return calls


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_e01_lone_surrogate_txn_id_is_w1_rejection(mod):
    result = mod.filter_transactions([{"txn_id": "\ud800" + P}])
    clean, rejected, details = result
    assert clean == []
    assert rejected == 1
    assert len(details) == 1
    assert _HEX64.fullmatch(details[0]["txn_ref"])
    assert details[0]["rule"] == "W1"
    assert details[0]["index"] == 0


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_e02_lone_surrogate_element_is_malformed(mod):
    clean, rejected, details = mod.filter_transactions(["\ud800"])
    assert clean == []
    assert rejected == 1
    assert details[0]["rule"] == "MALFORMED"
    assert details[0]["reason"] == "Malformed transaction element (not an object) — rejected"
    assert _HEX64.fullmatch(details[0]["txn_ref"])


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
@pytest.mark.parametrize("bad", [P, {}, None, ("a",)], ids=["str", "dict", "none", "tuple"])
def test_e04_non_list_raises_before_hmac(mod, bad, key_calls):
    with pytest.raises(TypeError, match="transactions must be a list"):
        mod.filter_transactions(bad)
    assert key_calls == []


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_list_subclass_rejected(mod, key_calls):
    class _L(list):
        pass

    with pytest.raises(TypeError):
        mod.filter_transactions(_L([{"a": "b"}]))
    assert key_calls == []


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_empty_list_returns_without_key(mod, key_calls):
    assert mod.filter_transactions([]) == ([], 0, [])
    assert key_calls == []


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_key_resolved_once_per_call(mod, key_calls):
    mod.filter_transactions([{"txn_id": "clean", "amount": 1}])
    assert key_calls == [1]


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_contains_full_pan_rejects_non_str(mod):
    with pytest.raises(TypeError):
        mod.contains_full_pan(123)
    assert mod.contains_full_pan(None) is False
    assert mod.contains_full_pan("") is False


_GOOD_ARN = "arn:aws:secretsmanager:us-east-1:123456789012:secret:txn-ref-AbCdEf"


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
@pytest.mark.parametrize(
    "bad_arn",
    [_GOOD_ARN + "\n", _GOOD_ARN.replace("123456789012", "12345678901\u0661")],
    ids=["trailing-newline", "non-ascii-digit-account"],
)
def test_malformed_arn_rejected_without_calling_seam(mod, bad_arn, monkeypatch):
    """re.ASCII + fullmatch, so a trailing newline and a non-ASCII
    digit in the account field are configuration errors; the seam is not called."""
    calls = []
    monkeypatch.setattr(mod, "_resolved_txn_ref_key", None)
    monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", bad_arn)
    monkeypatch.setattr(mod, "_fetch_secret_string", lambda arn: calls.append(arn) or "k" * 64)
    with pytest.raises(RuntimeError):
        mod._txn_ref_key()
    assert calls == []


def test_module_imports_without_boto3(monkeypatch):
    """NFR2: importing and detecting never needs boto3."""
    import importlib.util

    monkeypatch.setitem(sys.modules, "boto3", None)
    paths = [
        os.path.join(PROJECT_ROOT, "lambdas", "pan_filter", "pan_filter.py"),
        os.path.join(PROJECT_ROOT, "lambdas", "detection_agent", "pan_filter.py"),
        os.path.join(PROJECT_ROOT, "lambdas", "executor_agent", "pan_filter", "pan_filter.py"),
    ]
    for n, path in enumerate(paths):
        spec = importlib.util.spec_from_file_location(f"_pan_filter_noboto3_{n}", path)
        fresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fresh)
        assert fresh.contains_full_pan(P) is True
        # The key fetch is the only boto3 user and fails closed without it.
        monkeypatch.setenv("TXN_REF_HMAC_SECRET_ARN", _GOOD_ARN)
        with pytest.raises(RuntimeError, match="unavailable"):
            fresh._txn_ref_key()


@pytest.mark.parametrize("mod", _PAN_FILTER_MODULES, ids=_PAN_FILTER_MODULE_IDS)
def test_detail_shape_and_index(mod):
    txns = [{"txn_id": "ok"}, "bare", {"txn_id": "dirty", "card": P}]
    clean, rejected, details = mod.filter_transactions(txns)
    assert clean == [{"txn_id": "ok"}]
    assert rejected == 2
    assert [list(d) for d in details] == [["index", "txn_ref", "reason", "rule"]] * 2
    assert [(d["index"], d["rule"]) for d in details] == [(1, "MALFORMED"), (2, "W1")]
    assert details[1]["reason"] == "Full PAN detected — PCI-DSS v4.0 section 3.4 violation"


# ---------------------------------------------------------------------------
# Lambda handler entry points.
# Both handler copies are loaded with `pan_filter` bound to the matching
# module copy, so `from pan_filter import ...` resolves correctly.
# ---------------------------------------------------------------------------
import importlib.util
import json

_HANDLER_COPIES = [
    ("lambdas/pan_filter/handler.py", pan_filter_copy),
    ("lambdas/executor_agent/pan_filter/handler.py", executor_agent_pan_filter_copy),
]
_HANDLER_IDS = ["lambdas.pan_filter.handler", "lambdas.executor_agent.pan_filter.handler"]
_W1_REASON = "Full PAN detected — PCI-DSS v4.0 section 3.4 violation"


@pytest.fixture(params=_HANDLER_COPIES, ids=_HANDLER_IDS)
def pan_handler(request, monkeypatch):
    rel_path, pan_mod = request.param
    monkeypatch.setitem(sys.modules, "pan_filter", pan_mod)
    name = "_pan_handler_under_test_" + rel_path.replace("/", "_").replace(".", "_")
    spec = importlib.util.spec_from_file_location(name, os.path.join(PROJECT_ROOT, rel_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.filter_transactions is pan_mod.filter_transactions
    return mod


@pytest.fixture
def filter_spy(pan_handler, monkeypatch):
    calls = []
    original = pan_handler.filter_transactions

    def spy(txns):
        calls.append(txns)
        return original(txns)

    monkeypatch.setattr(pan_handler, "filter_transactions", spy)
    return calls


@pytest.mark.parametrize("event", [P, [], None, 42], ids=["str", "list", "none", "int"])
def test_e03_handler_non_dict_event(pan_handler, event):
    assert pan_handler.handler(event, None) == {"error": "event must be a JSON object"}


def test_handler_text_non_str(pan_handler):
    assert pan_handler.handler({"text": 5}, None) == {"error": "text must be a string"}


def test_ac23_text_too_long_skips_scan(pan_handler, monkeypatch):
    calls = []
    monkeypatch.setattr(pan_handler, "contains_full_pan", lambda t: calls.append(t) or False)
    assert pan_handler.handler({"text": "a" * 1_048_577}, None) == {"error": "text too long"}
    assert calls == []
    resp = pan_handler.handler({"text": "a" * 1_048_576}, None)
    assert resp["contains_pan"] is False
    assert len(calls) == 1


@pytest.mark.parametrize(
    "event",
    [{}, {"transactions": None}, {"transactions": []}],
    ids=["missing", "null", "empty"],
)
def test_ac10_batch_usage_error(pan_handler, filter_spy, event):
    assert pan_handler.handler(event, None) == pan_handler.USAGE
    assert pan_handler.USAGE == {
        "error": "No transactions or text provided",
        "usage": "Pass {\"transactions\": [...]} or {\"text\": \"...\"}",
    }
    assert filter_spy == []


@pytest.mark.parametrize("bad", [{}, "", 0, False], ids=["dict", "empty-str", "zero", "false"])
def test_ac10_batch_non_list_is_array_error(pan_handler, filter_spy, bad):
    assert pan_handler.handler({"transactions": bad}, None) == {
        "error": "transactions must be a JSON array"
    }
    assert filter_spy == []


def test_ac10_batch_cap(pan_handler, filter_spy, monkeypatch):
    monkeypatch.setenv("MAX_TRANSACTIONS", "2")
    resp = pan_handler.handler({"transactions": [{}, {}, {}]}, None)
    assert resp == {"error": "transactions exceeds the maximum of 2"}
    assert filter_spy == []


def test_ac20_batch_response_has_no_txn_ref(pan_handler, caplog):
    with caplog.at_level("WARNING"):
        resp = pan_handler.handler({"transactions": [{"txn_id": "t1", "card": P}]}, None)
    assert resp["rejected_indices"] == [0]
    assert set(resp) == {"total_input", "allowed_count", "rejected_count", "rejected_indices"}
    assert resp["rejected_count"] == 1
    assert resp["allowed_count"] == 0
    assert "clean_transactions" not in resp
    assert re.search(r"[0-9a-f]{64}", json.dumps(resp)) is None
    assert re.search(r"index=0$", caplog.text, re.MULTILINE)
    assert "rule" not in caplog.text and "W1" not in caplog.text
    assert re.search(r"[0-9a-f]{64}|txn_ref", caplog.text) is None


# ---------------------------------------------------------------------------
# Cumulative character budget for batch mode.
# ---------------------------------------------------------------------------
def _serialized_len(txns):
    return len(json.dumps(txns, ensure_ascii=False, separators=(",", ":")))


def test_batch_char_budget_value(pan_handler):
    assert pan_handler.MAX_BATCH_CHARS == 4 * pan_handler.MAX_TEXT_CHARS == 4_194_304


def test_batch_char_budget_rejected_before_filter(pan_handler, filter_spy, monkeypatch):
    monkeypatch.setattr(pan_handler, "MAX_BATCH_CHARS", 100)
    txns = [{"memo": "a" * 200}]
    assert _serialized_len(txns) > 100
    assert pan_handler.handler({"transactions": txns}, None) == {
        "error": "transactions exceeds the maximum serialized size of 100 characters"
    }
    assert filter_spy == []


def test_batch_char_budget_real_constant_rejects_oversized_single_leaf(pan_handler, filter_spy):
    txns = [{"memo": "a" * (4 * 1_048_576)}]
    resp = pan_handler.handler({"transactions": txns}, None)
    assert resp == {
        "error": "transactions exceeds the maximum serialized size of 4194304 characters"
    }
    assert filter_spy == []


def test_batch_char_budget_boundary_allowed(pan_handler, filter_spy, monkeypatch):
    txns = [{"txn_id": "t1", "memo": "hello"}]
    monkeypatch.setattr(pan_handler, "MAX_BATCH_CHARS", _serialized_len(txns))
    resp = pan_handler.handler({"transactions": txns}, None)
    assert resp["allowed_count"] == 1
    assert len(filter_spy) == 1


def test_batch_unserializable_rejected(pan_handler, filter_spy):
    nested = []
    for _ in range(100_000):
        nested = [nested]
    assert pan_handler.handler({"transactions": [nested]}, None) == {
        "error": "transactions must be JSON-serializable"
    }
    assert filter_spy == []


# ---------------------------------------------------------------------------
# Per-rejection log lines capped, one aggregate line.
# ---------------------------------------------------------------------------
def test_rejection_log_lines_capped_with_aggregate(pan_handler, monkeypatch, caplog):
    monkeypatch.setattr(pan_handler, "PAN_REJECTIONS_CAP", 3)
    txns = [{"txn_id": f"p{i}", "card": P} for i in range(5)]
    with caplog.at_level("WARNING"):
        resp = pan_handler.handler({"transactions": txns}, None)
    per_txn = [r for r in caplog.messages if "rejected index=" in r]
    aggregate = [r for r in caplog.messages if "further rejection(s) not logged" in r]
    assert len(per_txn) == 3
    assert aggregate == ["PAN filter: 2 further rejection(s) not logged individually (cap 3)"]
    assert resp["rejected_count"] == 5
    assert len(resp["rejected_indices"]) == 5  # response not capped


def test_rejection_logs_not_aggregated_under_cap(pan_handler, caplog):
    txns = [{"txn_id": f"p{i}", "card": P} for i in range(3)]
    with caplog.at_level("WARNING"):
        pan_handler.handler({"transactions": txns}, None)
    assert len([r for r in caplog.messages if "rejected index=" in r]) == 3
    assert not any("further rejection(s)" in r for r in caplog.messages)
    assert pan_handler.PAN_REJECTIONS_CAP == 500
