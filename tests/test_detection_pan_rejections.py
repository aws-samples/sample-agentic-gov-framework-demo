"""
Detection handler — PAN rejection surfacing and entry validation
(handler part).

Invoker-facing output carries pan_rejected_indices only (sorted ints ≤ 500,
plus pan_rejected_indices_truncated; no rule). The keyed txn_ref
goes only to the audit item's pan_rejection_refs attribute, never to the
WARNING log or the invoker.
"""
import json
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.detection_agent.handler as h

P = "4532015112830366"
_HEX64 = re.compile(r"[0-9a-f]{64}")


@pytest.fixture(autouse=True)
def _fast_detection(monkeypatch):
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    monkeypatch.setattr(h, "detect_fraud_cpu", lambda txns: ([], 0.0, []))
    assert not os.path.isdir("/var/task")


class _FakeTable:
    def __init__(self, items):
        self._items = items

    def put_item(self, Item):
        self._items.append(Item)


class _FakeResource:
    def __init__(self, items):
        self._items = items

    def Table(self, name):
        return _FakeTable(self._items)


@pytest.fixture
def audit_items(monkeypatch):
    items = []
    monkeypatch.setenv("WRITE_AUDIT", "true")
    monkeypatch.setattr(h.boto3, "resource", lambda *a, **k: _FakeResource(items))
    return items


def _clean_txn(i=0):
    return {"txn_id": f"c{i}", "sender_id": "a1", "receiver_id": "a2", "amount": 10.0,
            "timestamp": "2026-01-01T00:00:00"}


def _pan_txn(i=0):
    return {"txn_id": f"p{i}", "card": P}


def _normal_event():
    return {"mode": "cpu", "transactions_inline": [_clean_txn(), _pan_txn()]}


def _all_rejected_event():
    return {"mode": "cpu", "transactions_inline": [_pan_txn()]}


@pytest.mark.parametrize("event_fn,index", [(_normal_event, 1), (_all_rejected_event, 0)],
                         ids=["normal", "all-rejected"])
def test_ac14_pan_rejections_index_rule(event_fn, index):
    out = h.handler(event_fn())
    assert out["pan_rejected_count"] == 1
    assert out["pan_rejected_indices"] == [index]
    assert "pan_rejections" not in out
    assert "rule" not in json.dumps(out)
    assert out["pan_rejected_indices_truncated"] is False


def test_ac14_pan_rejections_capped_at_500():
    out = h.handler({"mode": "cpu", "transactions_inline": [_pan_txn(i) for i in range(501)]})
    assert out["pan_rejected_count"] == 501
    assert out["pan_rejected_indices"] == list(range(500))
    assert out["pan_rejected_indices_truncated"] is True


def test_no_rejections_no_keys():
    out = h.handler({"mode": "cpu", "transactions_inline": [_clean_txn()]})
    assert "pan_rejected_indices" not in out
    assert "pan_rejected_indices_truncated" not in out


@pytest.mark.parametrize("event_fn", [_normal_event, _all_rejected_event],
                         ids=["normal", "all-rejected"])
def test_ac20_output_has_no_txn_ref(event_fn, caplog):
    with caplog.at_level("WARNING"):
        out = h.handler(event_fn())
    assert _HEX64.search(json.dumps(out)) is None
    assert re.search(r"Rejected txn index=\d+$", caplog.text, re.MULTILINE)
    assert "rule" not in caplog.text and "W1" not in caplog.text
    assert re.search(r"[0-9a-f]{64}|txn_ref", caplog.text) is None


@pytest.mark.parametrize("event_fn,index", [(_normal_event, 1), (_all_rejected_event, 0)],
                         ids=["normal", "all-rejected"])
def test_ac20_audit_item_has_refs(event_fn, index, audit_items):
    out = h.handler(event_fn())
    assert len(audit_items) == 1
    refs = audit_items[0]["pan_rejection_refs"]
    assert len(refs) == 1
    assert refs[0]["index"] == index
    assert refs[0]["rule"] == "W1"
    assert _HEX64.fullmatch(refs[0]["txn_ref"])
    assert "pan_rejection_refs" not in out
    assert _HEX64.search(json.dumps(out)) is None


def test_ac20_audit_refs_capped(audit_items):
    out = h.handler({"mode": "cpu", "transactions_inline": [_pan_txn(i) for i in range(501)]})
    # Refs beyond the inline cap are durable in a chunk item written before
    # the main item.
    chunk, main = audit_items
    assert main["detection_id"] == out["detection_id"]
    assert len(main["pan_rejection_refs"]) == 500
    assert main["pan_rejection_ref_chunks"] == 1
    assert chunk["parent_detection_id"] == out["detection_id"]
    assert len(chunk["refs"]) == 1
    assert "pan_rejection_refs" not in out


def test_audit_write_failure_reraised(monkeypatch):
    monkeypatch.setenv("WRITE_AUDIT", "true")

    def boom(*a, **k):
        raise RuntimeError("ddb down")

    monkeypatch.setattr(h.boto3, "resource", boom)
    with pytest.raises(RuntimeError, match="ddb down"):
        h.handler(_all_rejected_event())


@pytest.mark.parametrize("bad", ["abc", {"a": 1}, None, ("x",)],
                         ids=["str", "dict", "none", "tuple"])
def test_inline_non_list_raises_before_filter(bad, monkeypatch):
    calls = []
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="^transactions_inline must be a JSON array$"):
        h.handler({"mode": "cpu", "transactions_inline": bad})
    assert calls == []


def test_inline_over_cap_raises(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "MAX_TRANSACTIONS", 2)
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="maximum of 2"):
        h.handler({"mode": "cpu", "transactions_inline": [_clean_txn(i) for i in range(3)]})
    assert calls == []


def test_file_source_over_cap_raises(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "MAX_TRANSACTIONS", 2)
    monkeypatch.setattr(h, "load_transactions", lambda f: [_clean_txn(i) for i in range(3)])
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="maximum of 2"):
        h.handler({"mode": "cpu"})
    assert calls == []


# Non-dict event rejected with ValueError before any work.
@pytest.mark.parametrize("bad", ["abc", [], None, 42], ids=["str", "list", "none", "int"])
def test_non_dict_event_raises_value_error(bad, monkeypatch):
    calls = []
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="^event must be a JSON object$"):
        h.handler(bad)
    assert calls == []


# Cumulative character budget on transactions_inline.
def _serialized_len(txns):
    return len(json.dumps(txns, ensure_ascii=False, separators=(",", ":")))


def test_inline_over_char_budget_raises_before_filter(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "MAX_INLINE_BATCH_CHARS", 100)
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="maximum serialized size of 100 characters"):
        h.handler({"mode": "cpu", "transactions_inline": [{"memo": "a" * 200}]})
    assert calls == []


def test_inline_char_budget_real_constant_rejects_oversized_leaf(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    assert h.MAX_INLINE_BATCH_CHARS == 4_194_304
    with pytest.raises(ValueError, match="maximum serialized size of 4194304 characters"):
        h.handler({"mode": "cpu", "transactions_inline": [{"memo": "a" * (4 * 1_048_576)}]})
    assert calls == []


def test_inline_char_budget_boundary_allowed(monkeypatch):
    txns = [_clean_txn()]
    monkeypatch.setattr(h, "MAX_INLINE_BATCH_CHARS", _serialized_len(txns))
    out = h.handler({"mode": "cpu", "transactions_inline": txns})
    assert "error" not in out
    assert out["transaction_count"] == 1


def test_inline_unserializable_raises_before_filter(monkeypatch):
    calls = []
    monkeypatch.setattr(h, "filter_transactions", lambda t: calls.append(t))
    with pytest.raises(ValueError, match="^transactions_inline must be JSON-serializable$"):
        h.handler({"mode": "cpu", "transactions_inline": [{"x": object()}]})
    assert calls == []


def test_file_source_not_subject_to_inline_char_budget(monkeypatch):
    monkeypatch.setattr(h, "MAX_INLINE_BATCH_CHARS", 10)
    monkeypatch.setattr(h, "load_transactions", lambda f: [_clean_txn(i) for i in range(3)])
    out = h.handler({"mode": "cpu"})
    assert "error" not in out
    assert out["transaction_count"] == 3


# Per-rejection log lines capped, one aggregate line.
def test_rejection_log_lines_capped_with_aggregate(monkeypatch, caplog):
    monkeypatch.setattr(h, "PAN_REJECTIONS_CAP", 3)
    with caplog.at_level("WARNING"):
        out = h.handler({"mode": "cpu", "transactions_inline": [_pan_txn(i) for i in range(5)]})
    per_txn = [m for m in caplog.messages if "Rejected txn index=" in m]
    aggregate = [m for m in caplog.messages if "further rejection(s) not logged" in m]
    assert len(per_txn) == 3
    assert aggregate == ["PAN filter: 2 further rejection(s) not logged individually (cap 3)"]
    assert out["pan_rejected_count"] == 5
    # invoker output capped at PAN_REJECTIONS_CAP
    assert len(out["pan_rejected_indices"]) == 3
    assert out["pan_rejected_indices_truncated"] is True


def test_rejection_logs_not_aggregated_under_cap(caplog):
    with caplog.at_level("WARNING"):
        h.handler({"mode": "cpu", "transactions_inline": [_pan_txn(i) for i in range(2)]})
    assert len([m for m in caplog.messages if "Rejected txn index=" in m]) == 2
    assert not any("further rejection(s)" in m for m in caplog.messages)
