"""
No keyed txn_ref and no PAN-filter rule id in any log line. The
detection handler and the PAN Lambda log the rejected index and counts only
(the rule that fired would be an evasion oracle for anyone reading the logs);
the audit item remains the only sink of the keyed ref and the rule.
"""
import importlib.util
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from _detection_fixtures import P, capture_audit, main_item, ring_txns  # noqa: E402

_LEAK = re.compile(r"[0-9a-f]{64}|txn_ref")
# Every rule id filter_transactions can report, plus the field name.
_RULE_ID = re.compile(r"\b(W1|X[1-5]|MALFORMED)\b|rule")

PAN_TXNS = [
    {"txn_id": "p1", "card": P},
    {"txn_id": "p2", "card": "4532-0151-1283-0366"},
    {"txn_id": "p3", "sender_id": "acc-45320151", "receiver_id": "acc-12830366"},
]


def _all_log_text(caplog):
    return "\n".join(r.getMessage() for r in caplog.records) + "\n" + caplog.text


def test_detection_handler_logs_no_txn_ref(monkeypatch, caplog):
    items = capture_audit(monkeypatch, h)
    with caplog.at_level("DEBUG"):
        out = h.handler({"mode": "cpu", "transactions_inline": ring_txns() + PAN_TXNS})
    assert out["pan_rejected_count"] == 3
    text = _all_log_text(caplog)
    assert _LEAK.search(text) is None
    assert _RULE_ID.search(text) is None
    assert len([m for m in caplog.messages
                if re.fullmatch(r"  Rejected txn index=\d+", m)]) == 3
    assert "Rejected 3 transactions containing PAN data" in caplog.messages
    refs = main_item(items, out["detection_id"])["pan_rejection_refs"]
    assert len(refs) == 3 and all(re.fullmatch(r"[0-9a-f]{64}", r["txn_ref"]) for r in refs)
    for ref in refs:
        assert ref["txn_ref"] not in text


def test_detection_audit_failure_log_has_no_item_content(monkeypatch, caplog):
    capture_audit(monkeypatch, h, fail_when=lambda item: True)
    with caplog.at_level("DEBUG"), pytest.raises(RuntimeError):
        h.handler({"mode": "cpu", "transactions_inline": PAN_TXNS})
    assert _LEAK.search(_all_log_text(caplog)) is None


@pytest.fixture
def pan_lambda(monkeypatch):
    import lambdas.pan_filter.pan_filter as pan_mod
    monkeypatch.setitem(sys.modules, "pan_filter", pan_mod)
    spec = importlib.util.spec_from_file_location(
        "_pan_handler_logs", os.path.join(PROJECT_ROOT, "lambdas", "pan_filter", "handler.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, pan_mod


def test_pan_lambda_logs_no_txn_ref(pan_lambda, caplog):
    mod, pan_mod = pan_lambda
    with caplog.at_level("DEBUG"):
        resp = mod.handler({"transactions": PAN_TXNS}, None)
    assert resp["rejected_count"] == 3
    text = _all_log_text(caplog)
    assert _LEAK.search(text) is None
    assert _RULE_ID.search(text) is None
    assert len([m for m in caplog.messages
                if re.fullmatch(r"PAN filter rejected index=\d+", m)]) == 3
    assert "PAN filter rejected 3/3 transactions" in caplog.messages
    # The refs exist server-side (computed by filter_transactions) but are
    # never logged.
    _, _, details = pan_mod.filter_transactions(PAN_TXNS)
    assert {d["rule"] for d in details} == {"W1", "X4"}  # the rules did fire
    for d in details:
        assert d["txn_ref"] not in text


def test_pan_lambda_malformed_element_logs_no_rule(pan_lambda, caplog):
    mod, _ = pan_lambda
    with caplog.at_level("DEBUG"):
        resp = mod.handler({"transactions": ["not-an-object", {"txn_id": "p1", "card": P}]}, None)
    assert resp["rejected_count"] == 2
    assert _RULE_ID.search(_all_log_text(caplog)) is None
