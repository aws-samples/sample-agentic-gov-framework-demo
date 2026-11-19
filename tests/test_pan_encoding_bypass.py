"""
PAN encodings and the per-rule oracle.

Each case runs the full detection handler() in cpu mode with the audit write
captured, and asserts that either the carrier transaction is rejected or no
13-19-digit substring of P reaches any sink (output, audit items, logs,
SAR/challenger prompt text), and that no invoker-facing response carries a
rule, reason or keyed txn_ref.
"""
import importlib.util
import json
import os
import re
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from _detection_fixtures import (  # noqa: E402
    P, P_SUBSTRINGS, capture_audit, keys_recursive, load_detection_shim, main_item, post, ring_txns,
)

_HEX64 = re.compile(r"[0-9a-f]{64}")
_TS = "2026-01-01T00:01:00"


def _load_sar_prompts():
    spec = importlib.util.spec_from_file_location(
        "_sar_prompts_encoding", os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "sar_prompts.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sar_prompts = _load_sar_prompts()


@pytest.fixture(autouse=True)
def _no_var_task():
    assert not os.path.isdir("/var/task")


def _valid(**extra):
    txn = {"txn_id": "case-1", "sender_id": "acc-x1", "receiver_id": "acc-x2",
           "amount": 50.0, "timestamp": _TS, "merchant_category": "retail"}
    txn.update(extra)
    return txn


def _run(monkeypatch, caplog, case_txns):
    items = capture_audit(monkeypatch, h)
    batch = ring_txns() + list(case_txns)
    with caplog.at_level("DEBUG"):
        out = h.handler({"mode": "cpu", "transactions_inline": batch})
    return out, items


def _prompt_texts(out):
    texts = []
    for cluster in out["flagged_clusters"]:
        enriched = sar_prompts.enrich_cluster(cluster)
        texts.append(sar_prompts.build_sar_prompt(enriched))
        texts.append(sar_prompts.build_challenger_prompt(enriched))
    return texts


def _assert_no_pan_in_sinks(out, items, caplog):
    sinks = [json.dumps(out, default=str), json.dumps(items, default=str), caplog.text]
    sinks += _prompt_texts(out)
    for sink in sinks:
        for sub in P_SUBSTRINGS:
            assert sub not in sink


def _assert_no_oracle(out):
    keys = set(keys_recursive(out))
    assert "rule" not in keys and "reason" not in keys
    assert "txn_ref" not in json.dumps(out)
    assert _HEX64.search(json.dumps(out)) is None


def _case_indices(n_case):
    base = len(ring_txns())
    return list(range(base, base + n_case))


# (id, case transactions, expectation) — expectation is "rejected" (every
# case txn rejected by the PAN filter or the schema), "dropped:<n>" (accepted
# with n non-schema fields dropped) or "invariant" (residual: only the sink
# invariant is asserted).
_FS = "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"
_ARABIC = "".join(chr(0x0660 + int(d)) for d in P)
_MATH_BOLD = "".join(chr(0x1D7CE + int(d)) for d in P)
CASES = [
    ("split-across-ids", [_valid(sender_id="acc-45320151", receiver_id="acc-12830366")], "rejected"),
    ("r10c-1-3-digit-fields", [_valid(a="453", b="201", c="511", d="283", e="036", f="6")], "dropped:6"),
    ("r2a-padding", [_valid(memo1="9945320151", memo2="12830366")], "rejected-or-dropped:2"),
    ("r10d-float-carrier", [_valid(x=45320151.0, y="12830366")], "rejected-or-dropped:2"),
    ("letter-interleaved-txn-and-sender",
     [_valid(txn_id="t-4532a0151", sender_id="b1283x0366")], "invariant"),
    ("within-record-two-id-residual",
     [_valid(sender_id="a4532x0151", receiver_id="b1283y0366")], "invariant"),
    ("nested-leaves", [_valid(meta={"p1": "4532", "p2": ["0151", "1283"], "p3": {"q": "0366"}})],
     "rejected-or-dropped:1"),
    ("sep-dash", [_valid(sender_id="4532-0151-1283-0366")], "rejected"),
    ("sep-space", [_valid(sender_id="4532 0151 1283 0366")], "rejected"),
    ("sep-zwsp", [_valid(sender_id="4532\u200b0151\u200b1283\u200b0366")], "rejected"),
    ("sep-lm", [_valid(sender_id="4532\u30fc0151\u30fc1283\u30fc0366")], "rejected"),
    ("sep-hangul", [_valid(sender_id="4532\u318d0151\u318d1283\u318d0366")], "rejected"),
    ("fullwidth-txn-id", [_valid(txn_id=_FS)], "rejected"),
    ("arabic-indic", [_valid(sender_id=_ARABIC)], "rejected"),
    ("math-bold", [_valid(sender_id=_MATH_BOLD)], "rejected"),
    ("r3-two-letters-schema", [_valid(sender_id="4532a0151b12830366")], "rejected"),
    ("unicode-hyphen-id", [_valid(sender_id="acc\u2010001")], "rejected"),
    ("amount-precision-carrier", [_valid(amount=4532015.112830366)], "rejected"),
    ("cross-record-residual",
     [_valid(txn_id="cr-1", sender_id="45320151", receiver_id="acc-y1"),
      _valid(txn_id="cr-2", sender_id="acc-y1", receiver_id="12830366")], "invariant"),
]


@pytest.mark.parametrize("case_txns,expect", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_encoding_case_never_reaches_a_sink(monkeypatch, caplog, case_txns, expect):
    out, items = _run(monkeypatch, caplog, case_txns)
    _assert_no_pan_in_sinks(out, items, caplog)
    _assert_no_oracle(out)
    # The ring itself always survives: the base batch is valid.
    assert len(out["flagged_clusters"]) == 1
    n_case = len(case_txns)
    rejected = out.get("pan_rejected_count", 0) + out["schema_rejected_count"]
    if expect == "rejected":
        assert rejected == n_case
        assert out["transaction_count"] == len(ring_txns())
    elif expect.startswith("dropped:"):
        assert rejected == 0
        assert out["fields_dropped"] == int(expect.split(":")[1])
    elif expect.startswith("rejected-or-dropped:"):
        assert rejected == n_case or out["fields_dropped"] == int(expect.split(":")[1])
    else:
        # Documented residual: accepted, but every
        # surviving identifier carries at most 12 digits.
        assert rejected == 0
        for sink in [json.dumps(out)] + _prompt_texts(out):
            assert re.search(r"\d{13,}", sink) is None
        for item in items:
            for cluster in item.get("flagged_clusters", []):
                for account in cluster["accounts"]:
                    assert len(re.sub(r"\D", "", account)) <= 12


def test_mixed_batch_indices_only(monkeypatch, caplog):
    batch = [_valid(txn_id="c0"), {"txn_id": "p1", "card": P},
             _valid(txn_id="c2"), {"txn_id": "p3", "card": "4532-0151-1283-0366"}]
    items = capture_audit(monkeypatch, h)
    out = h.handler({"mode": "cpu", "transactions_inline": batch})
    assert out["pan_rejected_indices"] == [1, 3]
    assert out["pan_rejected_count"] == 2
    _assert_no_oracle(out)
    # The server-side sink still carries rule + txn_ref.
    refs = main_item(items, out["detection_id"])["pan_rejection_refs"]
    assert [r["index"] for r in refs] == [1, 3]
    assert all(r["rule"] == "W1" and _HEX64.fullmatch(r["txn_ref"]) for r in refs)


def test_pan_lambda_batch_response_keys_exact(monkeypatch):
    import lambdas.pan_filter.pan_filter as pan_mod
    monkeypatch.setitem(sys.modules, "pan_filter", pan_mod)
    spec = importlib.util.spec_from_file_location(
        "_pan_handler_encoding", os.path.join(PROJECT_ROOT, "lambdas", "pan_filter", "handler.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    resp = mod.handler({"transactions": [_valid(), {"txn_id": "p", "card": P}]}, None)
    assert set(resp) == {"total_input", "allowed_count", "rejected_count", "rejected_indices"}
    assert resp["rejected_indices"] == [1]
    assert "rule" not in json.dumps(resp) and _HEX64.search(json.dumps(resp)) is None


def test_console_live_pan_results_carry_no_rule_local_diagnostic_only(monkeypatch):
    import app.invoke_live as invoke_live
    import lambdas.pan_filter.pan_filter as pan_mod
    monkeypatch.setitem(sys.modules, "pan_filter", pan_mod)
    spec = importlib.util.spec_from_file_location(
        "_pan_handler_console", os.path.join(PROJECT_ROOT, "lambdas", "pan_filter", "handler.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(invoke_live, "_invoke_lambda",
                        lambda name, payload, *, session: json.loads(json.dumps(mod.handler(payload))))
    live = invoke_live.run_pan_filter_live(session=object())
    assert all(r["rule"] is None for r in live["evasion"] + live["safe"])
    assert "rule" not in json.dumps(live["batch"])
    local = invoke_live.run_pan_filter_local()
    batch_rules = [r["rule"] for r in local["evasion"] if r["path"] == "batch"]
    assert batch_rules and all(rule in ("W1", "X4") for rule in batch_rules)
    assert set(local["batch"]) == {"total_input", "allowed_count", "rejected_count", "rejected_indices"}
    assert _HEX64.search(json.dumps(local["batch"])) is None


def test_detection_shim_response_has_no_rule(monkeypatch):
    shim = load_detection_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: h.handler)
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    status, body = post(shim, {"transactions_inline": ring_txns() + [{"txn_id": "p", "card": P}]})
    assert status == 200
    assert body["pan_rejected_indices"] == [3]
    assert "rule" not in set(keys_recursive(body))
    assert '"rule"' not in json.dumps(body)
