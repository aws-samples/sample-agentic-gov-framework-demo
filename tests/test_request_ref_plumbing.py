"""
request_ref correlation plumbing — detection shim + handler
part, followed by the compliance and executor parts.
"""
import os
import sys
import uuid

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from _detection_fixtures import capture_audit, load_detection_shim, main_item, post, ring_txns  # noqa: E402

from governance_common.payload_limits import REQUEST_REF_RE, new_request_ref  # noqa: E402
from governance_common.pan_filter import contains_full_pan  # noqa: E402

# A uuid4 the PAN classifier never flags (a random uuid4 is PAN-shaped ~2 %).
VALID = new_request_ref()
# Well-formed lowercase uuid4s that encode a Luhn-valid card number: the
# second is a real uuid4 from a seeded RNG, the first is hand-built.
PAN_SHAPED = ["abcdef01-4111-4111-a111-111111111111", "10a3d6b2-aa05-411a-b271-5945795e8229"]
MALFORMED = ["x", VALID.upper(), VALID + "a", 7, ["x"], {"a": 1}, "",
             "00000000-0000-0000-0000-000000000000", *PAN_SHAPED]


@pytest.mark.parametrize("ref", PAN_SHAPED)
def test_pan_shaped_refs_are_uuid4_shaped_and_flagged(ref):
    """The fixtures really are PAN-shaped refs: they pass the uuid4 regex and the
    PAN classifier flags them, so only the PAN check refuses them."""
    assert REQUEST_REF_RE.fullmatch(ref) and contains_full_pan(ref)


@pytest.fixture
def shim(monkeypatch):
    module = load_detection_shim()
    calls = []
    monkeypatch.setattr(module, "_get_handler", lambda: (lambda event: calls.append(event) or {"ok": 1}))
    module.handler_calls = calls
    return module


@pytest.mark.parametrize("ref", MALFORMED, ids=repr)
def test_detection_shim_rejects_malformed_request_ref(shim, ref):
    status, body = post(shim, {"transactions_inline": ring_txns(), "request_ref": ref})
    assert status == 400
    assert body == {"error": "invalid request_ref"}
    assert shim.handler_calls == []


def test_detection_shim_forwards_valid_request_ref(shim):
    status, _ = post(shim, {"transactions_inline": ring_txns(), "request_ref": VALID})
    assert status == 200
    assert shim.handler_calls[0]["request_ref"] == VALID


def test_detection_shim_without_request_ref_forwards_none(shim):
    status, _ = post(shim, {"transactions_inline": ring_txns()})
    assert status == 200
    assert "request_ref" not in shim.handler_calls[0]


@pytest.mark.parametrize("ref", MALFORMED, ids=repr)
def test_detection_handler_rejects_malformed_request_ref(monkeypatch, ref):
    capture_audit(monkeypatch, h)
    with pytest.raises(ValueError, match="^invalid request_ref$"):
        h.handler({"mode": "cpu", "transactions_inline": ring_txns(), "request_ref": ref})


def test_audit_item_carries_console_request_ref(monkeypatch):
    items = capture_audit(monkeypatch, h)
    shim = load_detection_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: h.handler)
    status, body = post(shim, {"transactions_inline": ring_txns(), "request_ref": VALID})
    assert status == 200
    item = main_item(items, body["detection_id"])
    assert item["console_request_ref"] == VALID
    # Not part of the invoker-facing output.
    assert "request_ref" not in body and "console_request_ref" not in body


def test_audit_item_without_request_ref_has_no_console_request_ref(monkeypatch):
    items = capture_audit(monkeypatch, h)
    out = h.handler({"mode": "cpu", "transactions_inline": ring_txns()})
    assert "console_request_ref" not in main_item(items, out["detection_id"])


def test_invoke_live_sends_request_ref_on_detection(monkeypatch):
    import app.invoke_live as invoke_live
    sent = []
    monkeypatch.setattr(invoke_live, "_invoke_agentcore",
                        lambda agent, payload, *, session: sent.append(payload) or {})
    invoke_live.run_detection_live(request_ref=VALID, session=object())
    invoke_live.run_detection_live(session=object())
    assert sent[0]["request_ref"] == VALID
    assert REQUEST_REF_RE.fullmatch(sent[1]["request_ref"])
    assert not contains_full_pan(sent[1]["request_ref"])


# ─── Compliance part ──────────────────────────────────────────────

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import FakeAws, detection_output  # noqa: E402
from _compliance_fixtures import load_compliance_shim, post as compliance_post  # noqa: E402


@pytest.fixture
def compliance_shim(monkeypatch):
    module = load_compliance_shim()
    calls = []
    monkeypatch.setattr(module, "_get_handler", lambda: (lambda event: calls.append(event) or {"ok": 1}))
    module.handler_calls = calls
    return module


@pytest.mark.parametrize("ref", MALFORMED, ids=repr)
def test_compliance_shim_rejects_malformed_request_ref(compliance_shim, ref):
    status, body = compliance_post(compliance_shim, {"detection_output": detection_output(), "request_ref": ref})
    assert status == 400
    assert body == {"error": "invalid request_ref"}
    assert compliance_shim.handler_calls == []


def test_compliance_shim_forwards_valid_request_ref(compliance_shim):
    status, _ = compliance_post(compliance_shim, {"detection_output": detection_output(), "request_ref": VALID})
    assert status == 200
    assert compliance_shim.handler_calls[0]["request_ref"] == VALID


def test_compliance_shim_without_request_ref_forwards_none(compliance_shim):
    compliance_post(compliance_shim, {"detection_output": detection_output()})
    assert "request_ref" not in compliance_shim.handler_calls[0]


@pytest.mark.parametrize("ref", MALFORMED, ids=repr)
def test_compliance_handler_rejects_malformed_request_ref(monkeypatch, ref):
    aws = FakeAws().install(monkeypatch, ch)
    with pytest.raises(ValueError, match="^invalid request_ref$"):
        ch.handler({"mode": "live", "detection_output": detection_output(), "request_ref": ref})
    assert aws.events == []


def test_compliance_decision_item_stores_and_output_echoes_request_ref(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output()
    aws.store_detection(det)
    shim = load_compliance_shim()
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    status, body = compliance_post(shim, {"detection_output": det, "request_ref": VALID})
    assert status == 200
    assert body["request_ref"] == VALID
    item = aws.decision_item()
    assert item["console_request_ref"] == VALID
    assert "request_ref" not in item


def test_compliance_without_request_ref_has_no_ref(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output()
    aws.store_detection(det)
    out = ch.handler({"mode": "live", "detection_output": det})
    assert "request_ref" not in out
    assert "console_request_ref" not in aws.decision_item()


def test_request_ref_is_not_part_of_provenance(monkeypatch):
    """A request_ref on the caller's detection_output is ignored by the
    provenance comparison (it is not an enrichment field)."""
    aws = FakeAws().install(monkeypatch, ch)
    det = detection_output()
    aws.store_detection(det)
    out = ch.handler({"mode": "live", "detection_output": dict(det, request_ref=VALID)})
    assert out["provenance_status"] == "VERIFIED"


# ─── Executor part ────────────────────────────────────────────────
import json  # noqa: E402

import _executor_fixtures as fx  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402

EX_CLUSTERS = [fx.CLUSTER_SAR, fx.CLUSTER_REVIEW, fx.CLUSTER_BREAKER]


@pytest.fixture
def ex_aws(monkeypatch):
    return fx.FakeExecutorAws(fx.stored_record(EX_CLUSTERS)).install(monkeypatch, ex)


def test_executor_valid_request_ref_on_every_audit_record(ex_aws):
    out = ex.handler(fx.event(EX_CLUSTERS, request_ref=VALID))
    assert "error" not in out
    taken = [i["action_taken"] for i in ex_aws.audit_items]
    assert taken.count("ACTION_INTENT") == 3 and len(taken) == 6
    assert all(i["console_request_ref"] == VALID for i in ex_aws.audit_items)
    assert "request_ref" not in json.dumps(ex_aws.audit_items).replace("console_request_ref", "")


@pytest.mark.parametrize("prepare", ["sox", "provenance", "replay"])
def test_executor_rejection_records_carry_request_ref(ex_aws, prepare):
    if prepare == "provenance":
        ex_aws.record["provenance_status"] = "UNVERIFIED"
    if prepare == "replay":
        ex_aws.state = True
    extra = {"override": 1} if prepare == "sox" else {}
    ex.handler(fx.event(EX_CLUSTERS, request_ref=VALID, **extra))
    (record,) = ex_aws.audit_items
    assert record["console_request_ref"] == VALID


def test_executor_without_request_ref_has_none(ex_aws):
    ex.handler(fx.event(EX_CLUSTERS))
    assert ex_aws.audit_items and not any("console_request_ref" in i for i in ex_aws.audit_items)


@pytest.mark.parametrize("ref", MALFORMED, ids=repr)
def test_executor_malformed_request_ref_is_sox_violation(ex_aws, ref):
    out = ex.handler(fx.event(EX_CLUSTERS, request_ref=ref))
    assert out["error"] == "SOX_VIOLATION"
    assert "request_ref" in out["message"]
    assert not ex_aws.claimed() and ex_aws.side_effects() == []
    (record,) = ex_aws.audit_items
    assert "console_request_ref" not in record  # malformed refs are never stored


def test_executor_provenance_identical_with_and_without_request_ref(ex_aws):
    plain = ex.verify_compliance_provenance("comp-1", "det-1", EX_CLUSTERS, dispatch_token=fx.TOKEN)
    ex_aws.record["console_request_ref"] = VALID
    ex_aws.record["request_ref"] = VALID
    with_ref = ex.verify_compliance_provenance("comp-1", "det-1", EX_CLUSTERS, dispatch_token=fx.TOKEN)
    assert plain == with_ref and plain[0] is None


# ─── PAN-shaped refs are never generated by the console ─────────────────────
import governance_common.payload_limits as pl  # noqa: E402


class _UuidSequence:
    """uuid.uuid4 replacement: the PAN-shaped fixtures first, then VALID."""

    def __init__(self):
        self.values = [uuid.UUID(r) for r in PAN_SHAPED] + [uuid.UUID(VALID)]
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.values.pop(0)


def test_new_request_ref_regenerates_pan_shaped_uuid4s(monkeypatch):
    seq = _UuidSequence()
    monkeypatch.setattr(pl.uuid, "uuid4", seq)
    assert pl.new_request_ref() == VALID
    assert seq.calls == 3


def test_new_request_ref_is_always_accepted():
    refs = [pl.new_request_ref() for _ in range(2000)]
    assert all(pl.request_ref_ok(r) for r in refs)


def test_console_run_regenerates_a_pan_shaped_ref(monkeypatch):
    import app.invoke_live as invoke_live
    sent = []
    monkeypatch.setattr(invoke_live, "_invoke_agentcore",
                        lambda agent, payload, *, session: sent.append(payload) or {})
    monkeypatch.setattr(pl.uuid, "uuid4", _UuidSequence())
    invoke_live.run_detection_live(session=object())
    assert sent[0]["request_ref"] == VALID


def test_operator_audit_event_id_is_never_pan_shaped(monkeypatch, tmp_path):
    """The operator-audit event id is the request_ref the console sends."""
    import app.operator_audit as operator_audit
    from app.console_identity import Principal
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(pl.uuid, "uuid4", _UuidSequence())
    monkeypatch.setenv("MODE", "local")
    principal = Principal(principal_id="local:alice", display_name="Alice", auth_mode="local",
                          roles=frozenset({"operator"}), authenticated_at="2026-01-01T00:00:00+00:00")
    event_id = operator_audit.record_console_action(principal, "PIPELINE_RUN", "REQUESTED",
                                                    sink=operator_audit.SINK_JSONL)
    assert event_id == VALID
