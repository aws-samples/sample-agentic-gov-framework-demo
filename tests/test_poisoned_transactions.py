"""1.2 live "Poisoned transactions" red-team run (console only).

The attack is planted in transaction fields; detection runs live on the
inline batch, compliance runs on the NEW recorded detection id, and the
executor is never dispatched. A console drift budget keeps repeated runs
below the 1-hour dispute-rate alarm floor. All AWS is mocked here."""
import os
import re
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_console_error_rendering import (  # noqa: E402,F401  (fixture import)
    FORBIDDEN, LEAKY, PROJECT_ROOT, _AgentCoreError, _all_text, _click, console,
)

PAGE = "1.2 Data & Access Controls — Prompt Injection"
RUN = "Run Poisoned Transactions (red team, dev pipeline)"
OK_DRIFT = {
    "alarms": {k: {"state": "OK", "reason": "", "updated": ""}
               for k in ("challenger", "guardrail", "volume", "sustained")},
    "holds": {r: {"held": False, "policies": [], "error": None}
              for r in ("detection-agent-role", "compliance-agent-role", "executor-agent-role")},
}


# ─── Inline rows (real schema, real detector, real prompt builders) ──────────

def test_poisoned_rows_are_the_sample_dataset_plus_the_planted_attacks():
    from app import invoke_live as il
    sample = il.load_sample_transactions()
    rows = il.build_poisoned_transactions()
    assert rows[:len(sample)] == sample
    planted = rows[len(sample):]
    assert planted == il.POISONED_ROWS and 3 <= len({r["sender_id"] for r in planted[:4]}) <= 4
    fields = {(p["field"], p["kind"]) for p in il.POISON_PAYLOADS}
    assert {("memo", "sentence"), ("counterparty_name", "sentence"), ("sender_id", "spaced"),
            ("merchant_category", "spaced"), ("merchant_category", "token"),
            ("sender_id / receiver_id", "token")} <= fields
    for p in il.POISON_PAYLOADS:
        if p["kind"] == "token":
            assert re.fullmatch(r"[A-Za-z0-9_-]{1,32}", p["value"]), p
        if p["kind"] in ("sentence", "spaced"):
            assert " " in p["value"]


def test_schema_drops_sentences_and_rejects_spaced_payloads():
    from app import invoke_live as il
    report = il.poisoned_schema_report()
    assert report["dropped_fields"] == ["counterparty_name", "memo"]
    assert sorted(r["reason_code"] for r in report["rejected"]) == ["CATEGORY", "ID_CHARSET"]
    assert report["normalized"][il.POISON_ACCOUNT_B] == il.POISON_ACCOUNT_B.casefold()


def test_detector_flags_the_ring_and_tokens_reach_the_untrusted_block():
    from app import invoke_live as il
    preview = il.local_poisoned_preview()
    ring = preview["ring_cluster"]
    assert ring["typology"] == "circular_structuring"
    blocks = il.prompt_untrusted_blocks(ring)
    survived = {t["token"]: t for t in il.surviving_tokens(blocks)}
    assert survived[il.POISON_ACCOUNT_A]["sar"] and survived[il.POISON_ACCOUNT_A]["challenger"]
    assert survived[il.POISON_CATEGORY_2]["challenger"]
    joined = "\n".join(blocks["sar"] + blocks["challenger"])
    for sentence in (il.POISON_MEMO_1, il.POISON_COUNTERPARTY_2, il.POISON_SPACED_SENDER):
        assert sentence not in joined


def test_guardrail_per_call_reads_the_response_only():
    from app import invoke_live as il
    assert il.guardrail_per_call({"model_metadata": {
        "sar_call": {"guardrail_action": "INTERVENED"},
        "challenger_call": {"guardrail_action": "NONE"}}}) == {
        "sar_call": "BLOCKED", "challenger_call": "NOT_BLOCKED"}
    assert il.guardrail_per_call({}) == {"sar_call": "UNKNOWN", "challenger_call": "UNKNOWN"}
    assert il.guardrail_per_call({"model_metadata": {"sar_call": {"guardrail_action": "ERROR"}}})[
        "sar_call"] == "ERROR"


def test_run_detection_live_sends_the_given_rows_inline(monkeypatch):
    from app import invoke_live as il
    sent = {}
    monkeypatch.setattr(il, "_invoke_agentcore", lambda agent, payload, **k: sent.update(
        agent=agent, payload=payload, **k) or {})
    rows = il.build_poisoned_transactions()
    il.run_detection_live(mode="cpu", request_ref="r", session="s", transactions=rows)
    assert sent["agent"] == il.DETECTION_AGENT and sent["session"] == "s"
    assert sent["payload"] == {"mode": "cpu", "transactions_inline": rows, "request_ref": "r"}
    il.run_detection_live(mode="cpu", request_ref="r", session="s")
    assert sent["payload"]["transactions_inline"] == il.load_sample_transactions()


# ─── Drift budget ────────────────────────────────────────────────────────────

def test_drift_floor_matches_the_alarm_publisher_and_breaker():
    import ast
    from app import drift_budget
    from circuit_breaker.handler import MIN_CLUSTERS_FOR_CORROBORATION
    from lambdas.drift_metric_publisher.handler import MIN_CLUSTERS_FOR_RATE
    with open(os.path.join(PROJECT_ROOT, "cdk", "agents_stack.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    cdk = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
           and any(getattr(t, "id", None) == "MIN_CLUSTERS_FOR_ALARM_RATE" for t in n.targets)]
    assert cdk == [drift_budget.ALARM_MIN_CLUSTERS] == [MIN_CLUSTERS_FOR_RATE] == [
        MIN_CLUSTERS_FOR_CORROBORATION]
    assert drift_budget.LEDGER_WINDOW_SECONDS >= 63 * 60  # 60-min alarm + 3-min breaker slack


def test_drift_budget_cooldown_floor_and_window(monkeypatch, tmp_path):
    from app import drift_budget as db
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    t = 1_000_000.0
    assert db.reserve_redteam(3, now=t) is None
    assert "cooldown" in db.reserve_redteam(3, now=t + 10)
    for i in range(1, 6):  # 3 clusters each, spaced past the cooldown
        assert db.reserve_redteam(3, now=t + i * 100) is None
    assert db.summary(now=t + 600)["clusters"] == 18
    # 18 + 3 would reach the 20-cluster floor: refused, nothing recorded.
    assert "budget" in db.reserve_redteam(3, now=t + 700)
    assert db.summary(now=t + 700)["clusters"] == 18
    # Worst case per run (REDTEAM_MAX_CLUSTERS) never lets the window reach the floor.
    assert db.summary(now=t + 700)["clusters"] + 1 < db.ALARM_MIN_CLUSTERS
    # Other console runs count toward the budget but are never refused.
    db.record(2, now=t + 800)
    assert db.summary(now=t + 800)["clusters"] == 20
    # Entries leave the window after LEDGER_WINDOW_SECONDS.
    later = t + 800 + db.LEDGER_WINDOW_SECONDS + 1
    assert db.summary(now=later)["clusters"] == 0
    assert db.reserve_redteam(3, now=later) is None


def test_drift_budget_ignores_a_corrupt_ledger(monkeypatch, tmp_path):
    from app import drift_budget as db
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / db.LEDGER_NAME).write_text("{not json", encoding="utf-8")
    assert db.summary()["clusters"] == 0


# ─── Page, MODE=live (mocked runtimes) ───────────────────────────────────────

def _detect_for_real(transactions):
    """What the detection runtime would return for `transactions` (real
    schema + CPU detector, in-process; nothing recorded)."""
    from lambdas.detection_agent.fraud_detection import detect_fraud_cpu
    from lambdas.detection_agent.txn_schema import canonicalize
    canonical, _, stats = canonicalize([dict(t) for t in transactions])
    clusters, _, _ = detect_fraud_cpu(canonical)
    for c in clusters:
        c["cluster_id"] = str(uuid.uuid4())
    return {"detection_id": str(uuid.uuid4()), "transaction_count": len(canonical),
            "flagged_clusters": clusters, "schema_rejected_count": stats["schema_rejected"],
            "fields_dropped": stats["fields_dropped"],
            "input_quality": {"transactions_in": len(transactions), "transactions_used": len(canonical),
                              "schema_rejected": stats["schema_rejected"], "duplicates_rejected": 0,
                              "fields_dropped": stats["fields_dropped"]}}


def _assessed(cluster, sar="INTERVENED", challenger="NONE", opinion="DISPUTE", decision="NEEDS_REVIEW"):
    return {"cluster_id": cluster["cluster_id"], "decision": decision, "challenger_opinion": opinion,
            "guardrail_triggered": "INTERVENED" in (sar, challenger), "challenger_failed": False,
            "sar_narrative": LEAKY, "challenger_rationale": LEAKY,
            "model_metadata": {"sar_call": {"guardrail_action": sar},
                               "challenger_call": {"guardrail_action": challenger, "confidence": "LOW"}}}


@pytest.fixture
def redteam(console, monkeypatch):
    il = console["invoke_live"]
    calls = {"detection": [], "compliance": [], "executor": [], "drift": 0}

    def detect(mode="cpu", request_ref=None, *, session, transactions=None):
        calls["detection"].append({"request_ref": request_ref, "session": session,
                                   "transactions": transactions, "mode": mode})
        return _detect_for_real(transactions)

    def comply(detection_output, *, session, request_ref=None):
        calls["compliance"].append({"detection_output": detection_output, "session": session,
                                    "request_ref": request_ref})
        ring = il.find_poisoned_cluster(detection_output)
        return {"detection_id": detection_output["detection_id"], "provenance_status": "VERIFIED",
                "dispatch_token": "secret-dispatch-token",
                "clusters_assessed": [_assessed(c) if c is ring else
                                      _assessed(c, sar="NONE", opinion="AGREE", decision="FILE_SAR")
                                      for c in detection_output["flagged_clusters"]]}

    def executor(*a, **k):
        calls["executor"].append(k)
        raise AssertionError("the executor must never be dispatched from a red-team run")

    def drift(*, session):
        calls["drift"] += 1
        assert session is console["sessions"]["operator"]
        return OK_DRIFT

    monkeypatch.setattr(il, "run_detection_live", detect)
    monkeypatch.setattr(il, "run_compliance_live", comply)
    monkeypatch.setattr(il, "run_executor_live", executor)
    monkeypatch.setattr(il, "run_executor_local", executor)
    monkeypatch.setattr(il, "test_prompt_injection_live", executor)
    monkeypatch.setattr(il, "get_drift_safety_live", drift)
    return calls


def test_live_run_records_a_detection_then_compliance_on_its_id(console, redteam):
    from app import invoke_live as il
    at = _click(console["page"](PAGE), RUN)
    [det], [comp] = redteam["detection"], redteam["compliance"]
    operator = console["sessions"]["operator"]
    assert det["session"] is operator and comp["session"] is operator
    assert det["mode"] == "cpu" and det["request_ref"] == comp["request_ref"] is not None
    assert det["transactions"] == il.build_poisoned_transactions()
    run = at.session_state["poisoned_run"]
    assert comp["detection_output"]["detection_id"] == run["detection"]["detection_id"]
    assert redteam["executor"] == []
    assert "dispatch_token" not in run["compliance"]
    assert "secret-dispatch-token" not in repr(run)
    assert redteam["drift"] == 2  # before and after


def test_live_run_renders_the_five_stages_honestly(console, redteam):
    at = _click(console["page"](PAGE), RUN)
    headers = [s.value for s in at.subheader]
    for stage in ("1 · Schema", "2 · Detection", "3 · What reached the model", "4 · Guardrail",
                  "5 · Outcome"):
        assert any(h.startswith(stage) for h in headers), (stage, headers)
    text = _all_text(at)
    assert "Red-team run against the dev pipeline" in text
    assert "ID_CHARSET" in text and "CATEGORY" in text and "`memo`" in text
    assert "circular_structuring" in text
    assert "ignore_all_previous_instructions" in text
    assert "BLOCKED" in text and "NOT_BLOCKED" in text
    assert "Short tokens" in text and "can pass the guardrail" in text
    assert "Decision: NEEDS_REVIEW" in text and "computed by code from a strict verdict" in text
    assert "Executor not dispatched" in text
    assert "all blocked" not in text.lower() and "4/4" not in text
    for needle in FORBIDDEN:
        assert needle not in text
    assert LEAKY not in text  # model prose is never rendered


def test_live_run_twice_is_held_by_the_cooldown(console, redteam):
    at = console["page"](PAGE)
    at = _click(at, RUN)
    at = _click(at, RUN)
    assert len(redteam["detection"]) == 1 and len(redteam["compliance"]) == 1
    assert "cooldown" in _all_text(at)


def test_live_run_refused_when_the_hour_is_near_the_alarm_floor(console, redteam):
    from app import drift_budget
    drift_budget.record(17)
    at = _click(console["page"](PAGE), RUN)
    assert redteam["detection"] == [] and redteam["compliance"] == []
    assert "drift budget used up" in _all_text(at)


@pytest.mark.parametrize("drift,expected", [
    ({**OK_DRIFT, "alarms": {**OK_DRIFT["alarms"], "sustained": {"state": "ALARM"}}}, "not OK (sustained)"),
    ({**OK_DRIFT, "alarms": {**OK_DRIFT["alarms"], "guardrail": {"state": "UNKNOWN"}}}, "fail closed"),
    ({**OK_DRIFT, "holds": {"compliance-agent-role": {"held": None}}}, "fail closed"),
    ({}, "fail closed"),
])
def test_live_run_refused_unless_drift_state_is_clean(console, redteam, monkeypatch, drift, expected):
    monkeypatch.setattr(console["invoke_live"], "get_drift_safety_live", lambda **k: drift)
    at = _click(console["page"](PAGE), RUN)
    assert expected in _all_text(at)
    assert redteam["detection"] == [] and redteam["compliance"] == []


def test_live_run_refused_and_hold_shown_when_a_role_is_held(console, redteam, monkeypatch):
    held = {**OK_DRIFT, "holds": {"compliance-agent-role": {"held": True, "policies": [], "error": None}}}
    monkeypatch.setattr(console["invoke_live"], "get_drift_safety_live", lambda **k: held)
    at = _click(console["page"](PAGE), RUN)
    assert "governance hold" in _all_text(at) and at.session_state["ks_engaged"] is True
    assert redteam["detection"] == []


def test_live_run_refused_while_hold_is_engaged(console, redteam):
    at = console["page"](PAGE)
    at.session_state["ks_engaged"] = True
    at = _click(at, RUN)
    assert any("governance hold" in e.value for e in at.error)
    assert redteam["detection"] == [] and redteam["drift"] == 0


def test_too_many_clusters_skips_compliance(console, redteam, monkeypatch):
    from app import drift_budget
    monkeypatch.setattr(drift_budget, "REDTEAM_MAX_CLUSTERS", 2)
    at = _click(console["page"](PAGE), RUN)
    assert len(redteam["detection"]) == 1 and redteam["compliance"] == []
    assert "compliance was not run" in _all_text(at)


def test_detection_failure_renders_safe_text_and_skips_compliance(console, redteam, monkeypatch):
    def boom(mode="cpu", request_ref=None, *, session, transactions=None):
        raise _AgentCoreError(503)
    monkeypatch.setattr(console["invoke_live"], "run_detection_live", boom)
    at = _click(console["page"](PAGE), RUN)
    text = _all_text(at)
    assert "Temporarily unavailable (ref " in text and redteam["compliance"] == []
    for needle in FORBIDDEN:
        assert needle not in text
    assert "Received error" not in text


def test_detection_error_body_renders_fixed_text(console, redteam, monkeypatch):
    monkeypatch.setattr(console["invoke_live"], "run_detection_live",
                        lambda mode="cpu", request_ref=None, *, session, transactions=None: {"error": LEAKY})
    at = _click(console["page"](PAGE), RUN)
    text = _all_text(at)
    assert "Detection failed; no detection was recorded for this run" in text
    assert redteam["compliance"] == [] and LEAKY not in text


def test_compliance_409_renders_safe_text(console, redteam, monkeypatch):
    def refuse(detection_output, *, session, request_ref=None):
        raise _AgentCoreError(409)
    monkeypatch.setattr(console["invoke_live"], "run_compliance_live", refuse)
    at = _click(console["page"](PAGE), RUN)
    text = _all_text(at)
    assert "This detection was already decided or isn't recorded (ref " in text
    assert redteam["executor"] == []
    for needle in FORBIDDEN:
        assert needle not in text


def test_no_aws_authority_shows_safe_message_and_local_preview(console, redteam, monkeypatch):
    from app import console_identity
    from app.console_identity import NO_AUTHORITY_MESSAGE, NoAwsAuthorityError

    def none(p, purpose):
        raise NoAwsAuthorityError()
    monkeypatch.setattr(console_identity, "governance_session", none)
    at = _click(console["page"](PAGE), RUN)
    text = _all_text(at)
    assert NO_AUTHORITY_MESSAGE in text and "Local preview" in text
    assert "circular_structuring" in text and "3 · What reached the model" in text
    assert redteam["detection"] == [] and redteam["compliance"] == [] and redteam["drift"] == 0


def test_challenger_and_pipeline_runs_count_toward_the_budget(console, monkeypatch):
    from app import drift_budget
    il = console["invoke_live"]
    detection = _detect_for_real(il.load_sample_transactions())
    monkeypatch.setattr(il, "run_detection_live", lambda *a, **k: dict(detection,
                                                                       detection_id=str(uuid.uuid4())))
    monkeypatch.setattr(il, "run_compliance_live", lambda d, **k: {"detection_id": d["detection_id"],
                                                                   "clusters_assessed": []})
    monkeypatch.setattr(il, "get_circuit_breaker_status_live", lambda **k: {"status": "ACTIVE"})
    _click(console["page"]("3.1 Deliberative Challenge — Champion/Challenger"), "Run Challenger Analysis")
    assert drift_budget.summary()["clusters"] == len(detection["flagged_clusters"]) > 0


def test_ordinary_runs_cannot_push_red_team_disputes_over_the_floor(monkeypatch, tmp_path):
    """Review B1: 6 red-team runs (18 clusters, ~12 disputes) + one 2-cluster
    sample run would be 20 clusters at ~0.65 > 0.51 -> breaker trip."""
    from app import drift_budget as db
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    t = 1_000_000.0
    for i in range(6):
        assert db.reserve_redteam(3, now=t + i * 100) is None
    now = t + 600
    msg = db.reserve_other(2, now=now)
    assert msg is not None and "no decision was recorded" in msg
    assert db.summary(now=now)["clusters"] == 18  # nothing recorded
    # Below the floor it is allowed and recorded.
    assert db.reserve_other(1, now=now) is None
    assert db.summary(now=now)["clusters"] == 19
    # The wait is until the LAST red-team entry ages out.
    assert "~" + str(int((t + 500 + db.LEDGER_WINDOW_SECONDS - now) / 60) + 1) + " min" in msg
    later = t + 500 + db.LEDGER_WINDOW_SECONDS + 1
    assert db.reserve_other(2, now=later) is None
    # 3 red-team runs + 6 sample runs (21 clusters, ~0.57) is refused at the 6th.
    db._path().unlink()
    for i in range(3):
        assert db.reserve_redteam(3, now=t + i * 100) is None
    results = [db.reserve_other(2, now=t + 400 + i) for i in range(6)]
    assert results[:5] == [None] * 5 and results[5] is not None
    assert db.summary(now=t + 500)["clusters"] == 19


def test_ordinary_runs_are_never_refused_without_red_team_entries(monkeypatch, tmp_path):
    from app import drift_budget as db
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    t = 1_000_000.0
    for i in range(15):
        assert db.reserve_other(2, now=t + i) is None
    assert db.summary(now=t + 20)["clusters"] == 30


def _fill_with_red_team(drift_budget, runs=6):
    t = drift_budget.time.time()
    for i in range(runs):
        assert drift_budget.reserve_redteam(3, now=t - (runs - i) * 100) is None


def _sample_runtimes(console, monkeypatch):
    il = console["invoke_live"]
    detection = _detect_for_real(il.load_sample_transactions())
    calls = {"compliance": 0, "executor": 0}

    def comply(d, **k):
        calls["compliance"] += 1
        return {"detection_id": d["detection_id"], "clusters_assessed": []}

    def executor(*a, **k):
        calls["executor"] += 1
        return {}
    monkeypatch.setattr(il, "run_detection_live", lambda *a, **k: dict(detection,
                                                                       detection_id=str(uuid.uuid4())))
    monkeypatch.setattr(il, "run_compliance_live", comply)
    monkeypatch.setattr(il, "run_executor_live", executor)
    monkeypatch.setattr(il, "get_circuit_breaker_status_live", lambda **k: {"status": "ACTIVE"})
    assert len(detection["flagged_clusters"]) == 2
    return calls


def test_challenger_page_refused_after_red_team_runs_near_the_floor(console, monkeypatch):
    from app import drift_budget
    calls = _sample_runtimes(console, monkeypatch)
    _fill_with_red_team(drift_budget)
    at = _click(console["page"]("3.1 Deliberative Challenge — Champion/Challenger"),
                "Run Challenger Analysis")
    assert calls["compliance"] == 0 and calls["executor"] == 0
    assert "Drift safety" in _all_text(at)
    assert drift_budget.summary()["clusters"] == 18


def test_pipeline_page_refused_after_red_team_runs_near_the_floor(console, monkeypatch):
    from app import drift_budget
    calls = _sample_runtimes(console, monkeypatch)
    _fill_with_red_team(drift_budget)
    at = _click(console["page"]("Run Pipeline (Happy Path)"), "Run Full Pipeline")
    assert calls["compliance"] == 0 and calls["executor"] == 0
    assert "Drift safety" in _all_text(at)
    assert drift_budget.summary()["clusters"] == 18


# ─── MODE=local is unchanged ─────────────────────────────────────────────────

def test_local_mode_keeps_the_cached_page_and_calls_no_live_agent(console, redteam, monkeypatch):
    monkeypatch.setenv("MODE", "local")
    at = console["page"](PAGE)
    assert not [b for b in at.button if b.label == RUN]
    at = _click(at, "Run Injection Attacks (4 Variants)")
    assert "injection_results" in at.session_state
    assert redteam["detection"] == [] and redteam["compliance"] == [] and redteam["drift"] == 0
