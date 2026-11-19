"""
Incomplete-evidence banner: the audit and PAN
pages say "INCOMPLETE EVIDENCE" whenever a read returned partial or failed
data, and the PAN summary is then never a success. Mocked AWS only; ambient
boto3 is refused.
"""
import json
import os
from unittest.mock import MagicMock

import pytest

from app import evidence_status
import app.invoke_live as invoke_live

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "app", "dashboard.py")
AUDIT_PAGE = "2.1 Decision Explainability — Audit Trail"
PAN_PAGE = "1.1 Data & Access Controls — PAN Filter"
TABLES = ("detection-results", "compliance-decisions", "executor-audit", "governance-audit")


def _complete():
    return {t: [{"id": t}] for t in TABLES}


# ─── Unit: audit ─────────────────────────────────────────────────────────────

def test_complete_read_has_no_reasons():
    assert evidence_status.audit_incomplete_reasons(_complete()) == []
    assert evidence_status.audit_incomplete_reasons({t: [] for t in TABLES}) == []


@pytest.mark.parametrize("entry,reason", [
    ({"error": "x"}, "compliance-decisions: read failed"),
    ({"error_ref": "abcd"}, "compliance-decisions: read failed"),
    ({"error_code": "Error", "error_ref": "abcd"}, "compliance-decisions: read failed"),
    ({"error_code": "AccessDenied"}, "compliance-decisions: read failed (AccessDenied)"),
    ({"error_code": "free text", "error_ref": "abcd"}, "compliance-decisions: read failed"),
])
def test_error_entries_are_failed_reads(entry, reason):
    data = _complete()
    data["compliance-decisions"] = [entry]
    assert evidence_status.audit_incomplete_reasons(data) == [reason]


def test_missing_table_and_partial_marker():
    data = _complete()
    del data["governance-audit"]
    data["_evidence"] = {"tables": {"executor-audit": "partial"}}
    assert evidence_status.audit_incomplete_reasons(data) == [
        "executor-audit: partial read", "governance-audit: read failed"]


def test_non_dict_is_all_failed():
    assert len(evidence_status.audit_incomplete_reasons(None)) == 4


# ─── Unit: PAN ───────────────────────────────────────────────────────────────

def _pan(actions=("BLOCKED", "BLOCKED"), safe=("ALLOWED",), batch=None):
    return {"evasion": [{"name": f"e{i}", "action": a} for i, a in enumerate(actions)],
            "safe": [{"name": f"s{i}", "action": a} for i, a in enumerate(safe)],
            "batch": batch if batch is not None else {"total_input": 8, "allowed_count": 2, "rejected_count": 6}}


def test_complete_pan_has_no_reasons():
    assert evidence_status.pan_incomplete_reasons(_pan()) == []
    # A MISSED evasion is a real result, not incomplete evidence.
    assert evidence_status.pan_incomplete_reasons(_pan(actions=("ALLOWED",))) == []


@pytest.mark.parametrize("results,reason", [
    (_pan(actions=("BLOCKED", "ERROR")), "evasion variants: 1 without a BLOCKED/ALLOWED verdict"),
    (_pan(safe=("ERROR",)), "safe inputs: 1 without a BLOCKED/ALLOWED verdict"),
    (_pan(batch={"error": "x"}), "batch ingress check: failed or missing"),
    (_pan(batch={"total_input": 8, "allowed_count": 2, "rejected_count": 5}),
     "batch ingress check: counts do not add up"),
    ({"evasion": [], "safe": []}, "batch ingress check: failed or missing"),
])
def test_pan_reasons(results, reason):
    assert reason in evidence_status.pan_incomplete_reasons(results)


# ─── invoke_live: partial live reads, unreadable local files ────────────────

class _Table:
    def __init__(self, name):
        self.name = name

    def query(self, **kwargs):
        key = "event_id" if self.name == "governance-audit" else {
            "detection-results": "detection_id", "compliance-decisions": "compliance_id",
            "executor-audit": "action_id"}[self.name]
        return {"Items": [{key: f"{self.name}-1"}, {key: f"{self.name}-2"}]}


def _session(short_tables=()):
    resource = MagicMock()
    resource.Table.side_effect = _Table

    def batch_get_item(RequestItems):
        (table, request), = RequestItems.items()
        keys = request["Keys"]
        if table in short_tables:   # one key never returned (UnprocessedKeys every round)
            return {"Responses": {table: [dict(k) for k in keys[:1]]},
                    "UnprocessedKeys": {table: {"Keys": keys[1:]}}}
        return {"Responses": {table: [dict(k) for k in keys]}}
    resource.batch_get_item.side_effect = batch_get_item
    session = MagicMock()
    session.resource.return_value = resource
    return session


def test_batch_get_short_read_marks_partial():
    data = invoke_live.read_audit_trail_live(session=_session(short_tables=("compliance-decisions",)),
                                             include_narratives=True)
    assert data["_evidence"] == {"tables": {"compliance-decisions": "partial"}}
    assert evidence_status.audit_incomplete_reasons(data) == ["compliance-decisions: partial read"]
    keys = invoke_live.audit_read_keys(data)
    assert "_evidence" not in keys
    assert len(keys["compliance-decisions"]) < len(keys["detection-results"])  # the short read


def test_full_live_read_has_no_evidence_marker():
    data = invoke_live.read_audit_trail_live(session=_session(), include_narratives=False)
    assert "_evidence" not in data and evidence_status.audit_incomplete_reasons(data) == []


def test_local_unreadable_compliance_file_is_a_failed_read(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "compliance_result.json").mkdir()   # exists but can't be read as a file
    data = invoke_live.read_audit_trail_local()
    assert "error_ref" in data["compliance-decisions"][0]
    assert "compliance-decisions: read failed" in evidence_status.audit_incomplete_reasons(data)


def test_local_jsonl_with_an_undecodable_line_is_partial(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "executor_audit.jsonl").write_text(
        json.dumps({"action_id": "a1", "timestamp": "2026-01-01T00:00:00+00:00"}) + "\n{not json\n",
        encoding="utf-8")
    data = invoke_live.read_audit_trail_local()
    assert [r["action_id"] for r in data["executor-audit"]] == ["a1"]
    assert data["_evidence"] == {"tables": {"executor-audit": "partial"}, "skipped": {"executor-audit": 1}}
    assert evidence_status.audit_incomplete_reasons(data) == [
        "executor-audit: partial read (1 undecodable line skipped)"]


def test_local_unreadable_jsonl_is_a_failed_read(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "executor_audit.jsonl").mkdir()
    data = invoke_live.read_audit_trail_local()
    assert "executor-audit: read failed" in evidence_status.audit_incomplete_reasons(data)


def _audit_lines(n):
    return "".join(json.dumps({"action_id": f"a{i}", "timestamp": f"2026-01-01T00:00:{i:02d}+00:00"}) + "\n"
                   for i in range(n))


def _deny_executor_audit_opens(monkeypatch, times):
    """The OS refuses the first ``times`` opens of executor_audit.jsonl
    (PermissionError, as macOS does on a cloud-synced File Provider path right after a write)."""
    import builtins
    real_open = builtins.open
    calls = {"denied": 0}

    def fake_open(path, *a, **k):
        if str(path).endswith("executor_audit.jsonl") and calls["denied"] < times:
            calls["denied"] += 1
            raise PermissionError(13, "Operation not permitted")
        return real_open(path, *a, **k)
    monkeypatch.setattr(invoke_live, "open", fake_open, raising=False)
    monkeypatch.setattr(invoke_live, "_LOCAL_READ_RETRY_DELAYS", (0, 0, 0))
    return calls


def test_local_transient_permission_denial_is_retried(tmp_path, monkeypatch):
    # Reproduced scenario: the file is fine, the first open is refused.
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "executor_audit.jsonl").write_text(_audit_lines(3), encoding="utf-8")
    calls = _deny_executor_audit_opens(monkeypatch, times=2)
    data = invoke_live.read_audit_trail_local()
    assert calls["denied"] == 2
    assert len(data["executor-audit"]) == 3 and "_evidence" not in data
    assert evidence_status.audit_incomplete_reasons(data) == []


def test_local_persistent_permission_denial_stays_a_failed_read(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    (tmp_path / "executor_audit.jsonl").write_text(_audit_lines(3), encoding="utf-8")
    calls = _deny_executor_audit_opens(monkeypatch, times=99)
    data = invoke_live.read_audit_trail_local()
    assert calls["denied"] == len(invoke_live._LOCAL_READ_RETRY_DELAYS) + 1
    (entry,) = data["executor-audit"]
    assert entry["error_code"] == "AccessDenied" and len(entry["error_ref"]) == 8
    assert evidence_status.audit_incomplete_reasons(data) == ["executor-audit: read failed (AccessDenied)"]


def test_local_tables_not_written_are_not_failed_reads(tmp_path, monkeypatch):
    # Local mode writes only executor_audit.jsonl (plus escalation/SAR files):
    # absent detection/compliance/governance files are empty tables, not failures.
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(invoke_live, "PROJECT_ROOT", str(tmp_path))   # no circuit_breaker state
    monkeypatch.setattr(invoke_live, "CACHED_INPUTS_DIR", str(tmp_path / "no-cached-inputs"))
    (tmp_path / "executor_audit.jsonl").write_text(_audit_lines(2), encoding="utf-8")
    (tmp_path / "escalation_c1.json").write_text("{}", encoding="utf-8")
    data = invoke_live.read_audit_trail_local()
    assert data["detection-results"] == data["compliance-decisions"] == data["governance-audit"] == []
    assert len(data["executor-audit"]) == 2
    assert evidence_status.audit_incomplete_reasons(data) == []


# ─── AppTest: the banner on the pages ────────────────────────────────────────

@pytest.fixture
def console(monkeypatch, tmp_path):
    import boto3
    from app import console_auth, console_identity
    from app.console_identity import Principal
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0")
    monkeypatch.setattr(console_auth, "_server_address", lambda: "127.0.0.1")

    def refuse(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, refuse)
    sessions = {p: MagicMock(name=f"{p}-session") for p in ("operator", "approver", "auditor", "audit_writer")}
    monkeypatch.setattr(console_identity, "governance_session", lambda p, purpose: sessions[purpose])
    principal = Principal(principal_id="local:alice", display_name="Alice", auth_mode="local",
                          roles=frozenset({"approver", "auditor"}),
                          authenticated_at="2026-01-01T00:00:00+00:00",
                          aws_principal_arn="arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice")

    def page(name, mode="live"):
        from streamlit.testing.v1 import AppTest
        monkeypatch.setenv("MODE", mode)
        at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60)
        at.session_state["principal"] = principal
        at.run()
        at.sidebar.radio[0].set_value(name).run()
        assert not at.exception, at.exception
        return at
    return {"page": page, "tmp": tmp_path}


def _click(at, label):
    [b for b in at.button if b.label.startswith(label)][0].click().run()
    assert not at.exception, at.exception
    return at


def _banner(at):
    return [e.value for e in at.error if str(e.value).startswith("INCOMPLETE EVIDENCE")]


def test_audit_page_banner_on_one_failed_live_table(console, monkeypatch):
    data = _complete()
    data["executor-audit"] = [{"error_code": "AccessDenied", "error_ref": "abcd1234"}]
    monkeypatch.setattr(invoke_live, "read_audit_trail_live", lambda **k: data)
    at = _click(console["page"](AUDIT_PAGE), "Load Live Audit Records")
    (banner,) = _banner(at)
    assert "executor-audit: read failed" in banner and "not evidence for sign-off" in banner
    assert not at.success


def test_audit_page_complete_live_read_has_no_banner(console, monkeypatch):
    monkeypatch.setattr(invoke_live, "read_audit_trail_live", lambda **k: _complete())
    at = _click(console["page"](AUDIT_PAGE), "Load Live Audit Records")
    assert _banner(at) == []


def test_audit_page_banner_on_partial_live_read(console, monkeypatch):
    data = dict(_complete(), _evidence={"tables": {"governance-audit": "partial"}})
    monkeypatch.setattr(invoke_live, "read_audit_trail_live", lambda **k: data)
    at = _click(console["page"](AUDIT_PAGE), "Load Live Audit Records")
    assert "governance-audit: partial read" in _banner(at)[0]


def test_audit_page_banner_in_local_mode_with_unreadable_file(console):
    (console["tmp"] / "compliance_result.json").mkdir()
    at = _click(console["page"](AUDIT_PAGE, mode="local"), "Load Local Audit Records")
    assert "compliance-decisions: read failed" in _banner(at)[0]


def test_audit_page_local_complete_has_no_banner(console):
    at = _click(console["page"](AUDIT_PAGE, mode="local"), "Load Local Audit Records")
    assert _banner(at) == []


def test_audit_page_local_transient_denial_has_no_banner(console, monkeypatch):
    (console["tmp"] / "executor_audit.jsonl").write_text(_audit_lines(3), encoding="utf-8")
    _deny_executor_audit_opens(monkeypatch, times=1)
    at = _click(console["page"](AUDIT_PAGE, mode="local"), "Load Local Audit Records")
    assert _banner(at) == []
    assert not [w for w in at.warning if "Could not read records" in str(w.value)]


def test_audit_page_local_persistent_denial_keeps_banner(console, monkeypatch):
    (console["tmp"] / "executor_audit.jsonl").write_text(_audit_lines(3), encoding="utf-8")
    _deny_executor_audit_opens(monkeypatch, times=99)
    at = _click(console["page"](AUDIT_PAGE, mode="local"), "Load Local Audit Records")
    (banner,) = _banner(at)
    assert banner.startswith("INCOMPLETE EVIDENCE: executor-audit: read failed (AccessDenied).")
    assert "not evidence for sign-off" in banner
    assert any("Could not read records (AccessDenied, ref " in str(w.value) for w in at.warning)


def test_audit_page_local_only_executor_table_written_has_no_banner(console):
    (console["tmp"] / "executor_audit.jsonl").write_text(_audit_lines(2), encoding="utf-8")
    at = _click(console["page"](AUDIT_PAGE, mode="local"), "Load Local Audit Records")
    assert _banner(at) == []


def test_pan_page_banner_and_no_success_on_error(console, monkeypatch):
    results = {"evasion": [{"name": "e", "technique": "t", "path": "text", "action": "BLOCKED"},
                           {"name": "f", "technique": "t", "path": "text", "action": "ERROR"}],
               "safe": [{"name": "s", "path": "text", "action": "ALLOWED"}],
               "batch": {"total_input": 8, "allowed_count": 2, "rejected_count": 6}}
    monkeypatch.setattr(invoke_live, "run_pan_filter_live", lambda **k: results)
    at = _click(console["page"](PAN_PAGE), "Run PAN Filter")
    assert "evasion variants: 1 without a BLOCKED/ALLOWED verdict" in _banner(at)[0]
    assert not at.success


def test_pan_page_count_mismatch_blocks_success(console, monkeypatch):
    results = {"evasion": [{"name": "e", "technique": "t", "path": "text", "action": "BLOCKED"}],
               "safe": [{"name": "s", "path": "text", "action": "ALLOWED"}],
               "batch": {"total_input": 8, "allowed_count": 2, "rejected_count": 5}}
    monkeypatch.setattr(invoke_live, "run_pan_filter_live", lambda **k: results)
    at = _click(console["page"](PAN_PAGE), "Run PAN Filter")
    assert "batch ingress check: counts do not add up" in _banner(at)[0]
    assert not at.success


def test_pan_page_complete_run_succeeds_without_banner(console, monkeypatch):
    results = {"evasion": [{"name": "e", "technique": "t", "path": "text", "action": "BLOCKED"}],
               "safe": [{"name": "s", "path": "text", "action": "ALLOWED"}],
               "batch": {"total_input": 8, "allowed_count": 2, "rejected_count": 6}}
    monkeypatch.setattr(invoke_live, "run_pan_filter_live", lambda **k: results)
    at = _click(console["page"](PAN_PAGE), "Run PAN Filter")
    assert _banner(at) == [] and at.success
