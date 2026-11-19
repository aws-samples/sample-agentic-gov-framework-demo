"""
Local console: cached demo INPUTS vs runtime OUTPUTS.

detection_result.json / compliance_result.json are read-only cached demo
inputs under <repo>/cached_output/; a local run never writes them. With
LOCAL_OUTPUT_DIR pointing elsewhere, the audit trail (2.1) must still show
them (an output-dir copy wins), runtime outputs stay in LOCAL_OUTPUT_DIR,
nothing is written into the repo, and empty tabs say why they're empty.
Temp dirs only; ambient boto3 is refused; no AWS.
"""
import builtins
import hashlib
import json
import os
from unittest.mock import MagicMock

import pytest

from app import evidence_status
import app.invoke_live as invoke_live

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "app", "dashboard.py")
REPO_CACHED = os.path.join(PROJECT_ROOT, "cached_output")
AUDIT_PAGE = "2.1 Decision Explainability — Audit Trail"
MODEL_PAGE = "5.2 Deployment Control — Model Assurance"


def _repo_json(name):
    with open(os.path.join(REPO_CACHED, name), encoding="utf-8") as f:
        return json.load(f)


def _repo_snapshot():
    """Names + content hashes of <repo>/cached_output (to prove no writes)."""
    snap = {}
    for name in sorted(os.listdir(REPO_CACHED)):
        path = os.path.join(REPO_CACHED, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                snap[name] = hashlib.sha256(f.read()).hexdigest()
        else:
            snap[name] = "dir"
    return snap


def _audit_lines(n):
    return "".join(json.dumps({"action_id": f"a{i}", "timestamp": f"2026-01-01T00:00:{i:02d}+00:00"}) + "\n"
                   for i in range(n))


@pytest.fixture
def out(tmp_path, monkeypatch):
    """Empty LOCAL_OUTPUT_DIR; governance state read from a temp root."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(out_dir))
    monkeypatch.setattr(invoke_live, "PROJECT_ROOT", str(tmp_path / "root"))
    monkeypatch.setattr(invoke_live, "_LOCAL_READ_RETRY_DELAYS", (0, 0, 0))
    return out_dir


# ─── Unit: cached_input_path ─────────────────────────────────────────────────

def test_cached_input_falls_back_to_repo(out):
    path, label, checked = invoke_live.cached_input_path("detection_result.json")
    assert path == os.path.join(REPO_CACHED, "detection_result.json")
    assert label == "cached_output/" and checked == ["LOCAL_OUTPUT_DIR", "cached_output/"]


def test_cached_input_in_output_dir_wins(out):
    (out / "detection_result.json").write_text("{}", encoding="utf-8")
    path, label, _ = invoke_live.cached_input_path("detection_result.json")
    assert path == str(out / "detection_result.json") and label == "LOCAL_OUTPUT_DIR"


def test_cached_input_without_local_output_dir(monkeypatch):
    monkeypatch.delenv("LOCAL_OUTPUT_DIR", raising=False)
    path, label, checked = invoke_live.cached_input_path("compliance_result.json")
    assert path == os.path.join(REPO_CACHED, "compliance_result.json")
    assert label == "cached_output/" and checked == ["cached_output/"]
    assert invoke_live.local_output_dir() == REPO_CACHED


# ─── Unit: read_audit_trail_local ────────────────────────────────────────────

def test_empty_output_dir_reads_repo_cached_inputs(out):
    (out / "executor_audit.jsonl").write_text(_audit_lines(2), encoding="utf-8")
    data = invoke_live.read_audit_trail_local(include_narratives=True)
    assert data["detection-results"] == [_repo_json("detection_result.json")]
    assert data["compliance-decisions"] == [_repo_json("compliance_result.json")]
    assert [r["action_id"] for r in data["executor-audit"]] == ["a1", "a0"]
    assert data["governance-audit"] == []
    assert evidence_status.audit_incomplete_reasons(data) == []
    assert data["_cached_inputs"]["detection-results"]["read_from"] == "cached_output/"
    assert data["_output_dir"] == "LOCAL_OUTPUT_DIR"


def test_output_dir_copy_takes_precedence(out):
    (out / "compliance_result.json").write_text(json.dumps({"compliance_id": "override"}), encoding="utf-8")
    data = invoke_live.read_audit_trail_local()
    assert data["compliance-decisions"] == [{"compliance_id": "override"}]
    assert data["detection-results"][0]["detection_id"] == _repo_json("detection_result.json")["detection_id"]
    assert data["_cached_inputs"]["compliance-decisions"]["read_from"] == "LOCAL_OUTPUT_DIR"


def test_unreadable_output_dir_copy_is_failed_read_not_fallback(out):
    (out / "detection_result.json").mkdir()   # exists, can't be read as a file
    data = invoke_live.read_audit_trail_local()
    assert "error_ref" in data["detection-results"][0]
    assert evidence_status.audit_incomplete_reasons(data)[0].startswith("detection-results: read failed")


def test_unreadable_repo_cached_input_is_failed_read(out, tmp_path, monkeypatch):
    repo = tmp_path / "repo_cached"
    repo.mkdir()
    (repo / "compliance_result.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(invoke_live, "CACHED_INPUTS_DIR", str(repo))
    target = str(repo / "compliance_result.json")
    real_open = builtins.open

    def deny(path, *a, **k):
        if str(path) == target:
            raise PermissionError(13, "Operation not permitted")
        return real_open(path, *a, **k)
    monkeypatch.setattr(builtins, "open", deny)
    data = invoke_live.read_audit_trail_local()
    assert data["compliance-decisions"][0]["error_code"] == "AccessDenied"
    assert evidence_status.audit_incomplete_reasons(data) == [
        "compliance-decisions: read failed (AccessDenied)"]


def test_unset_local_output_dir_unchanged(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCAL_OUTPUT_DIR", raising=False)
    monkeypatch.setattr(invoke_live, "PROJECT_ROOT", str(tmp_path))
    data = invoke_live.read_audit_trail_local(include_narratives=True)
    assert data["detection-results"] == [_repo_json("detection_result.json")]
    assert data["compliance-decisions"] == [_repo_json("compliance_result.json")]
    assert data["_output_dir"] == "cached_output/"


def test_readers_never_write_repo_cached_output(out):
    before = _repo_snapshot()
    invoke_live.read_audit_trail_local()
    invoke_live.read_audit_trail_local(include_narratives=True)
    assert _repo_snapshot() == before
    assert os.listdir(out) == []


# ─── AppTest (MODE=local) ────────────────────────────────────────────────────

@pytest.fixture
def console(monkeypatch, out):
    import boto3
    from app import console_auth, console_identity
    from app.console_identity import Principal
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
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

    def page(name):
        from streamlit.testing.v1 import AppTest
        monkeypatch.setenv("MODE", "local")
        at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60)
        at.session_state["principal"] = principal
        at.run()
        at.sidebar.radio[0].set_value(name).run()
        assert not at.exception, at.exception
        return at
    return page


def _load(at):
    [b for b in at.button if b.label.startswith("Load Local Audit Records")][0].click().run()
    assert not at.exception, at.exception
    return at


def _banner(at):
    return [e.value for e in at.error if str(e.value).startswith("INCOMPLETE EVIDENCE")]


def _infos(at):
    return [str(i.value) for i in at.info]


def _captions(at):
    return [str(c.value) for c in at.caption]


def test_audit_page_empty_output_dir_shows_cached_records(console, out):
    (out / "executor_audit.jsonl").write_text(_audit_lines(1), encoding="utf-8")
    before = _repo_snapshot()
    at = _load(console(AUDIT_PAGE))
    assert _banner(at) == []
    shown = [str(j.value) for j in at.json]
    det_id = _repo_json("detection_result.json")["detection_id"]
    comp_id = _repo_json("compliance_result.json")["compliance_id"]
    assert any(det_id in s for s in shown) and any(comp_id in s for s in shown)
    assert any('"a0"' in s for s in shown)   # executor-audit from the temp dir
    caps = _captions(at)
    assert ("Cached demo detection record (from cached_output/), not a record of your pipeline run."
            in caps)
    assert ("Cached demo compliance record (from cached_output/), not a record of your pipeline run."
            in caps)
    assert not any("No compliance records found" in i for i in _infos(at))
    assert _repo_snapshot() == before


def test_audit_page_output_dir_copy_wins(console, out):
    (out / "detection_result.json").write_text(json.dumps({"detection_id": "from-out-dir"}), encoding="utf-8")
    at = _load(console(AUDIT_PAGE))
    shown = [str(j.value) for j in at.json]
    assert any("from-out-dir" in s for s in shown)
    assert ("Cached demo detection record (from LOCAL_OUTPUT_DIR), not a record of your pipeline run."
            in _captions(at))


def test_audit_page_unreadable_cached_input_keeps_banner(console, out):
    (out / "compliance_result.json").mkdir()
    at = _load(console(AUDIT_PAGE))
    assert "compliance-decisions: read failed" in _banner(at)[0]


def test_audit_page_genuinely_empty_tables_have_accurate_messages(console, out, tmp_path, monkeypatch):
    monkeypatch.setattr(invoke_live, "CACHED_INPUTS_DIR", str(tmp_path / "no-cached-inputs"))
    at = _load(console(AUDIT_PAGE))
    assert _banner(at) == []
    infos = _infos(at)
    assert infos == [
        "No cached demo detection record found in LOCAL_OUTPUT_DIR or cached_output/. "
        "Local runs don't write this table; it comes from the cached demo data.",
        "No cached demo compliance record found in LOCAL_OUTPUT_DIR or cached_output/. "
        "Local runs don't write this table; it comes from the cached demo data.",
        "No executor audit records in LOCAL_OUTPUT_DIR yet. Run the pipeline in local mode first.",
        "No governance hold recorded. The circuit breaker has not been triggered.",
    ]
    assert not any(str(tmp_path) in i or os.path.expanduser("~") in i for i in infos)


def test_model_assurance_page_uses_output_dir_copy(console, out):
    comp = {"clusters_assessed": [{"model_metadata": {"sar_call": {"model_id": "unlisted.model-x"}}}]}
    (out / "compliance_result.json").write_text(json.dumps(comp), encoding="utf-8")
    at = console(MODEL_PAGE)
    assert any("unlisted.model-x" in str(m.value) for m in at.markdown)
