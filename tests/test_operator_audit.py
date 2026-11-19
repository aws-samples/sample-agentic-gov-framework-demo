"""
Test: app/operator_audit.py.

Sink selection by MODE, the conditional PutItem through the principal's own
session, the append-only 0600 JSONL, input validation (enums, details
limits, ids only), and the SIGN_IN_FAILED rule: never DynamoDB, never any
AWS session (a session argument is a ValueError).
"""
import json
import os
import stat
from datetime import datetime
from unittest.mock import MagicMock

import boto3
import pytest

from app import operator_audit
from app.console_identity import NoAwsAuthorityError, Principal

SECRET_PASSWORD = "correct horse battery staple"
SECRET_TOKEN = "eyJraWQiOiJzZWNyZXQtdG9rZW4ifQ"  # gitleaks:allow -- fake fixture: base64 of {"kid":"secret-token"}, a redaction sentinel


def _principal(**kw):
    base = dict(principal_id="local:alice", display_name="Alice", auth_mode="local",
                roles=frozenset({"operator"}), authenticated_at="2026-01-01T00:00:00+00:00")
    base.update(kw)
    return Principal(**base)


@pytest.fixture(autouse=True)
def out_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("MODE", "local")

    def refuse(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    monkeypatch.setattr(boto3, "client", refuse)
    monkeypatch.setattr(boto3, "resource", refuse)
    monkeypatch.setattr(boto3, "Session", refuse)
    return tmp_path


def _lines(out_dir):
    path = out_dir / operator_audit.JSONL_NAME
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def _fake_session():
    table = MagicMock()
    resource = MagicMock()
    resource.Table.return_value = table
    session = MagicMock()
    session.resource.return_value = resource
    return session, resource, table


def test_local_mode_appends_jsonl_0600(out_dir):
    p = _principal(aws_principal_arn="arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice")
    event_id = operator_audit.record_console_action(p, "PIPELINE_RUN", "REQUESTED", target="det-123",
                                                    details={"compliance_source": "cached", "clusters": 2})
    operator_audit.record_console_action(p, "PIPELINE_RUN", "COMPLETED", target="det-123", outcome="OK")
    lines = _lines(out_dir)
    assert [l["phase"] for l in lines] == ["REQUESTED", "COMPLETED"]
    first = lines[0]
    assert first["event_id"] == event_id and first["event_type"] == "CONSOLE_ACTION"
    assert first["actor_id"] == "local:alice" and first["actor_display"] == "Alice"
    assert first["actor_auth_mode"] == "local" and first["actor_aws_arn"].endswith("/alice")
    assert first["details"] == {"compliance_source": "cached", "clusters": 2}
    assert first["record_day"] == datetime.fromisoformat(first["timestamp"]).date().isoformat()
    assert stat.S_IMODE(os.stat(out_dir / operator_audit.JSONL_NAME).st_mode) == 0o600


def test_live_mode_conditional_put_through_given_session(monkeypatch):
    monkeypatch.setenv("MODE", "live")
    session, resource, table = _fake_session()
    event_id = operator_audit.record_console_action(_principal(), "BREAKER_TRIP", "REQUESTED", session=session)
    session.resource.assert_called_once_with("dynamodb", region_name=operator_audit.REGION)
    resource.Table.assert_called_once_with("operator-audit")
    kwargs = table.put_item.call_args.kwargs
    assert kwargs["ConditionExpression"] == "attribute_not_exists(event_id)"
    assert kwargs["Item"]["event_id"] == event_id and kwargs["Item"]["actor_id"] == "local:alice"


def test_live_mode_without_session_fails_closed(monkeypatch, out_dir):
    monkeypatch.setenv("MODE", "live")
    with pytest.raises(NoAwsAuthorityError):
        operator_audit.record_console_action(_principal(), "AUDIT_READ", "REQUESTED")
    assert _lines(out_dir) == []


def test_live_mode_put_error_propagates(monkeypatch):
    monkeypatch.setenv("MODE", "live")
    session, _, table = _fake_session()
    table.put_item.side_effect = RuntimeError("denied")
    with pytest.raises(RuntimeError):
        operator_audit.record_console_action(_principal(), "SOX_TEST", "REQUESTED", session=session)


def test_explicit_jsonl_sink_in_live_mode(monkeypatch, out_dir):
    monkeypatch.setenv("MODE", "live")
    operator_audit.record_console_action(_principal(), "SIGN_IN", "COMPLETED", sink=operator_audit.SINK_JSONL)
    assert [l["action"] for l in _lines(out_dir)] == ["SIGN_IN"]


class TestSignInFailed:
    def test_session_argument_is_a_programming_error(self, out_dir):
        session, _, table = _fake_session()
        with pytest.raises(ValueError):
            operator_audit.record_console_action(None, "SIGN_IN_FAILED", "FAILED", session=session)
        table.put_item.assert_not_called()
        assert _lines(out_dir) == []

    @pytest.mark.parametrize("mode", ["local", "live"])
    def test_always_jsonl_never_dynamodb(self, monkeypatch, out_dir, mode):
        monkeypatch.setenv("MODE", mode)
        operator_audit.record_console_action(None, "SIGN_IN_FAILED", "FAILED", attempted_operator_id="alice",
                                             sink=operator_audit.SINK_DYNAMODB)
        (line,) = _lines(out_dir)
        assert line["attempted_operator_id"] == "alice"
        assert not any(k.startswith("actor_") for k in line)

    @pytest.mark.parametrize("attempted", ["Alice; DROP", "x" * 100, None, 7, "' OR 1=1"])
    def test_invalid_attempted_id_recorded_as_invalid(self, out_dir, attempted):
        operator_audit.record_console_action(None, "SIGN_IN_FAILED", "FAILED", attempted_operator_id=attempted)
        assert _lines(out_dir)[0]["attempted_operator_id"] == "<invalid>"


@pytest.mark.parametrize("kwargs", [
    {"action": "DELETE_EVERYTHING"},
    {"phase": "STARTED"},
    {"details": {f"k{i}": 1 for i in range(21)}},
    {"details": {"k": "x" * 257}},
    {"details": {"k": {"nested": 1}}},
    {"details": {"k": True}},
    {"details": {"Bad Key": 1}},
    {"details": ["not", "a", "dict"]},
    {"target": '{"payload": "body"}'},
    {"target": "x" * 257},
    {"outcome": "has spaces"},
])
def test_invalid_calls_rejected_before_any_write(out_dir, kwargs):
    call = {"principal": _principal(), "action": "PAN_TEST", "phase": "REQUESTED"}
    call.update(kwargs)
    with pytest.raises(ValueError):
        operator_audit.record_console_action(**call)
    assert _lines(out_dir) == []


def test_principal_required_except_sign_in_failed(out_dir):
    with pytest.raises(ValueError):
        operator_audit.record_console_action(None, "PIPELINE_RUN", "REQUESTED")
    with pytest.raises(ValueError):
        operator_audit.record_console_action({"actor_id": "forged"}, "PIPELINE_RUN", "REQUESTED")


def test_records_never_contain_secrets(out_dir):
    p = _principal()
    operator_audit.record_console_action(p, "SIGN_IN", "COMPLETED")
    operator_audit.record_console_action(None, "SIGN_IN_FAILED", "FAILED", attempted_operator_id="alice")
    operator_audit.record_console_action(p, "GATE_RUN", "FAILED", outcome="EXIT_1", details={"error_ref": "1a2b3c4d"})
    raw = (out_dir / operator_audit.JSONL_NAME).read_text()
    assert SECRET_PASSWORD not in raw and SECRET_TOKEN not in raw
    assert "password" not in raw.lower() and "Traceback" not in raw


def test_action_enum_is_fixed():
    assert operator_audit.ACTIONS == {
        "PIPELINE_RUN", "PAN_TEST", "INJECTION_TEST", "SOX_TEST", "BREAKER_TRIP", "RELEASE_REQUEST",
        "RELEASE_APPROVE", "DRIFT_INJECTION", "AUDIT_READ", "GATE_RUN", "MODEL_REGISTRY_VIEW",
        "SIGN_IN", "SIGN_OUT", "SIGN_IN_FAILED"}


# ─── Dashboard stamping ────────────────────────

DASHBOARD_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "dashboard.py")
REQUEST_ID = "0" * 8 + "-0000-4000-8000-" + "0" * 12
CB_PAGE = "4.1 Drift Control — Circuit Breaker"

# (page, button label, invoke_live helper the button reaches, audit action)
GOVERNANCE_BUTTONS = [
    ("Run Pipeline (Happy Path)", "Run Full Pipeline", "run_detection_local", "PIPELINE_RUN"),
    ("1.1 Data & Access Controls — PAN Filter", None, "run_pan_filter_local", "PAN_TEST"),
    ("1.2 Data & Access Controls — Prompt Injection", "Run Injection Attacks (4 Variants)",
     "test_prompt_injection_local", "INJECTION_TEST"),
    ("1.3 Data & Access Controls — SOX Separation of Duties", "Attempt 5 Forbidden Actions",
     "test_sox_rejection_local", "SOX_TEST"),
    (CB_PAGE, "Manual Circuit Breaker", "run_circuit_breaker_local", "BREAKER_TRIP"),
    (CB_PAGE, "Request release", "request_release_local", "RELEASE_REQUEST"),
    (CB_PAGE, "Approve release", "approve_release_local", "RELEASE_APPROVE"),
    (CB_PAGE, "Guardrail Rate Breach\n(inject malicious data)", "run_circuit_breaker_local", "DRIFT_INJECTION"),
]


@pytest.fixture
def dashboard(monkeypatch, out_dir):
    """Local console (loopback) with a signed-in approver principal; every
    reached invoke_live helper and every audit write is logged in order."""
    import app.invoke_live as invoke_live
    from app import console_auth, console_identity

    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0")
    monkeypatch.setattr(console_auth, "_server_address", lambda: "127.0.0.1")
    monkeypatch.setattr(console_identity, "governance_session",
                        lambda p, purpose: (_ for _ in ()).throw(NoAwsAuthorityError()))
    log = []
    real_record = operator_audit.record_console_action

    def recording(principal, action, phase, *a, **k):
        log.append(("audit", action, phase))
        return real_record(principal, action, phase, *a, **k)
    monkeypatch.setattr(operator_audit, "record_console_action", recording)

    fake_results = {
        "run_detection_local": lambda *a, **k: {"detection_id": "det-1", "transaction_count": 1,
                                                "flagged_clusters": []},
        "run_pan_filter_local": lambda *a, **k: {"evasion": [], "safe": []},
        "test_prompt_injection_local": lambda *a, **k: {"clusters_assessed": []},
        "test_sox_rejection_local": lambda *a, **k: {"error": "SOX_VIOLATION", "message": "x"},
        "run_circuit_breaker_local": lambda *a, **k: {"status": "GOVERNANCE_HOLD", "event_id": "e1"},
        "request_release_local": lambda *a, **k: {"status": "RELEASE_PENDING", "release_request_id": REQUEST_ID},
        "approve_release_local": lambda *a, **k: {"status": "ACTIVE"},
    }
    for name, fn in fake_results.items():
        def wrapper(*a, _name=name, _fn=fn, **k):
            log.append(("helper", _name))
            return _fn(*a, **k)
        monkeypatch.setattr(invoke_live, name, wrapper)
    monkeypatch.setattr(invoke_live, "get_circuit_breaker_status_local", lambda: {"status": "ACTIVE"})

    def open_page(name, principal=None):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60)
        at.session_state["principal"] = principal or _principal(roles=frozenset({"approver"}))
        at.run()
        at.sidebar.radio[0].set_value(name).run()
        assert not at.exception, at.exception
        return at
    return {"open": open_page, "log": log}


def _press(at, label):
    if label == "Approve release":
        at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    button = [b for b in at.button if (label is None and b.label.startswith("Run PAN Filter"))
              or b.label == label][0]
    button.click().run()
    assert not at.exception, at.exception
    return at


def _texts(at):
    return " ".join(str(e.value) for kind in ("error", "warning", "success", "markdown")
                    for e in getattr(at, kind))


@pytest.mark.parametrize("page,label,helper,action", GOVERNANCE_BUTTONS,
                         ids=[b[3] + ":" + (b[1] or "pan").split("\n")[0] for b in GOVERNANCE_BUTTONS])
def test_requested_record_with_actor_precedes_the_helper(dashboard, out_dir, page, label, helper, action):
    _press(dashboard["open"](page), label)
    log = dashboard["log"]
    assert ("helper", helper) in log
    requested = log.index(("audit", action, "REQUESTED"))
    assert requested < log.index(("helper", helper))
    assert ("audit", action, "COMPLETED") in log[requested:]
    line = next(l for l in _lines(out_dir) if l["action"] == action and l["phase"] == "REQUESTED")
    assert line["actor_id"] == "local:alice"
    done = next(l for l in _lines(out_dir) if l["action"] == action and l["phase"] == "COMPLETED")
    assert done["details"]["request_event_id"] == line["event_id"]


@pytest.mark.parametrize("page,label,helper,action", GOVERNANCE_BUTTONS,
                         ids=[b[3] + ":" + (b[1] or "pan").split("\n")[0] for b in GOVERNANCE_BUTTONS])
def test_requested_write_failure_blocks_the_helper(dashboard, monkeypatch, page, label, helper, action):
    def failing(principal, act, phase, *a, **k):
        dashboard["log"].append(("audit", act, phase))
        raise OSError("disk full: /Users/secret/cached_output")
    monkeypatch.setattr(operator_audit, "record_console_action", failing)
    at = _press(dashboard["open"](page), label)
    assert ("helper", helper) not in dashboard["log"]
    text = _texts(at)
    assert "Action not performed: the audit record could not be written (ref " in text
    assert "/Users/secret" not in text and "disk full" not in text


def test_completed_write_failure_still_shows_result_with_warning(dashboard, monkeypatch):
    real = operator_audit.record_console_action

    def fail_completed(principal, action, phase, *a, **k):
        if phase == "COMPLETED":
            raise OSError("disk full")
        return real(principal, action, phase, *a, **k)
    monkeypatch.setattr(operator_audit, "record_console_action", fail_completed)
    at = _press(dashboard["open"](CB_PAGE), "Request release")
    assert REQUEST_ID in _texts(at)  # the action's result is shown
    assert "Action completed but its outcome could not be recorded (ref " in _texts(at)


def test_dashboard_records_never_contain_secrets(dashboard, out_dir, monkeypatch):
    import app.invoke_live as invoke_live
    token = "T" * 43
    monkeypatch.setattr(invoke_live, "run_detection_local",
                        lambda *a, **k: {"detection_id": "det-1", "transaction_count": 1, "flagged_clusters": []})
    monkeypatch.setattr(invoke_live, "run_compliance_local",
                        lambda *a, **k: {"compliance_id": "c1", "clusters_assessed": [], "dispatch_token": token})
    monkeypatch.setattr(invoke_live, "run_executor_local", lambda *a, **k: {"actions": []})
    at = _press(dashboard["open"]("Run Pipeline (Happy Path)"), "Run Full Pipeline")
    assert "dispatch_token" not in at.session_state["pipeline_compliance"]  # token never kept in session state
    _press(dashboard["open"](CB_PAGE), "Manual Circuit Breaker")
    raw = (out_dir / operator_audit.JSONL_NAME).read_text()
    assert token not in raw and SECRET_PASSWORD not in raw and "Traceback" not in raw
    assert "clusters_assessed" not in raw and "flagged_clusters" not in raw  # no payload bodies
