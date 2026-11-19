"""
Test: Drift Control page (4.1) live fixes and PAN page (1.1) variants.

- Manual trip / release request / approval go to fsi-circuit-breaker-human
  with a single-use identity proof and, for a manual trip, a reason CODE
  from the circuit breaker's own enum.
- The dashboard only shows an engaged / re-enabled state when the Lambda
  actually returned it, and re-reads the real state afterwards. Release is
  two-step (request id, then approval of that id). Refusals render fixed
  text from the breaker's code/status, never its message, and
  the console never resets alarm state.
- Breach buttons publish the raw-count metrics the alarms evaluate, one
  datapoint per minute, and only report a trip on GOVERNANCE_HOLD; live
  publishing needs CONSOLE_ALLOW_DRIFT_INJECTION=true and a grant.
- The pages are gated on a signed-in console principal and
  every live call runs under that principal's own session.
- Every PAN evasion variant is blocked and every safe input passes through
  the same entry point the dashboard uses (local filter and Lambda handler).

All AWS calls are mocked; nothing here reaches AWS.
"""
import importlib.util
import io
import json
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

import pytest
from botocore.credentials import Credentials

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import boto3  # noqa: E402

import app.cloudwatch_metrics as cwm  # noqa: E402
import app.invoke_live as invoke_live  # noqa: E402
from app import console_auth, console_identity  # noqa: E402
from app.console_identity import Principal  # noqa: E402
from circuit_breaker.handler import KNOWN_MANUAL_TRIGGER_REASONS  # noqa: E402

DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "app", "dashboard.py")
CB_PAGE = "4.1 Drift Control — Circuit Breaker"
REQUEST_ID = "0" * 8 + "-0000-4000-8000-" + "0" * 12


# ─── Invoke payloads ──────────────────────────────────────────────────────────

class _FakeLambda:
    def __init__(self, response):
        self.payloads, self.functions = [], []
        self._response = response

    def invoke(self, FunctionName, InvocationType, Payload):
        self.functions.append(FunctionName)
        self.payloads.append(json.loads(Payload))
        return {"Payload": io.BytesIO(json.dumps(self._response).encode())}


class _FakeSession:
    """Explicit session: real static creds for presigning (no network)."""

    def __init__(self, lam):
        self.lam, self.services = lam, []

    def get_credentials(self):
        return Credentials("AKIDEXAMPLE", "secret")

    def client(self, service, **kwargs):
        self.services.append(service)
        return {"lambda": self.lam}[service]


def _forbid_ambient(monkeypatch):
    def _no_client(*a, **k):
        raise AssertionError("breaker helpers must use the explicit session")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, _no_client)


def _assert_proof(payload, action, target):
    from circuit_breaker.identity_proof import HEADER_RE
    query = parse_qs(urlsplit(payload["caller_identity_presigned_url"]).query)
    assert query["X-Amz-SignedHeaders"] == ["host;x-fsi-breaker-nonce"] and query["X-Amz-Expires"] == ["60"]
    m = HEADER_RE.fullmatch(payload["caller_identity_nonce"])
    assert m and m.group(1) == action and m.group(2) == target


def test_manual_trip_payload_has_identity_proof_and_known_reason_code(monkeypatch):
    lam = _FakeLambda({"status": "GOVERNANCE_HOLD"})
    _forbid_ambient(monkeypatch)
    session = _FakeSession(lam)

    invoke_live.run_circuit_breaker_live(session=session)

    payload = lam.payloads[0]
    assert payload["action"] == "invoke"
    _assert_proof(payload, "trip", "trip")
    assert payload["trigger_reason_code"] in KNOWN_MANUAL_TRIGGER_REASONS
    assert payload["trigger_reason_code"] == "OPERATOR_PRECAUTION"
    assert "trigger_reason" not in payload  # no free text
    assert lam.functions == ["fsi-circuit-breaker-human"]


def test_release_request_and_approve_payloads_have_identity_proof(monkeypatch):
    lam = _FakeLambda({"status": "RELEASE_PENDING"})
    _forbid_ambient(monkeypatch)
    invoke_live.request_release_live(session=_FakeSession(lam))
    invoke_live.approve_release_live(REQUEST_ID, session=_FakeSession(lam))
    req, approve = lam.payloads
    assert req["action"] == "request_release"
    _assert_proof(req, "request_release", "active-hold")
    assert approve["action"] == "approve_release" and approve["release_request_id"] == REQUEST_ID
    _assert_proof(approve, "approve_release", REQUEST_ID)
    assert lam.functions == ["fsi-circuit-breaker-human"] * 2
    with pytest.raises(ValueError):
        invoke_live.approve_release_live("../../x", session=_FakeSession(lam))


def test_console_never_invokes_the_automated_breaker():
    assert not hasattr(invoke_live, "re_enable_circuit_breaker_live")
    assert not hasattr(invoke_live, "CIRCUIT_BREAKER_LAMBDA")
    assert invoke_live.CIRCUIT_BREAKER_HUMAN_LAMBDA == "fsi-circuit-breaker-human"
    for name in os.listdir(os.path.join(PROJECT_ROOT, "app")):
        if name.endswith(".py"):
            with open(os.path.join(PROJECT_ROOT, "app", name), encoding="utf-8") as f:
                text = f.read()
            assert '"fsi-circuit-breaker"' not in text, name


# ─── Dashboard (AppTest) ──────────────────────────────────────────────────────

ACTIVE = {"status": "ACTIVE", "message": "Circuit breaker not engaged"}
HOLD = {"status": "GOVERNANCE_HOLD", "revoked_roles": invoke_live.AGENT_ROLES}
OK_ALARMS = {k: {"state": "OK", "reason": "", "updated": ""} for k in ("challenger", "guardrail", "volume")}


def _iam(held):
    # The agent roles carry no AWS managed policies (cdk_nag IAM4 fix), so an
    # un-held role reports an empty attached-policy list.
    return {r: {"held": held, "policies": ["governance-hold-deny-all"] if held else [],
                "error": None}
            for r in invoke_live.AGENT_ROLES}


OPERATOR_ARN = "arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice"


def _principal(roles=("operator", "approver")):
    return Principal(principal_id="local:alice", display_name="Alice", auth_mode="local",
                     roles=frozenset(roles), authenticated_at="2026-01-01T00:00:00+00:00",
                     aws_principal_arn=OPERATOR_ARN)


@pytest.fixture
def live_mocks(monkeypatch, tmp_path):
    """Patch every live helper the 4.1 page uses; tests override as needed.
    The console is signed in (local console auth on loopback) and the
    principal's governance sessions are fakes; ambient boto3 is forbidden."""
    monkeypatch.setenv("MODE", "live")
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.delenv("CONSOLE_ALLOW_DRIFT_INJECTION", raising=False)
    monkeypatch.setattr(console_auth, "_server_address", lambda: "127.0.0.1")
    sessions = {}

    def fake_governance_session(p, purpose):
        return sessions.setdefault(purpose, MagicMock(name=f"{purpose}-session"))
    monkeypatch.setattr(console_identity, "governance_session", fake_governance_session)
    _forbid_ambient(monkeypatch)
    mocks = {
        "run_circuit_breaker_live": MagicMock(),
        "request_release_live": MagicMock(),
        "approve_release_live": MagicMock(),
        "get_circuit_breaker_status_live": MagicMock(return_value=ACTIVE),
        "get_agent_role_hold_state_live": MagicMock(return_value=_iam(False)),
        "get_cloudwatch_alarm_states_live": MagicMock(return_value=OK_ALARMS),
        "run_drift_breach_live": MagicMock(),
    }
    for name, mock in mocks.items():
        monkeypatch.setattr(invoke_live, name, mock)
    mocks["sessions"] = sessions
    return mocks


def _cb_page(session=None, principal=None):
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60)
    at.session_state["principal"] = principal or _principal()
    for k, v in (session or {}).items():
        at.session_state[k] = v
    at.run()
    at.sidebar.radio[0].set_value(CB_PAGE).run()
    assert not at.exception, at.exception
    return at


def _click(at, label):
    [b for b in at.button if b.label == label][0].click().run()
    assert not at.exception, at.exception
    return at


def _texts(elements):
    return " ".join(e.value for e in elements)


def test_manual_trip_rejected_shows_error_and_no_engaged_state(live_mocks):
    live_mocks["run_circuit_breaker_live"].return_value = {
        "status": "REJECTED", "http_status": 403,
        "message": "Manual invoke denied: caller is not an authorized break-glass principal."}
    at = _click(_cb_page(), "Manual Circuit Breaker")

    errors = _texts(at.error)
    assert "refused" in errors and "403" in errors and "Not authorized for this action" in errors
    assert "break-glass" not in errors  # the breaker's message is never rendered
    assert "GOVERNANCE_HOLD" not in errors
    # Signed with the principal's own operator session, never ambient credentials.
    assert live_mocks["run_circuit_breaker_live"].call_args.kwargs["session"] is \
        live_mocks["sessions"]["operator"]
    assert at.session_state["ks_engaged"] is False
    assert "ks_result" not in at.session_state
    assert "IAM Policy Diff — Before vs After Circuit Breaker" not in _texts(at.subheader)
    # The real state was re-read after the action.
    live_mocks["get_circuit_breaker_status_live"].assert_called()
    live_mocks["get_agent_role_hold_state_live"].assert_called()


def test_manual_trip_success_reflects_reread_hold(live_mocks):
    live_mocks["run_circuit_breaker_live"].return_value = {
        "status": "GOVERNANCE_HOLD", "event_id": "e1", "trigger_reason": "x", "http_status": 503}
    live_mocks["get_circuit_breaker_status_live"].return_value = HOLD
    live_mocks["get_agent_role_hold_state_live"].return_value = _iam(True)
    at = _click(_cb_page(), "Manual Circuit Breaker")

    assert at.session_state["ks_engaged"] is True
    assert "GOVERNANCE_HOLD" in _texts(at.error)
    assert "governance-hold-deny-all" in _texts(at.markdown)


def test_reset_alarm_helpers_are_gone():
    assert not hasattr(invoke_live, "reset_cloudwatch_alarms_live")
    assert not hasattr(cwm, "reset_all_alarms") and not hasattr(cwm, "set_alarm_state")


def test_approve_rejected_keeps_state_and_does_not_reset_alarms(live_mocks):
    live_mocks["approve_release_live"].return_value = {
        "status": "REJECTED", "http_status": 403, "code": "SECOND_APPROVER_REQUIRED",
        "message": "a second, distinct approver on the same identity channel is required"}
    live_mocks["get_circuit_breaker_status_live"].return_value = HOLD
    live_mocks["get_agent_role_hold_state_live"].return_value = _iam(True)
    at = _cb_page({"ks_engaged": True, "ks_status": HOLD})
    at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    at = _click(at, "Approve release")

    assert live_mocks["approve_release_live"].call_args.args == (REQUEST_ID,)
    # The approver's own AWS session signs the approval.
    assert live_mocks["approve_release_live"].call_args.kwargs["session"] is \
        live_mocks["sessions"]["approver"]
    assert at.session_state["ks_engaged"] is True
    assert at.session_state["ks_status"]["status"] == "GOVERNANCE_HOLD"
    assert "ks_reenable" not in at.session_state
    assert "A different approver must approve this release" in _texts(at.error)
    assert "RE-ENABLED" not in _texts(at.success)


def test_approve_success_shows_active_and_never_resets_alarms(live_mocks):
    live_mocks["approve_release_live"].return_value = {
        "status": "ACTIVE", "message": "All agents re-enabled", "released_by": "arn:x"}
    at = _cb_page({"ks_engaged": True, "ks_status": HOLD})
    at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    at = _click(at, "Approve release")

    # No console SetAlarmState: the operator is told to wait for OK instead.
    assert "wait for the alarm to return to `OK`" in _texts(at.caption)
    assert at.session_state["ks_engaged"] is False
    assert "ACTIVE" in _texts(at.success)


def test_approve_with_malformed_request_id_never_invokes(live_mocks):
    at = _cb_page({"ks_engaged": True, "ks_status": HOLD})
    at.text_input(key="ks_approve_request_id").set_value("not-an-id")
    at = _click(at, "Approve release")
    live_mocks["approve_release_live"].assert_not_called()
    assert "36-character" in _texts(at.error)


def test_request_release_shows_request_id(live_mocks):
    live_mocks["request_release_live"].return_value = {
        "status": "RELEASE_PENDING", "release_request_id": REQUEST_ID, "expires_at": "later",
        "http_status": 202}
    live_mocks["get_circuit_breaker_status_live"].return_value = HOLD
    at = _click(_cb_page({"ks_engaged": True, "ks_status": HOLD}), "Request release")
    live_mocks["request_release_live"].assert_called_once()
    assert REQUEST_ID in _texts(at.success)
    assert at.session_state["ks_engaged"] is True


def test_check_status_unknown_is_not_reported_active(live_mocks):
    live_mocks["get_circuit_breaker_status_live"].return_value = {"error": {"errorMessage": "boom"}}
    at = _click(_cb_page(), "Check Status")
    assert "ACTIVE" not in _texts(at.success)
    assert "UNKNOWN" in _texts(at.warning)
    assert "boom" not in _texts(at.warning)


def test_volume_button_runs_breach_flow_and_reports_real_outcome(live_mocks, monkeypatch):
    monkeypatch.setenv("CONSOLE_ALLOW_DRIFT_INJECTION", "true")
    live_mocks["run_drift_breach_live"].return_value = {
        "outcome": "NOT_TRIPPED", "datapoints_published": 2, "alarm_state": "OK",
        "breaker": ACTIVE, "elapsed_seconds": 300}
    at = _click(_cb_page(), "Volume Spike Breach\n(4x detection volume)")
    live_mocks["run_drift_breach_live"].assert_called_once()
    assert live_mocks["run_drift_breach_live"].call_args.args[0] == "volume"
    grant = live_mocks["run_drift_breach_live"].call_args.kwargs["grant"]
    assert isinstance(grant, invoke_live.DriftInjectionGrant) and grant.metric_key == "volume"
    assert at.session_state["ks_engaged"] is False


def test_breach_buttons_refused_without_the_drift_injection_flag(live_mocks):
    at = _click(_cb_page(), "Volume Spike Breach\n(4x detection volume)")
    live_mocks["run_drift_breach_live"].assert_not_called()
    assert "Drift injection is disabled" in _texts(at.error)


@pytest.mark.parametrize("label", ["Manual Circuit Breaker", "Request release", "Check Status"])
def test_breaker_controls_gated_on_a_signed_in_principal(live_mocks, label):
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60).run()
    assert not at.exception
    assert label not in [b.label for b in at.button]
    assert len(at.sidebar.radio) == 0
    for name in ("run_circuit_breaker_live", "request_release_live", "get_circuit_breaker_status_live"):
        live_mocks[name].assert_not_called()


# ─── Metric publication ───────────────────────────────────────────────────────

@pytest.mark.parametrize("key,expected", [
    ("challenger", {"ClustersAssessed": (20, "Count"), "ChallengerDisputeCount": (12, "Count")}),
    ("guardrail", {"ClustersAssessed": (20, "Count"), "GuardrailInterventionCount": (4, "Count")}),
    ("volume", {"DetectionVolumeMultiplier": (4.2, "None")}),
])
def test_breach_metric_data_matches_alarm_metrics(key, expected):
    data = cwm.breach_metric_data(key)
    assert {m["MetricName"]: (m["Value"], m["Unit"]) for m in data} == expected
    assert all("Dimensions" not in m for m in data)


def test_rate_datapoints_breach_alarm_math():
    for key, count_name, threshold in (("challenger", "ChallengerDisputeCount", 0.51),
                                       ("guardrail", "GuardrailInterventionCount", 0.10)):
        values = {m["MetricName"]: m["Value"] for m in cwm.breach_metric_data(key)}
        assert values["ClustersAssessed"] >= 20
        assert values[count_name] / values["ClustersAssessed"] > threshold


def test_no_precomputed_rate_metrics_published():
    names = {m["MetricName"] for k in cwm.BREACH_DATAPOINTS for m in cwm.breach_metric_data(k)}
    assert "ChallengerDisputeRate" not in names
    assert "GuardrailInterventionRate" not in names


class _Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _run_flow(monkeypatch, key, breaker_states, start=60 * 1000 + 30):
    fake_cw = MagicMock()
    session = MagicMock()
    session.client.side_effect = lambda service, **k: {"cloudwatch": fake_cw}[service]
    _forbid_ambient(monkeypatch)
    monkeypatch.setenv("CONSOLE_ALLOW_DRIFT_INJECTION", "true")
    statuses = iter(breaker_states)
    monkeypatch.setattr(invoke_live, "get_circuit_breaker_status_live",
                        lambda *, session: next(statuses, breaker_states[-1]))
    monkeypatch.setattr(invoke_live, "get_cloudwatch_alarm_states_live", lambda *, session: OK_ALARMS)
    clock = _Clock(start)
    messages = []
    grant = invoke_live.DriftInjectionGrant(event_id="e", principal_id="local:alice", metric_key=key)
    result = invoke_live.run_drift_breach_live(key, progress=messages.append, session=session,
                                               grant=grant, clock=clock, sleep=clock.sleep)
    return result, fake_cw, messages


def test_breach_flow_publishes_datapoints_in_separate_minutes(monkeypatch):
    result, fake_cw, messages = _run_flow(monkeypatch, "challenger", [ACTIVE] * 8 + [HOLD])

    calls = fake_cw.put_metric_data.call_args_list
    assert len(calls) == 2
    minutes = set()
    for call in calls:
        assert call.kwargs["Namespace"] == "FSI/AgenticCompliance"
        data = call.kwargs["MetricData"]
        assert {m["MetricName"]: m["Value"] for m in data} == {
            "ClustersAssessed": 20, "ChallengerDisputeCount": 12}
        ts = {m["Timestamp"] for m in data}
        assert len(ts) == 1
        minutes.add(ts.pop().replace(second=0, microsecond=0))
    assert len(minutes) == 2
    assert result["outcome"] == "TRIPPED"
    assert any("Datapoint 2/2 published" in m for m in messages)
    assert any("GOVERNANCE_HOLD" in m for m in messages)


def test_breach_flow_never_claims_trip_without_hold(monkeypatch):
    result, fake_cw, messages = _run_flow(monkeypatch, "volume", [ACTIVE])
    assert result["outcome"] == "NOT_TRIPPED"
    assert fake_cw.put_metric_data.call_count == 2
    assert result["elapsed_seconds"] >= invoke_live.BREACH_TIMEOUT_SECONDS
    assert not any("GOVERNANCE_HOLD" in m for m in messages)


def test_breach_flow_skips_publish_when_already_held(monkeypatch):
    result, fake_cw, _ = _run_flow(monkeypatch, "guardrail", [HOLD])
    assert result["outcome"] == "ALREADY_HELD"
    fake_cw.put_metric_data.assert_not_called()


# ─── PAN variants ─────────────────────────────────────────────────────────────

def test_pan_variants_local_all_blocked_and_safe_pass():
    results = invoke_live.run_pan_filter_local()
    assert len(results["evasion"]) == len(invoke_live.PAN_EVASION_VARIANTS) >= 13
    assert [r["name"] for r in results["evasion"] if r["action"] != "BLOCKED"] == []
    assert [r["name"] for r in results["safe"] if r["action"] != "ALLOWED"] == []
    assert {r["path"] for r in results["evasion"]} == {"text", "batch"}


@pytest.fixture
def pan_lambda_handler(monkeypatch):
    import lambdas.pan_filter.pan_filter as pan_mod
    monkeypatch.setitem(sys.modules, "pan_filter", pan_mod)
    spec = importlib.util.spec_from_file_location(
        "_pan_handler_dashboard_test", os.path.join(PROJECT_ROOT, "lambdas/pan_filter/handler.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.handler


def test_pan_variants_via_lambda_handler_all_blocked_and_safe_pass(monkeypatch, pan_lambda_handler):
    events = []

    session = object()

    def fake_invoke(function_name, payload, *, session):
        events.append(payload)
        return json.loads(json.dumps(pan_lambda_handler(payload)))
    monkeypatch.setattr(invoke_live, "_invoke_lambda", fake_invoke)

    results = invoke_live.run_pan_filter_live(session=session)
    assert [r["name"] for r in results["evasion"] if r["action"] != "BLOCKED"] == []
    assert [r["name"] for r in results["safe"] if r["action"] != "ALLOWED"] == []
    # Split-field variants went through the batch entry point.
    assert sum(1 for e in events if "transactions" in e and len(e["transactions"]) == 1) == 4


def test_documented_residuals_not_listed_as_passing():
    """Documented PAN-filter residuals (e.g. two inserted letters) must not be demo cases."""
    all_inputs = json.dumps(invoke_live.PAN_EVASION_VARIANTS + invoke_live.PAN_SAFE_VARIANTS)
    assert "4532a0151b12830366" not in all_inputs


SUPERSEDED = {"status": "GOVERNANCE_HOLD", "code": "RELEASE_SUPERSEDED", "http_status": 409,
              "newer_hold_detected": True, "roles_reattached": list(invoke_live.AGENT_ROLES),
              "reattach_failures": {}}


@pytest.mark.parametrize("failures", [{}, {"executor-agent-role": {"error_id": "e", "error_class": "Throttling"}}])
def test_approve_superseded_by_a_newer_hold(live_mocks, failures):
    live_mocks["approve_release_live"].return_value = {**SUPERSEDED, "reattach_failures": failures}
    live_mocks["get_circuit_breaker_status_live"].return_value = HOLD
    live_mocks["get_agent_role_hold_state_live"].return_value = _iam(True)
    at = _cb_page({"ks_engaged": True, "ks_status": HOLD})
    at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    at = _click(at, "Approve release")
    errors = _texts(at.error)
    assert "A newer hold superseded this release" in errors
    if failures:
        assert "re-attach FAILED on executor-agent-role; re-trip now" in errors
    else:
        assert "the hold was restored" in errors
    assert "ks_reenable" not in at.session_state and "RE-ENABLED" not in _texts(at.success)


def test_approve_superseded_before_detach_uses_the_refusal_text(live_mocks):
    live_mocks["approve_release_live"].return_value = {
        "status": "GOVERNANCE_HOLD", "code": "RELEASE_SUPERSEDED", "http_status": 409}
    at = _cb_page({"ks_engaged": True, "ks_status": HOLD})
    at.text_input(key="ks_approve_request_id").set_value(REQUEST_ID)
    at = _click(at, "Approve release")
    assert "A newer hold superseded this release; request again (HTTP 409)" in _texts(at.error)
