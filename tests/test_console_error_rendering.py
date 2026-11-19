"""
Test: app/safe_errors.py. Unit part; the AppTest
rendering cases and the AST guard land with the dashboard wiring.

Operator-facing messages never contain exception text (account ids, role
names, table names, regions, paths); the full exception is still logged
server-side under the same error id.
"""
import logging

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

from app import safe_errors

LEAKY = ("User: arn:aws:sts::123456789012:assumed-role/secret-role/x is not authorized "
         "on table executor-audit in us-east-1 (/Users/secret/path)")
FORBIDDEN = ("123456789012", "secret-role", "executor-audit", "us-east-1", "/Users/secret")


def _client_error(code, message=LEAKY, op="Query"):
    return ClientError({"Error": {"Code": code, "Message": message}}, op)


def test_report_hides_exception_text_and_logs_it(caplog):
    exc = _client_error("AccessDeniedException")
    with caplog.at_level(logging.ERROR, logger="app.safe_errors"):
        message, error_id = safe_errors.report(exc, "Audit read")
    assert message == f"Audit read failed (ref {error_id[:8]}). Details are in the console log."
    assert "ref " in message
    for needle in FORBIDDEN:
        assert needle not in message
    (record,) = [r for r in caplog.records if error_id in r.getMessage()]
    assert record.exc_info[1] is exc  # full detail kept server-side


def test_report_ids_are_unique():
    exc = ValueError("/Users/secret/path")
    assert safe_errors.report(exc, "x")[1] != safe_errors.report(exc, "x")[1]


@pytest.mark.parametrize("code,expected", [
    ("AccessDeniedException", "AccessDenied"), ("AccessDenied", "AccessDenied"),
    ("UnauthorizedOperation", "AccessDenied"), ("NotAuthorizedException", "AccessDenied"),
    ("ThrottlingException", "Throttling"), ("Throttling", "Throttling"),
    ("TooManyRequestsException", "Throttling"), ("ProvisionedThroughputExceededException", "Throttling"),
    ("ResourceNotFoundException", "NotFound"), ("NoSuchEntity", "NotFound"), ("NoSuchKey", "NotFound"),
    ("ServiceUnavailable", "Unavailable"), ("InternalServerError", "Unavailable"),
    ("ValidationException", "Error"),
])
def test_classify_from_code_only(code, expected):
    assert safe_errors.classify(_client_error(code)) == expected


def test_classify_non_client_errors():
    assert safe_errors.classify(EndpointConnectionError(endpoint_url="https://x")) == "Unavailable"
    assert safe_errors.classify(ValueError(LEAKY)) == "Error"


def test_credential_errors():
    assert safe_errors.is_credential_error(NoCredentialsError())
    assert safe_errors.is_credential_error(_client_error("ExpiredToken"))
    assert not safe_errors.is_credential_error(_client_error("AccessDeniedException"))
    message, error_id = safe_errors.report_credentials(NoCredentialsError(), "Pipeline run")
    assert message == ("AWS session requires MFA or has expired; refresh credentials "
                       f"(ref {error_id[:8]})")


@pytest.mark.parametrize("status,expected", [
    (400, "The request was rejected as malformed"),
    (409, "This detection was already decided or isn't recorded"),
    (411, "Request rejected (length required)"),
    (413, "Request too large"),
    (429, "Agent busy; try again shortly"),
    (503, "Temporarily unavailable"),
    (500, "Agent error"),
    (418, "Agent error"),
    (None, "Agent error"),
])
def test_agentcore_status_messages(status, expected):
    assert safe_errors.agentcore_status_message(status) == expected


def test_status_messages_carry_no_placeholders():
    for message in safe_errors.AGENTCORE_STATUS_MESSAGES.values():
        assert "{" not in message and "%" not in message


# ─── AST guards over app/ ─────────────────────────────────────────

import ast  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(PROJECT_ROOT, "app")
DASHBOARD_PATH = os.path.join(APP_DIR, "dashboard.py")
_ALLOWED_EXC_CONSUMERS = {"report", "classify", "report_credentials", "is_credential_error",
                          "_agent_error_text", "_audit_error_entry", "_runtime_error_status",
                          "_extract_error_body", "_client_error_code"}
# Console exception types whose text is fixed by construction (a constant, a
# per-code message table, or a safe_errors reference string); rendering them
# is how the console shows "Not authorized" / "No AWS authority" etc.
FIXED_MESSAGE_EXCEPTIONS = {"ActionRefused", "DriftInjectionRefused", "ConsoleAuthConfigError",
                            "ProfileConfigError", "ConsoleAuthzError", "NoAwsAuthorityError"}


def _caught_names(handler) -> set:
    if handler.type is None:
        return set()
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return {ast.unparse(t).split(".")[-1] for t in types}


def _app_sources():
    for name in sorted(os.listdir(APP_DIR)):
        if name.endswith(".py"):
            path = os.path.join(APP_DIR, name)
            with open(path, encoding="utf-8") as f:
                yield name, ast.parse(f.read(), filename=path)


def _call_name(call: ast.Call) -> str:
    return ast.unparse(call.func)


def _is_allowed_consumer(call: ast.Call) -> bool:
    name = _call_name(call)
    return name.startswith("logger.") or name.split(".")[-1] in _ALLOWED_EXC_CONSUMERS


def _exception_text_violations(tree) -> list:
    """f-strings / str() / repr() / format() / Streamlit calls that reference a
    name bound by `except ... as <name>`, outside logger.* and the safe_errors
    helpers."""
    violations = []
    for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler) and n.name):
        caught = _caught_names(handler)
        if caught and caught <= FIXED_MESSAGE_EXCEPTIONS:
            continue
        name = handler.name
        allowed = set()
        for node in ast.walk(handler):
            if isinstance(node, ast.Call) and _is_allowed_consumer(node):
                allowed.update(id(sub) for sub in ast.walk(node))

        def refs(node):
            # A reference wrapped by an allowed consumer (logger.*, report(),
            # classify(), ...) doesn't count: those never return exception text.
            return any(isinstance(sub, ast.Name) and sub.id == name and id(sub) not in allowed
                       for sub in ast.walk(node))

        for node in ast.walk(handler):
            if id(node) in allowed:
                continue
            if isinstance(node, ast.JoinedStr) and refs(node):
                violations.append(ast.unparse(node))
            elif isinstance(node, ast.Call):
                fn = _call_name(node)
                args = list(node.args) + [k.value for k in node.keywords]
                if fn in ("str", "repr", "format") and any(refs(a) for a in args):
                    violations.append(ast.unparse(node))
                elif fn.endswith(".format") and any(refs(a) for a in args):
                    violations.append(ast.unparse(node))
                elif fn.startswith(("st.", "status.")) and any(refs(a) for a in args):
                    violations.append(ast.unparse(node))
    return violations


def test_ast_guard_no_exception_text_reaches_the_console():
    found = {name: _exception_text_violations(tree) for name, tree in _app_sources()}
    assert {k: v for k, v in found.items() if v} == {}


def test_ast_guard_no_st_exception_calls():
    for name, tree in _app_sources():
        calls = [ast.unparse(n) for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and _call_name(n).endswith("st.exception")]
        assert calls == [], name


def test_ast_guard_detects_a_planted_violation():
    planted = ast.parse(
        "try:\n    x()\nexcept Exception as e:\n    st.error(f'failed: {e}')\n    logger.error('%s', e)\n")
    assert "f'failed: {e}'" in _exception_text_violations(planted)
    fixed = ast.parse("try:\n    x()\nexcept ActionRefused as r:\n    st.error(r.message)\n")
    assert _exception_text_violations(fixed) == []


def test_fixed_message_exceptions_carry_fixed_text():
    from app import console_auth, console_identity
    from app import invoke_live
    from governance_common import aws_profile_check
    assert str(console_identity.NoAwsAuthorityError()) == console_identity.NO_AUTHORITY_MESSAGE
    assert str(console_identity.ConsoleAuthzError()) == console_identity.NOT_AUTHORIZED_MESSAGE
    for code, message in aws_profile_check.MESSAGES.items():
        assert aws_profile_check.ProfileConfigError(code).message == message
    for code, message in console_auth.CONFIG_MESSAGES.items():
        assert console_auth.ConsoleAuthConfigError(code).message == message
    # Every ActionRefused / DriftInjectionRefused raise site passes a constant,
    # a fixed-message attribute, or safe_errors output (never exception text):
    # the guard above checks those sites like any other except handler.
    assert invoke_live.DRIFT_INJECTION_DISABLED_MESSAGE.startswith("Drift injection is disabled")


def _boto3_aliases(tree) -> set:
    aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(a.asname or a.name for a in node.names if a.name == "boto3")
    return aliases


def test_no_ambient_boto3_constructors_in_app_outside_identity_and_auth():
    """Every live AWS call in app/ runs under an
    explicit governance session; only console_identity (session factory) and
    console_auth (the unsigned Cognito client) may construct boto3 objects."""
    offenders = {}
    for name, tree in _app_sources():
        if name in ("console_identity.py", "console_auth.py"):
            continue
        aliases = _boto3_aliases(tree)
        hits = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "boto3":
                hits.extend(a.name for a in node.names if a.name in ("Session", "client", "resource"))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("Session", "client", "resource") \
                    and isinstance(node.func.value, ast.Name) and node.func.value.id in aliases | {"boto3"}:
                hits.append(ast.unparse(node))
        if hits:
            offenders[name] = hits
    assert offenders == {}


def test_transitional_ambient_session_is_gone():
    for name, tree in _app_sources():
        names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert "_transitional_ambient_session" not in names, name
        assert "_transitional_local_principal" not in names, name
    with open(DASHBOARD_PATH, encoding="utf-8") as f:
        assert "TRANSITIONAL(C6)" not in f.read()


# ─── _breaker_error_text ─────────────────────────────────────────────────────

@pytest.fixture
def dashboard_module(monkeypatch):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_dashboard_login_hardening as harness
    module, _, _ = harness.TestModuleLevelThrottleBehavior()._fresh_dashboard_module(monkeypatch)
    return module


def test_breaker_error_text_never_renders_lambda_error_or_message(dashboard_module):
    text = dashboard_module._breaker_error_text(
        "Manual circuit breaker", {"error": {"errorMessage": "arn:aws:iam::123456789012:role/secret-role"}})
    assert "123456789012" not in text and "secret-role" not in text
    rejected = dashboard_module._breaker_error_text("Release approval", {
        "status": "REJECTED", "http_status": 403, "code": "SECOND_APPROVER_REQUIRED",
        "message": "caller arn:aws:sts::123456789012:assumed-role/secret-role/x"})
    assert "A different approver must approve this release" in rejected and "403" in rejected
    assert "123456789012" not in rejected
    unknown = dashboard_module._breaker_error_text("x", {"status": "REJECTED", "http_status": 403,
                                                         "message": LEAKY})
    assert "Not authorized for this action" in unknown and "secret-role" not in unknown


# ─── AppTest rendering ───────────────────────────────────────────────────────

ACTIVE = {"status": "ACTIVE", "message": "Circuit breaker not engaged"}
OK_ALARMS = {k: {"state": "OK", "reason": "", "updated": ""} for k in ("challenger", "guardrail", "volume")}


class _AgentCoreError(Exception):
    def __init__(self, status):
        message = (f"Received error ({status}) from runtime. secret-role executor-audit "
                   "123456789012 us-east-1")
        super().__init__(message)
        self.response = {"Error": {"Code": "RuntimeClientError", "Message": message}}


@pytest.fixture
def console(monkeypatch, tmp_path):
    """Signed-in local console principal, MODE=live, fake governance
    sessions; ambient boto3 forbidden."""
    import boto3
    import app.invoke_live as invoke_live
    from app import console_auth, console_identity
    from app.console_identity import Principal

    monkeypatch.setenv("MODE", "live")
    monkeypatch.setenv("CONSOLE_AUTH_MODE", "local")
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("DEMO_PACING_SECONDS_SCALE", "0")
    monkeypatch.setattr(console_auth, "_server_address", lambda: "127.0.0.1")

    def refuse(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, refuse)

    sessions = {p: MagicMock(name=f"{p}-session") for p in ("operator", "approver", "auditor")}
    monkeypatch.setattr(console_identity, "governance_session", lambda p, purpose: sessions[purpose])
    principal = Principal(principal_id="local:alice", display_name="Alice", auth_mode="local",
                          roles=frozenset({"approver", "auditor"}),
                          authenticated_at="2026-01-01T00:00:00+00:00",
                          aws_principal_arn="arn:aws:sts::123456789012:assumed-role/fsi-console-operator/alice")

    def page(name):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(DASHBOARD_PATH, default_timeout=60)
        at.session_state["principal"] = principal
        at.run()
        at.sidebar.radio[0].set_value(name).run()
        assert not at.exception, at.exception
        return at
    return {"page": page, "sessions": sessions, "invoke_live": invoke_live}


def _click(at, label):
    [b for b in at.button if b.label == label][0].click().run()
    assert not at.exception, at.exception
    return at


def _all_text(at) -> str:
    parts = []
    for kind in ("error", "warning", "info", "success", "markdown", "caption", "text", "code", "json",
                 "exception", "subheader", "title"):
        for element in getattr(at, kind):
            parts.append(str(getattr(element, "value", "")))
    for element in at.status if hasattr(at, "status") else []:
        parts.append(str(getattr(element, "label", "")))
    return "\n".join(parts)


def _assert_safe(text):
    # The incomplete-evidence banner names tables with fixed
    # strings; those are not exception text.
    for table in ("detection-results", "compliance-decisions", "executor-audit", "governance-audit"):
        for suffix in (": read failed", ": partial read"):
            text = text.replace(table + suffix, "")
    # The static Data Separation table names the tables as code cells.
    text = text.replace("| `executor-audit` |", "")
    for needle in FORBIDDEN:
        assert needle not in text, needle
    assert "ref " in text


def test_audit_page_query_access_denied_renders_reference_only(console, caplog):
    table = MagicMock()
    table.query.side_effect = _client_error("AccessDeniedException")
    table.scan.side_effect = AssertionError("scan")
    console["sessions"]["auditor"].resource.return_value.Table.return_value = table
    at = _click(console["page"]("2.1 Decision Explainability — Audit Trail"), "Load Live Audit Records")
    _assert_safe(_all_text(at))
    assert any("Audit read failed" in r.getMessage() and r.exc_info for r in caplog.records)


def test_manual_trip_client_error_renders_reference_only(console, monkeypatch):
    def boom(**kwargs):
        raise _client_error("AccessDeniedException", op="Invoke")
    monkeypatch.setattr(console["invoke_live"], "run_circuit_breaker_live", boom)
    monkeypatch.setattr(console["invoke_live"], "get_circuit_breaker_status_live", lambda **k: ACTIVE)
    monkeypatch.setattr(console["invoke_live"], "get_agent_role_hold_state_live", lambda **k: {})
    monkeypatch.setattr(console["invoke_live"], "get_cloudwatch_alarm_states_live", lambda **k: OK_ALARMS)
    at = _click(console["page"]("4.1 Drift Control — Circuit Breaker"), "Manual Circuit Breaker")
    _assert_safe(_all_text(at))


def test_breach_publish_client_error_renders_reference_only(console, monkeypatch):
    monkeypatch.setenv("CONSOLE_ALLOW_DRIFT_INJECTION", "true")
    il = console["invoke_live"]

    def boom(*a, **k):
        raise _client_error("AccessDeniedException", op="PutMetricData")
    monkeypatch.setattr(il, "publish_breach_metric_live", boom)
    monkeypatch.setattr(il, "get_circuit_breaker_status_live", lambda **k: ACTIVE)
    monkeypatch.setattr(il, "get_agent_role_hold_state_live", lambda **k: {})
    monkeypatch.setattr(il, "get_cloudwatch_alarm_states_live", lambda **k: OK_ALARMS)
    at = _click(console["page"]("4.1 Drift Control — Circuit Breaker"),
                "Volume Spike Breach\n(4x detection volume)")
    _assert_safe(_all_text(at))


def test_registry_load_error_renders_reference_only(console, monkeypatch):
    import importlib
    import model_assurance
    monkeypatch.setattr(importlib, "reload", lambda module: module)  # keep the patched loader

    def boom(*a, **k):
        raise ValueError("/Users/secret/path")
    monkeypatch.setattr(model_assurance, "load_registry", boom)
    at = console["page"]("5.2 Deployment Control — Model Assurance")
    _assert_safe(_all_text(at))
    assert "Approved-models registry failed to load" in _all_text(at)


@pytest.mark.parametrize("status,expected", [
    (409, "This detection was already decided or isn't recorded"),
    (413, "Request too large"),
    (503, "Temporarily unavailable"),
])
def test_compliance_non_2xx_renders_mapped_status_message(console, monkeypatch, status, expected):
    import json as _json
    il = console["invoke_live"]
    with open(os.path.join(PROJECT_ROOT, "cached_output", "detection_result.json"), encoding="utf-8") as f:
        detection = _json.load(f)
    monkeypatch.setattr(il, "run_detection_live", lambda *a, **k: detection)
    monkeypatch.setattr(il, "_get_runtime_arn", lambda name, **k: "arn:aws:bedrock-agentcore:fake")
    agentcore = MagicMock()
    agentcore.exceptions.RuntimeClientError = _AgentCoreError
    agentcore.invoke_agent_runtime.side_effect = lambda **k: (_ for _ in ()).throw(_AgentCoreError(status))
    console["sessions"]["operator"].client.side_effect = lambda service, **k: agentcore
    at = _click(console["page"]("Run Pipeline (Happy Path)"), "Run Full Pipeline")
    text = _all_text(at)
    assert f"{expected} (ref " in text
    for needle in FORBIDDEN:
        assert needle not in text
    assert "Received error" not in text


def test_unpinned_runtimes_fail_closed_with_the_safe_message(console):
    """No pinned runtime ARNs: the run is refused with a reference, nothing
    is invoked and no runtime is looked up by name."""
    class ParameterNotFound(Exception):
        response = {"Error": {"Code": "ParameterNotFound", "Message": "/fsi/governance/x 123456789012"}}
    sts, ssm, data, control = MagicMock(), MagicMock(), MagicMock(), MagicMock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    ssm.get_parameter.side_effect = ParameterNotFound()
    clients = {"sts": sts, "ssm": ssm, "bedrock-agentcore": data, "bedrock-agentcore-control": control}
    console["sessions"]["operator"].client.side_effect = lambda service, **k: clients.get(service, MagicMock())
    at = _click(console["page"]("Run Pipeline (Happy Path)"), "Run Full Pipeline")
    text = _all_text(at)
    assert "(ref " in text
    for needle in FORBIDDEN:
        assert needle not in text
    data.invoke_agent_runtime.assert_not_called()
    control.list_agent_runtimes.assert_not_called()


# ─── 3.1 Champion/Challenger, MODE=live: fresh detection first ───────────────
# The compliance runtime assesses only RECORDED detections and decides each
# once (409 otherwise). The live page used to submit a hand-built
# "challenger-scenario" detection that was never recorded.

CHALLENGER_PAGE = "3.1 Deliberative Challenge — Champion/Challenger"
RUN_CHALLENGER = "Run Challenger Analysis"


def _cached(name):
    import json as _json
    with open(os.path.join(PROJECT_ROOT, "cached_output", name), encoding="utf-8") as f:
        return _json.load(f)


@pytest.fixture
def challenger_live(console, monkeypatch):
    """Fake detection runtime (a NEW uuid4 detection_id per call) and fake
    compliance runtime (echoes the detection_id it was given)."""
    import uuid as _uuid
    il = console["invoke_live"]
    calls = {"detection": [], "compliance": []}

    def detect(mode="cpu", request_ref=None, *, session):
        calls["detection"].append({"request_ref": request_ref, "session": session})
        return dict(_cached("detection_result.json"), detection_id=str(_uuid.uuid4()))

    def comply(detection_output, *, session, request_ref=None):
        calls["compliance"].append({"detection_output": detection_output, "session": session,
                                    "request_ref": request_ref})
        return dict(_cached("compliance_result.json"), detection_id=detection_output["detection_id"],
                    dispatch_token="secret-dispatch-token")

    monkeypatch.setattr(il, "run_detection_live", detect)
    monkeypatch.setattr(il, "run_compliance_live", comply)
    monkeypatch.setattr(il, "get_circuit_breaker_status_live", lambda **k: ACTIVE)
    return calls


def test_live_challenger_runs_fresh_detection_then_compliance_on_its_id(console, challenger_live):
    at = _click(console["page"](CHALLENGER_PAGE), RUN_CHALLENGER)
    [det], [comp] = challenger_live["detection"], challenger_live["compliance"]
    operator = console["sessions"]["operator"]
    assert det["session"] is operator and comp["session"] is operator
    assert det["request_ref"] == comp["request_ref"] is not None
    assert comp["detection_output"]["detection_id"] != "challenger-scenario"
    assert "Champion vs Challenger Results" in [s.value for s in at.subheader]
    stored = at.session_state["challenger_compliance"]
    assert "dispatch_token" not in stored
    assert stored["detection_id"] == comp["detection_output"]["detection_id"]


def test_live_challenger_never_resubmits_a_decided_detection(console, challenger_live):
    at = console["page"](CHALLENGER_PAGE)
    at = _click(at, RUN_CHALLENGER)
    at = _click(at, RUN_CHALLENGER)
    ids = [c["detection_output"]["detection_id"] for c in challenger_live["compliance"]]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert len(challenger_live["detection"]) == 2


def test_live_challenger_compliance_409_renders_safe_message(console, challenger_live, monkeypatch):
    def refuse(detection_output, *, session, request_ref=None):
        raise _AgentCoreError(409)
    monkeypatch.setattr(console["invoke_live"], "run_compliance_live", refuse)
    at = _click(console["page"](CHALLENGER_PAGE), RUN_CHALLENGER)
    text = _all_text(at)
    assert "No clusters assessed: This detection was already decided or isn't recorded (ref " in text
    for needle in FORBIDDEN:
        assert needle not in text
    assert "Received error" not in text


def test_live_challenger_detection_failure_skips_compliance(console, challenger_live, monkeypatch):
    def boom(mode="cpu", request_ref=None, *, session):
        raise _AgentCoreError(503)
    monkeypatch.setattr(console["invoke_live"], "run_detection_live", boom)
    at = _click(console["page"](CHALLENGER_PAGE), RUN_CHALLENGER)
    text = _all_text(at)
    assert "No clusters assessed: Temporarily unavailable (ref " in text
    assert challenger_live["compliance"] == []
    for needle in FORBIDDEN:
        assert needle not in text


def test_live_challenger_detection_error_body_renders_fixed_text(console, challenger_live, monkeypatch):
    monkeypatch.setattr(console["invoke_live"], "run_detection_live",
                        lambda mode="cpu", request_ref=None, *, session: {"error": LEAKY})
    at = _click(console["page"](CHALLENGER_PAGE), RUN_CHALLENGER)
    text = _all_text(at)
    assert "Detection failed; no detection was recorded for this run" in text
    assert challenger_live["compliance"] == []
    for needle in FORBIDDEN:
        assert needle not in text


def test_live_challenger_refused_while_hold_is_engaged(console, challenger_live):
    at = console["page"](CHALLENGER_PAGE)
    at.session_state["ks_engaged"] = True
    at = _click(at, RUN_CHALLENGER)
    assert any("governance hold" in e.value for e in at.error)
    assert challenger_live["detection"] == [] and challenger_live["compliance"] == []
