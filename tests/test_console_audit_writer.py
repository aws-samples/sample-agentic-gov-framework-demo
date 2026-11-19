"""
Strict hosted purpose-to-role mapping: in alb-cognito mode an auditor-only principal never gets the
operator-hosted role. Its operator-audit records (AUDIT_READ, SIGN_IN, ...)
go through the PutItem-only audit_writer role, still carrying the
STS-verified actor_aws_arn; with no audit_writer mapping they are refused
(fail closed), never written through the operator role. Mocked STS/DynamoDB.
"""
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import console_auth, console_identity  # noqa: E402
from app.console_identity import ConsoleAuthzError, NoAwsAuthorityError, Principal  # noqa: E402
from _cdk_synth import DEFAULT_CONTEXT, FULL_CONTEXT, role_actions, role_props, role_statements, synth  # noqa: E402

SUB = "0f1e2d3c-aaaa-bbbb-cccc-123456789abc"
ACCT = "123456789012"
OPERATOR_HOSTED = f"arn:aws:iam::{ACCT}:role/fsi-console/fsi-console-operator-hosted"
AUDIT_WRITER = f"arn:aws:iam::{ACCT}:role/fsi-console/fsi-console-audit-writer-hosted"
READER = f"arn:aws:iam::{ACCT}:role/fsi-compliance-reader"
ROLE_NAMES = {OPERATOR_HOSTED: "fsi-console-operator-hosted", AUDIT_WRITER: "fsi-console-audit-writer-hosted",
              READER: "fsi-compliance-reader"}


def _hosted(roles):
    return Principal(principal_id=f"cognito:{SUB}", display_name="Ada", auth_mode="alb-cognito",
                     roles=frozenset(roles), authenticated_at="2026-01-01T00:00:00+00:00")


class RoleSession:
    """A boto3.Session for one assumed role: STS identity + recorded PutItems."""

    def __init__(self, role_arn, fail_identity=False):
        self.role_arn = role_arn
        self.puts = []
        self.sts = MagicMock()
        if fail_identity:
            self.sts.get_caller_identity.side_effect = RuntimeError("sts down")
        else:
            self.sts.get_caller_identity.return_value = {
                "Arn": f"arn:aws:sts::{ACCT}:assumed-role/{ROLE_NAMES[role_arn]}/cognito-{SUB}"}
        table = MagicMock()
        table.put_item.side_effect = lambda Item, **k: self.puts.append(Item)
        self.dynamodb = MagicMock()
        self.dynamodb.Table.return_value = table

    def client(self, service, **kwargs):
        assert service == "sts"
        return self.sts

    def resource(self, service, **kwargs):
        assert service == "dynamodb"
        return self.dynamodb


@pytest.fixture
def hosted(monkeypatch):
    state = {}
    monkeypatch.setattr(console_identity, "_state", lambda: state)
    monkeypatch.setattr(console_identity, "_ASSUMED_CACHE", {})
    console_auth._reset_role_arns_for_tests()
    monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps(
        {"operator": OPERATOR_HOSTED, "auditor": READER, "audit_writer": AUDIT_WRITER}))
    host_sts = MagicMock()
    assumed = []
    sessions = {}
    fail_identity = set()

    def assume_role(**kwargs):
        assumed.append(kwargs["RoleArn"])
        return {"Credentials": {"AccessKeyId": kwargs["RoleArn"], "SecretAccessKey": "s", "SessionToken": "t"}}
    host_sts.assume_role.side_effect = assume_role

    def fake_session(**kw):
        if not kw:
            host = MagicMock()
            host.client.return_value = host_sts
            return host
        arn = kw["aws_access_key_id"]
        sessions[arn] = RoleSession(arn, fail_identity=arn in fail_identity)
        return sessions[arn]
    monkeypatch.setattr(console_identity, "_boto3_session", fake_session)
    yield {"state": state, "assumed": assumed, "sessions": sessions, "fail_identity": fail_identity}
    console_auth._reset_role_arns_for_tests()


def test_auditor_only_principal_never_gets_the_operator_role(hosted):
    p = _hosted({"auditor"})
    with pytest.raises(ConsoleAuthzError):
        console_identity.governance_session(p, "operator")
    assert hosted["assumed"] == []
    console_identity.governance_session(p, "audit_writer")
    assert hosted["assumed"] == [AUDIT_WRITER]


def test_operator_and_approver_use_the_operator_role(hosted):
    for roles in ({"operator"}, {"approver"}):
        p = _hosted(roles)
        assert console_identity.audit_purpose_for(p) == "operator"
    assert console_identity.audit_purpose_for(_hosted({"auditor"})) == "audit_writer"
    console_identity.governance_session(_hosted({"operator"}), "operator")
    assert hosted["assumed"] == [OPERATOR_HOSTED]


def test_audit_writer_purpose_records_the_session_arn(hosted):
    p = _hosted({"auditor"})
    hosted["state"]["principal"] = p
    console_identity.governance_session(p, "audit_writer")
    assert hosted["state"]["principal"].aws_principal_arn.endswith(
        f"assumed-role/fsi-console-audit-writer-hosted/cognito-{SUB}")


def test_role_arn_parsing():
    parsed = console_auth.parse_console_role_arns(json.dumps(
        {"operator": OPERATOR_HOSTED, "audit_writer": AUDIT_WRITER, "approver": OPERATOR_HOSTED}))
    assert parsed == {"operator": OPERATOR_HOSTED, "audit_writer": AUDIT_WRITER}


def test_unknown_purpose_still_refused(hosted):
    with pytest.raises(ValueError):
        console_identity.governance_session(_hosted({"auditor"}), "admin")


# ─── Dashboard: AUDIT_READ through the audit-writer session ─────────────────

@pytest.fixture
def dashboard(monkeypatch, hosted):
    import test_dashboard_login_hardening as harness
    module, _fake_st, fake_state = harness.TestModuleLevelThrottleBehavior()._fresh_dashboard_module(monkeypatch)
    monkeypatch.setattr(module, "MODE", "live")
    monkeypatch.setenv("MODE", "live")
    # console_identity's session state seam is the dict the fixture installed.
    return module, hosted["state"]


def test_hosted_auditor_audit_read_writes_through_the_audit_writer(dashboard, hosted):
    dash, state = dashboard
    state["principal"] = _hosted({"auditor"})
    action = dash.begin_action("AUDIT_READ", None, "auditor")
    assert hosted["assumed"] == [READER, AUDIT_WRITER] and OPERATOR_HOSTED not in hosted["assumed"]
    writer = hosted["sessions"][AUDIT_WRITER]
    assert action.audit_session is writer
    (item,) = writer.puts
    assert item["action"] == "AUDIT_READ" and item["phase"] == "REQUESTED"
    assert item["actor_aws_arn"].endswith(f"assumed-role/fsi-console-audit-writer-hosted/cognito-{SUB}")
    assert hosted["sessions"][READER].puts == []


def test_hosted_auditor_audit_read_refused_without_a_verified_arn(dashboard, hosted):
    dash, state = dashboard
    hosted["fail_identity"].add(AUDIT_WRITER)
    state["principal"] = _hosted({"auditor"})
    with pytest.raises(dash.ActionRefused) as info:
        dash.begin_action("AUDIT_READ", None, "auditor")
    assert info.value.message == console_identity.NO_AUTHORITY_MESSAGE
    assert hosted["sessions"][AUDIT_WRITER].puts == []


def test_hosted_auditor_without_audit_writer_mapping_is_refused(dashboard, hosted, monkeypatch):
    dash, state = dashboard
    console_auth._reset_role_arns_for_tests()
    monkeypatch.setenv("CONSOLE_ROLE_ARNS", json.dumps({"operator": OPERATOR_HOSTED, "auditor": READER}))
    state["principal"] = _hosted({"auditor"})
    with pytest.raises(dash.ActionRefused) as info:
        dash.begin_action("AUDIT_READ", None, "auditor")
    assert info.value.message == console_identity.NO_AUTHORITY_MESSAGE
    assert OPERATOR_HOSTED not in hosted["assumed"]
    assert all(not s.puts for s in hosted["sessions"].values())


def test_hosted_sign_in_event_uses_the_audit_writer(hosted, monkeypatch, tmp_path):
    monkeypatch.setenv("MODE", "live")
    monkeypatch.setenv("LOCAL_OUTPUT_DIR", str(tmp_path))
    p = _hosted({"auditor"})
    hosted["state"]["principal"] = p
    console_auth.record_session_event(p, "SIGN_IN")
    assert hosted["assumed"] == [AUDIT_WRITER]
    (item,) = hosted["sessions"][AUDIT_WRITER].puts
    assert item["action"] == "SIGN_IN"


def test_local_auditor_with_operator_profile_records_audit_read(monkeypatch, tmp_path):
    """Local mode is unchanged: the audit writer is the person's own
    operator profile, with no console-role check."""
    import test_dashboard_login_hardening as harness
    dash, _fake_st, _ = harness.TestModuleLevelThrottleBehavior()._fresh_dashboard_module(monkeypatch)
    state = {}
    monkeypatch.setattr(console_identity, "_state", lambda: state)
    monkeypatch.setattr(dash, "MODE", "live")
    monkeypatch.setenv("MODE", "live")
    monkeypatch.setattr(console_identity, "check_profile", lambda *a, **k: None)
    sessions = {}

    def fake_session(**kw):
        role = {"op-profile": OPERATOR_HOSTED, "audit-profile": READER}[kw["profile_name"]]
        sessions[kw["profile_name"]] = RoleSession(role)
        return sessions[kw["profile_name"]]
    monkeypatch.setattr(console_identity, "_boto3_session", fake_session)
    state["principal"] = Principal(
        principal_id="local:alice", display_name="Alice", auth_mode="local", roles=frozenset({"auditor"}),
        authenticated_at="2026-01-01T00:00:00+00:00",
        aws_profiles={"operator": "op-profile", "auditor": "audit-profile"})
    action = dash.begin_action("AUDIT_READ", None, "auditor")
    assert action.audit_session is sessions["op-profile"]
    (item,) = sessions["op-profile"].puts
    assert item["action"] == "AUDIT_READ" and item["actor_aws_arn"]


# ─── CDK ─────────────────────────────────────────────────────────────────────

def test_audit_writer_role_only_with_host_context():
    default = synth(DEFAULT_CONTEXT)["agents"]
    names = {r["Properties"].get("RoleName") for r in default["Resources"].values()
             if r["Type"] == "AWS::IAM::Role"}
    assert "fsi-console-audit-writer-hosted" not in names
    t = synth(FULL_CONTEXT)["agents"]
    assert role_actions(t, "fsi-console-audit-writer-hosted") == {"dynamodb:PutItem"}
    (stmt,) = role_statements(t, "fsi-console-audit-writer-hosted")
    assert "OperatorAudit" in json.dumps(stmt["Resource"]) and "/index" not in json.dumps(stmt["Resource"])
    props = role_props(t, "fsi-console-audit-writer-hosted")
    assert props["Path"] == "/fsi-console/" and props["MaxSessionDuration"] == 3600
    assert props["AssumeRolePolicyDocument"] == role_props(t, "fsi-console-operator-hosted")[
        "AssumeRolePolicyDocument"]
