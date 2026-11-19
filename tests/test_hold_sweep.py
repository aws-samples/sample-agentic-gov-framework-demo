"""
Reconciling governance-hold sweep: while the hold
is active, re-attach governance-hold-deny-all to any agent role missing it.
Idempotent, audited (GOVERNANCE_HOLD_RECONCILED), scheduled and run after
each trip. It never detaches (code, plus no IAM grant). Mocked AWS only.
"""
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _breaker_fixtures import DENY_ARN, FakeBreakerAws, cb, client_error  # noqa: E402
from _cdk_synth import DEFAULT_CONTEXT, FULL_CONTEXT, as_list, logical_id, render, resources, role_actions, \
    role_props, statements_with_action, synth, notifies_on_call_only  # noqa: E402

hold_sweep = cb.hold_sweep
ROLES = list(cb.AGENT_ROLES)


def _now():
    return datetime.now(timezone.utc)


class StrictIam:
    """The fake IAM plus a detach that fails the test if ever called."""

    def __init__(self, aws):
        self._iam = aws.iam

    def __getattr__(self, name):
        if name == "detach_role_policy":
            raise AssertionError("the sweep must never detach")
        return getattr(self._iam, name)


@pytest.fixture
def aws(monkeypatch):
    aws = FakeBreakerAws().install(monkeypatch, entry="sweep")
    aws.iam.detach_role_policy = MagicMock(side_effect=AssertionError("the sweep must never detach"))
    return aws


def _event(aws, event_type, ago, event_id=None, timestamp=None):
    event_id = event_id or f"{event_type.lower()}-{ago}"
    aws.gov.items[event_id] = {"event_id": event_id, "event_type": event_type,
                               "timestamp": timestamp or (_now() - ago).isoformat()}
    return event_id


def _sweep(aws, **kwargs):
    """The sweep as the handler wires it (state item read consistently). These
    tests write no state item, so they cover the pre-upgrade index fallback;
    the state-item cases are in tests/test_governance_state.py."""
    metrics = []
    result = hold_sweep.reconcile_hold(
        StrictIam(aws), aws.gov, roles=ROLES, deny_policy_arn=DENY_ARN, trigger="schedule",
        emit_metric=lambda name, value: metrics.append((name, value)),
        read_state=lambda: cb.governance_state.read(aws.state), **kwargs)
    return result, metrics


def _attaches(aws):
    return [e[1] for e in aws.log if e[0] == "attach"]


def test_reattaches_the_one_missing_role_and_audits(aws):
    hold = _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.iam.held.update(ROLES[:2])
    result, metrics = _sweep(aws)
    assert result["status"] == "RECONCILED" and result["roles_reattached"] == [ROLES[2]]
    assert _attaches(aws) == [ROLES[2]]
    (record,) = aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["event_id"].startswith("reconcile#") and record["hold_event_id"] == hold
    assert record["roles_reattached"] == [ROLES[2]] and record["roles_already_held"] == ROLES[:2]
    assert record["roles_confirmed_after"] == ROLES and record["trigger"] == "schedule"
    assert record["attach_failures"] == {}
    assert metrics == [("HoldReconciled", 1)]
    aws.iam.detach_role_policy.assert_not_called()


def test_all_held_is_idempotent(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.iam.held.update(ROLES)
    result, metrics = _sweep(aws)
    assert result["status"] == "HOLD_CONFIRMED"
    assert _attaches(aws) == [] and aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED") == [] and metrics == []


def test_release_newer_than_hold_is_no_hold(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    _event(aws, "GOVERNANCE_HOLD_RELEASED", timedelta(minutes=5))
    result, _ = _sweep(aws)
    assert result == {"status": "NO_HOLD"}
    assert _attaches(aws) == [] and not [e for e in aws.log if e[0] == "put"]


def test_break_glass_release_counts_as_release(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10), timestamp="2026-01-01T10:00:00+00:00")
    _event(aws, "BREAK_GLASS_RELEASE_STARTED", timedelta(minutes=5), timestamp="2026-01-01T10:05:00.5Z")
    assert _sweep(aws)[0] == {"status": "NO_HOLD"}


def test_timestamps_with_and_without_microseconds_compare_correctly(aws):
    # Lexically "...10:00:00+00:00" > "...10:00:00.500000+00:00", but the
    # release (with microseconds) is half a second later.
    _event(aws, "GOVERNANCE_HOLD", timedelta(), timestamp="2026-01-01T10:00:00+00:00")
    _event(aws, "GOVERNANCE_HOLD_RELEASED", timedelta(), timestamp="2026-01-01T10:00:00.500000+00:00")
    assert _sweep(aws)[0] == {"status": "NO_HOLD"}


def test_unparseable_timestamp_counts_as_oldest(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    _event(aws, "GOVERNANCE_HOLD_RELEASED", timedelta(), timestamp="not-a-time")
    result, _ = _sweep(aws)
    assert result["status"] == "RECONCILED"


def test_intent_alone_is_an_active_hold(aws):
    _event(aws, "GOVERNANCE_HOLD_INTENT", timedelta(minutes=10), event_id="intent-x")
    result, _ = _sweep(aws)
    assert result["status"] == "RECONCILED" and sorted(_attaches(aws)) == sorted(ROLES)


def test_release_racing_the_sweep_prevents_the_attach(aws, monkeypatch):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    real = hold_sweep.hold_active
    calls = []

    def racing(table, now=None):
        calls.append(1)
        state = real(table, now)
        if len(calls) == 2:
            return state._replace(active=False)
        return state
    monkeypatch.setattr(hold_sweep, "hold_active", racing)
    result, _ = _sweep(aws)
    assert result == {"status": "NO_HOLD", "raced_release": True} and _attaches(aws) == []


def test_fresh_hold_is_left_to_the_trip(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(seconds=30))
    assert _sweep(aws)[0] == {"status": "HOLD_TOO_RECENT"} and _attaches(aws) == []


def test_audit_write_failure_raises_after_the_attach(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.gov.put_error["GOVERNANCE_HOLD_RECONCILED"] = client_error("InternalServerError", "PutItem")
    with pytest.raises(hold_sweep.HoldReconcileAuditError):
        _sweep(aws)
    assert sorted(_attaches(aws)) == sorted(ROLES)  # containment first


def test_query_error_no_attach_and_alerts(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.gov.query_error = client_error("ThrottlingException", "Query")
    result, metrics = _sweep(aws)
    assert result == {"status": "ERROR"} and metrics == [("HoldSweepFailed", 1)] and _attaches(aws) == []


def test_attach_failure_is_recorded_per_role(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.iam.held.update(ROLES[:2])
    aws.iam.attach_error[ROLES[2]] = client_error("AccessDenied", "AttachRolePolicy")
    result, metrics = _sweep(aws)
    assert result["roles_reattached"] == [] and result["attach_failures"][ROLES[2]]["error_class"] == "AccessDenied"
    (record,) = aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["roles_confirmed_after"] == ROLES[:2]
    assert metrics == [("HoldReconciled", 0)]


def test_list_error_counts_the_role_as_missing(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.iam.held.update(ROLES)
    aws.iam.list_error[ROLES[0]] = client_error("Throttling", "ListAttachedRolePolicies")
    result, _ = _sweep(aws)
    assert result["status"] == "RECONCILED" and _attaches(aws) == [ROLES[0]]


def test_module_never_references_detach():
    with open(hold_sweep.__file__, encoding="utf-8") as f:
        source = f.read()
    assert "detach_role_policy" not in source and "DetachRolePolicy" not in source.replace(
        "no iam:DetachRolePolicy", "")
    import re
    assert not re.search(r"^\s*(import handler|from handler import)", source, flags=re.M)  # no back-import


# ─── Entry wiring ────────────────────────────────────────────────────────────

def test_sweep_entry_runs_reconcile(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    result = cb.handler({"action": "reconcile_hold"})
    assert result["status"] == "RECONCILED" and sorted(_attaches(aws)) == sorted(ROLES)
    (record,) = aws.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["trigger"] == "schedule"
    assert ("metric", "FSI/GovernanceIntegrity", "HoldReconciled") in aws.log


@pytest.mark.parametrize("hold", [True, False], ids=["hold", "no-hold"])
def test_completed_sweep_emits_the_liveness_heartbeat(aws, hold):
    if hold:
        _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    result = cb.handler({"action": "reconcile_hold"})
    assert result["status"] in ("RECONCILED", "NO_HOLD")
    assert ("metric", "FSI/GovernanceIntegrity", "HoldSweepHeartbeat") in aws.log


def test_errored_sweep_emits_no_heartbeat(aws, monkeypatch):
    monkeypatch.setattr(cb.hold_sweep, "reconcile_hold", lambda *a, **k: {"status": "ERROR"})
    assert cb.handler({"action": "reconcile_hold"}) == {"status": "ERROR"}
    assert ("metric", "FSI/GovernanceIntegrity", "HoldSweepHeartbeat") not in aws.log


def test_sweep_entry_maps_audit_failure_to_governance_audit_error(aws):
    _event(aws, "GOVERNANCE_HOLD", timedelta(minutes=10))
    aws.gov.put_error["GOVERNANCE_HOLD_RECONCILED"] = client_error("InternalServerError", "PutItem")
    with pytest.raises(cb.GovernanceAuditWriteError):
        cb.handler({"action": "reconcile_hold"})


@pytest.mark.parametrize("event", [
    {"action": "invoke"}, {"action": "auto_trip"}, {"action": "status"}, {"action": "check"},
    {"action": "recheck_alarms"}, {"action": "approve_release"}, {},
    {"source": "aws.cloudwatch", "alarmArn": "x", "alarmData": {}},
    {"action": "reconcile_hold", "mode": "local", "source": "aws.cloudwatch"},
])
def test_sweep_entry_refuses_everything_else(aws, event):
    result = cb.handler(dict(event))
    assert result["http_status"] == 403 and result["message"] == cb.WRONG_ENTRY_MESSAGE
    assert aws.log == []


@pytest.mark.parametrize("entry", ["automated", "human", None])
def test_reconcile_refused_on_the_other_entries(monkeypatch, entry):
    aws = FakeBreakerAws().install(monkeypatch, entry=entry)
    result = cb.handler({"action": "reconcile_hold"})
    assert result["http_status"] == 403 and aws.log == []


def test_local_mode_reconcile_is_no_hold(monkeypatch):
    monkeypatch.setenv("BREAKER_ENTRY", "sweep")
    monkeypatch.setattr(cb.boto3, "client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("aws")))
    assert cb.handler({"action": "reconcile_hold", "mode": "local"}) == {"status": "NO_HOLD"}


# ─── Post-trip reconcile (pinned order) ──────────────────────────────────────

@pytest.fixture
def automated(monkeypatch):
    monkeypatch.setattr(cb, "TRUSTED_AUTOMATED_TRIP_PRINCIPAL_ARNS",
                        ["arn:aws:iam::123456789012:role/executor-agent-role"])
    return FakeBreakerAws().install(monkeypatch, entry="automated")


def _trip():
    return cb.handler({"action": "auto_trip", "trip_source": "EXECUTOR_CONTAINMENT"})


def test_post_trip_reconcile_reattaches_before_the_hold_record(automated):
    automated.iam.attach_error[ROLES[1]] = client_error("Throttling", "AttachRolePolicy")
    result = _trip()
    assert result["status"] == "GOVERNANCE_HOLD" and sorted(result["roles_revoked"]) == sorted(ROLES)
    (hold,) = automated.gov.by_type("GOVERNANCE_HOLD")
    assert hold["reconciled_roles"] == [ROLES[1]] and sorted(hold["roles_revoked"]) == sorted(ROLES)
    (record,) = automated.gov.by_type("GOVERNANCE_HOLD_RECONCILED")
    assert record["trigger"] == "post_trip" and record["hold_event_id"] == hold["event_id"]
    attaches = [i for i, e in enumerate(automated.log) if e == ("attach", ROLES[1])]
    hold_put = automated.log.index(("put", "GOVERNANCE_HOLD", hold["event_id"]))
    assert len(attaches) == 2 and attaches[-1] < hold_put


def test_post_trip_reconcile_happens_even_when_the_hold_write_fails(automated):
    automated.iam.attach_error[ROLES[1]] = client_error("Throttling", "AttachRolePolicy")
    automated.gov.put_error["GOVERNANCE_HOLD"] = client_error("InternalServerError", "PutItem")
    with pytest.raises(cb.GovernanceAuditWriteError):
        _trip()
    assert [e for e in automated.log if e == ("attach", ROLES[1])] == [("attach", ROLES[1])] * 2
    assert ROLES[1] in automated.iam.held


def test_post_trip_reconcile_not_run_when_all_confirmed(automated):
    _trip()
    assert automated.gov.by_type("GOVERNANCE_HOLD_RECONCILED") == []
    (hold,) = automated.gov.by_type("GOVERNANCE_HOLD")
    assert "reconciled_roles" not in hold


def test_post_trip_reconcile_failure_still_raises_enforcement_error(automated):
    automated.iam.attach_error[ROLES[1]] = client_error("AccessDenied", "AttachRolePolicy")
    automated.gov.put_error["GOVERNANCE_HOLD_RECONCILED"] = client_error("InternalServerError", "PutItem")

    original = automated.iam.attach_role_policy

    def always_fail(RoleName, PolicyArn):
        if RoleName == ROLES[1]:
            automated.log.append(("attach", RoleName))
            raise client_error("AccessDenied", "AttachRolePolicy")
        return original(RoleName=RoleName, PolicyArn=PolicyArn)
    automated.iam.attach_role_policy = always_fail
    with pytest.raises(cb.GovernanceHoldEnforcementError) as info:
        _trip()
    assert info.value.unconfirmed_roles == [ROLES[1]]
    (hold,) = automated.gov.by_type("GOVERNANCE_HOLD")
    assert ROLES[1] not in hold["roles_revoked"]


# ─── CDK ─────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def agents():
    return synth(DEFAULT_CONTEXT)["agents"]


def test_sweep_role_is_attach_only(agents):
    actions = role_actions(agents, "governance-hold-sweep-role")
    assert actions == {"iam:AttachRolePolicy", "iam:ListAttachedRolePolicies", "dynamodb:Query",
                       "dynamodb:PutItem", "dynamodb:GetItem", "cloudwatch:PutMetricData",
                       "sqs:SendMessage", "logs:CreateLogStream", "logs:PutLogEvents"}
    assert not role_props(agents, "governance-hold-sweep-role").get("ManagedPolicyArns")
    (logs_statement,) = statements_with_action(agents, "governance-hold-sweep-role", "logs:PutLogEvents")
    assert [render(r) for r in as_list(logs_statement["Resource"])] == [
        "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/fsi/lambda/fsi-governance-hold-sweep:*"]
    assert "iam:DetachRolePolicy" not in actions
    (attach,) = statements_with_action(agents, "governance-hold-sweep-role", "iam:AttachRolePolicy")
    deny_id = logical_id(agents, "AWS::IAM::ManagedPolicy", "ManagedPolicyName", "governance-hold-deny-all")
    assert attach["Condition"] == {"ArnEquals": {"iam:PolicyARN": {"Ref": deny_id}}}
    assert len(as_list(attach["Resource"])) == 3
    (put,) = statements_with_action(agents, "governance-hold-sweep-role", "dynamodb:PutItem")
    assert put["Condition"] == {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["reconcile#*"]}}
    (query,) = statements_with_action(agents, "governance-hold-sweep-role", "dynamodb:Query")
    assert render(as_list(query["Resource"])[0]).endswith("/index/by_event_type")
    (metric,) = statements_with_action(agents, "governance-hold-sweep-role", "cloudwatch:PutMetricData")
    assert metric["Condition"] == {"StringEquals": {"cloudwatch:namespace": "FSI/GovernanceIntegrity"}}
    assert role_props(agents, "governance-hold-sweep-role")["AssumeRolePolicyDocument"]["Statement"][0][
        "Principal"] == {"Service": "lambda.amazonaws.com"}


def test_sweep_function_inherits_breaker_props_with_its_own_role(agents):
    def fn(name):
        return agents["Resources"][logical_id(agents, "AWS::Lambda::Function", "FunctionName", name)]["Properties"]
    sweep, breaker = fn("fsi-governance-hold-sweep"), fn("fsi-circuit-breaker")
    for key in ("Runtime", "Handler", "Code", "Timeout", "MemorySize", "DeadLetterConfig"):
        assert sweep[key] == breaker[key], key
    assert sweep["Role"] == {"Fn::GetAtt": [logical_id(agents, "AWS::IAM::Role", "RoleName",
                                                       "governance-hold-sweep-role"), "Arn"]}
    assert sweep["Role"] != breaker["Role"]
    assert sweep["Environment"]["Variables"]["BREAKER_ENTRY"] == "sweep"


def test_sweep_schedule(agents):
    (rule,) = [r["Properties"] for r in resources(agents, "AWS::Events::Rule").values()
               if r["Properties"].get("Name") == "fsi-governance-hold-sweep"]
    assert rule["ScheduleExpression"] == "rate(5 minutes)"
    (target,) = rule["Targets"]
    assert target["Input"] == '{"action":"reconcile_hold"}' and target["RetryPolicy"] == {"MaximumRetryAttempts": 2}
    dlq = logical_id(agents, "AWS::SQS::Queue", "QueueName", "fsi-circuit-breaker-dlq")
    assert target["DeadLetterConfig"] == {"Arn": {"Fn::GetAtt": [dlq, "Arn"]}}


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT], ids=["default", "full"])
def test_only_events_invokes_the_sweep(context):
    t = synth(context)["agents"]
    sweep_id = logical_id(t, "AWS::Lambda::Function", "FunctionName", "fsi-governance-hold-sweep")
    perms = [p["Properties"] for p in resources(t, "AWS::Lambda::Permission").values()
             if p["Properties"]["FunctionName"] == {"Fn::GetAtt": [sweep_id, "Arn"]}]
    assert [p["Principal"] for p in perms] == ["events.amazonaws.com"]
    for policy in resources(t, "AWS::IAM::Policy").values():
        for s in policy["Properties"]["PolicyDocument"]["Statement"]:
            rendered = " ".join(render(r) for r in as_list(s["Resource"]))
            if all(a.startswith("logs:") for a in as_list(s["Action"])):
                # The sweep's own log group (its role's scoped log writes).
                rendered = rendered.replace("log-group:/fsi/lambda/fsi-governance-hold-sweep:*", "")
            assert sweep_id not in rendered and "fsi-governance-hold-sweep" not in rendered, s


def test_sweep_alarms_are_action_less(agents):
    alarms = {r["Properties"]["AlarmName"]: r["Properties"]
              for r in resources(agents, "AWS::CloudWatch::Alarm").values()}
    assert alarms["fsi-hold-reconciled"]["MetricName"] == "HoldReconciled"
    assert alarms["fsi-hold-reconciled"]["Period"] == 300
    assert alarms["fsi-hold-sweep-failed"]["MetricName"] == "HoldSweepFailed"
    assert alarms["fsi-hold-sweep-failed"]["Period"] == 900
    for name in ("fsi-hold-reconciled", "fsi-hold-sweep-failed"):
        assert notifies_on_call_only(alarms[name]), name
