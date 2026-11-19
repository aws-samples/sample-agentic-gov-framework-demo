"""
Compliance gate: on-call alarm topic, analyst-queue send restriction and
scoped Lambda logging. The pure assertions pass on the real synthesized
templates and fail on each mutated copy. Local synth only.
"""
import copy
import os
import sys

import pytest

from _cdk_synth import DEFAULT_CONTEXT, FULL_CONTEXT, logical_id, resources, synth

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
import compliance_gate  # noqa: E402
from compliance_gate import ComplianceGate, hardening_assertions  # noqa: E402


@pytest.fixture(scope="module")
def real():
    t = synth(DEFAULT_CONTEXT)
    return t["data"], t["agents"]


def _failures(data, agents):
    return [d for _, ok, d in hardening_assertions(data, agents) if not ok]


@pytest.mark.parametrize("context", [DEFAULT_CONTEXT, FULL_CONTEXT, {"alarm_email": "oncall@example.com"}],
                         ids=["default", "full", "email"])
def test_assertions_pass_on_real_templates(context):
    t = synth(context)
    results = hardening_assertions(t["data"], t["agents"])
    assert len(results) >= 40
    assert [d for _, ok, d in results if not ok] == []
    assert {domain for domain, _, _ in results} == {"Audit", "Access Control"}


def _alarm(template, name):
    return template["Resources"][logical_id(template, "AWS::CloudWatch::Alarm", "AlarmName", name)]["Properties"]


def _mutate(real, fn):
    data, agents = copy.deepcopy(real)
    fn(data, agents)
    return _failures(data, agents)


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(TreatMissingData="notBreaching"),
    lambda p: p.update(MetricName="HoldReconciled"),
    lambda p: p.update(AlarmActions=[]),
], ids=["missing-data-not-breaching", "wrong-metric", "no-action"])
def test_weakened_sweep_liveness_alarm_fails(real, mutation):
    def weaken(data, agents):
        mutation(_alarm(agents, "fsi-hold-sweep-not-running"))
    assert any("fsi-hold-sweep-not-running" in d for d in _mutate(real, weaken))


def test_missing_sweep_liveness_alarm_fails(real):
    def drop(data, agents):
        del agents["Resources"][logical_id(agents, "AWS::CloudWatch::Alarm", "AlarmName",
                                           "fsi-hold-sweep-not-running")]
    failures = _mutate(real, drop)
    assert any("treats missing data as breaching" in d for d in failures)


def test_unencrypted_topic_fails(real):
    def strip(data, agents):
        topic = logical_id(data, "AWS::SNS::Topic", "TopicName", "fsi-governance-alarms")
        del data["Resources"][topic]["Properties"]["KmsMasterKeyId"]
    assert any("is encrypted" in d for d in _mutate(real, strip))


def test_widened_topic_policy_fails(real):
    def widen(data, agents):
        for p in resources(data, "AWS::SNS::TopicPolicy").values():
            p["Properties"]["PolicyDocument"]["Statement"] = [
                s for s in p["Properties"]["PolicyDocument"]["Statement"] if "ArnNotLike" not in s.get("Condition", {})]
            for s in p["Properties"]["PolicyDocument"]["Statement"]:
                if s["Effect"] == "Allow":
                    s["Principal"] = {"AWS": "*"}
    failures = _mutate(real, widen)
    assert any("only this account's CloudWatch alarms" in d for d in failures)
    assert any("denied to every other source" in d for d in failures)


@pytest.mark.parametrize("name", ["fsi-break-glass-assumed", "fsi-out-of-band-hold-change",
                                  "fsi-uncorroborated-drift-alarm", "fsi-drift-metric-publisher-errors"])
def test_review_alarm_without_action_fails(real, name):
    failures = _mutate(real, lambda data, agents: _alarm(agents, name).pop("AlarmActions"))
    assert any(f"alarm {name} notifies" in d for d in failures)


@pytest.mark.parametrize("name", ["fsi-audit-archive-pan-refused", "fsi-audit-archiver-dlq-not-empty"])
def test_archive_alarm_without_action_fails(real, name):
    failures = _mutate(real, lambda data, agents: _alarm(data, name).pop("AlarmActions"))
    assert any(f"alarm {name} notifies" in d for d in failures)


def test_topic_on_a_trigger_alarm_fails(real):
    def add(data, agents):
        review = _alarm(agents, "fsi-break-glass-assumed")["AlarmActions"][0]
        _alarm(agents, "fsi-challenger-dispute-rate-breach")["AlarmActions"].append(review)
    assert any("trigger alarm fsi-challenger-dispute-rate-breach" in d for d in _mutate(real, add))


def test_queue_without_send_deny_fails(real):
    def drop(data, agents):
        for p in resources(data, "AWS::SQS::QueuePolicy").values():
            p["Properties"]["PolicyDocument"]["Statement"] = [
                s for s in p["Properties"]["PolicyDocument"]["Statement"] if s.get("Sid") != "DenySendExceptExecutor"]
    assert any("SendMessage denied" in d for d in _mutate(real, drop))


def test_queue_exempting_another_role_fails(real):
    def swap(data, agents):
        for p in resources(data, "AWS::SQS::QueuePolicy").values():
            for s in p["Properties"]["PolicyDocument"]["Statement"]:
                if s.get("Sid") == "DenySendExceptExecutor":
                    s["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] = ["arn:aws:iam::123456789012:role/admin"]
    assert any("SendMessage denied" in d for d in _mutate(real, swap))


def test_basic_execution_role_back_fails(real):
    def attach(data, agents):
        role = logical_id(agents, "AWS::IAM::Role", "RoleName", "circuit-breaker-role")
        agents["Resources"][role]["Properties"]["ManagedPolicyArns"] = [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]
    assert any("circuit-breaker-role: no AWSLambdaBasicExecutionRole" in d for d in _mutate(real, attach))


def test_wildcard_log_resource_fails(real):
    def widen(data, agents):
        role = logical_id(data, "AWS::IAM::Role", "RoleName", "fsi-audit-archiver-role")
        for p in resources(data, "AWS::IAM::Policy").values():
            if {"Ref": role} in p["Properties"]["Roles"]:
                for s in p["Properties"]["PolicyDocument"]["Statement"]:
                    if "logs:PutLogEvents" in s["Action"]:
                        s["Resource"] = "*"
    assert any("fsi-audit-archiver-role: log writes scoped" in d for d in _mutate(real, widen))


def test_function_on_default_log_group_fails(real):
    def drop(data, agents):
        fn = logical_id(agents, "AWS::Lambda::Function", "FunctionName", "fsi-pan-filter")
        del agents["Resources"][fn]["Properties"]["LoggingConfig"]
    assert any("fsi-pan-filter logs to its own" in d for d in _mutate(real, drop))


def test_gate_records_hardening_assertions(monkeypatch, real):
    monkeypatch.setattr(compliance_gate, "synth_cdk_templates", lambda use_cache=True: real)
    gate = ComplianceGate()
    gate.check_audit_archive()
    hardening = [a for a in gate.results if a["description"].startswith("Hardening:")]
    assert len(hardening) >= 40 and all(a["passed"] for a in hardening)


def test_synth_unavailable_fails_hardening_closed(monkeypatch):
    def boom(use_cache=True):
        raise compliance_gate.SynthUnavailable("cdk synth exited 1")
    monkeypatch.setattr(compliance_gate, "synth_cdk_templates", boom)
    gate = ComplianceGate()
    gate.check_audit_archive()
    (a,) = [a for a in gate.results if a["description"].startswith("Hardening:")]
    assert not a["passed"]
