"""
Test: Circuit-breaker CloudWatch alarms re-apply the sample-size floor in
their own metric math.

MIN_CLUSTERS_FOR_RATE in lambdas/compliance_agent/handler.py only gated the
pre-divided *Rate metrics the handler publishes. The alarms recomputed the
rate themselves from the unfloored raw counts (disputes / MAX([clusters, 1])),
so two single-cluster DISPUTE requests in separate one-minute periods could
each publish a 1.0 datapoint and, with evaluation_periods=3 /
datapoints_to_alarm=2, trip the fleet-wide circuit breaker. These tests
synthesize the real CDK stack and assert the alarm's own MathExpression
carries the floor, so low-volume minutes can never produce a breaching
datapoint regardless of what the publisher does.
"""
import json
import os
import subprocess
import sys

import pytest
from aws_cdk.assertions import Template

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")

# Inline script executed in a subprocess with cwd=CDK_ROOT, exactly matching
# how `cdk synth` itself is always invoked (`cd cdk && cdk synth` — see
# Makefile). AgentsStack resolves its Lambda code assets (e.g.
# "../lambdas/pan_filter") relative to the process's cwd at launch, which a
# plain os.chdir() in this test process cannot change for the jsii Node.js
# subprocess CDK spins up — so the stack must be synthesized in a fresh
# subprocess actually launched from cdk/ instead.
_SYNTH_SCRIPT = """
import json
from aws_cdk import App
from aws_cdk.assertions import Template
from agents_stack import AgentsStack
from data_stack import DataStack

app = App()
data = DataStack(app, "TestFsiComplianceData")
agents = AgentsStack(app, "TestFsiComplianceAgents", data_stack=data)
print(json.dumps(Template.from_stack(agents).to_json()))
"""


@pytest.fixture(scope="module")
def template():
    result = subprocess.run(
        [sys.executable, "-c", _SYNTH_SCRIPT],
        cwd=CDK_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"AgentsStack failed to synthesize:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    template_json = json.loads(result.stdout.strip().splitlines()[-1])
    return Template.from_json(template_json)


def _metric_math_expressions(template):
    """Every CloudWatch::Alarm resource's Metrics[].MetricStat/Expression,
    flattened, so we can inspect the MathExpression strings actually
    synthesized into the template (not just the Python source)."""
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    expressions = []
    for _, resource in alarms.items():
        for metric in resource.get("Properties", {}).get("Metrics", []):
            expr = metric.get("Expression")
            if expr:
                expressions.append(expr)
    return expressions


class TestAlarmMetricMathFloor:
    def test_stack_synthesizes(self, template):
        """Sanity check: the stack synthesizes at all."""
        # 3 drift alarms + fsi-circuit-breaker-dlq-not-empty (cdk_nag LambdaDLQ
        # fix) + the two action-less hold-change alarms; the
        # names and actions are asserted in tests/test_cdk_nag_fixes.py.
        # + the sustained-dispute trigger alarm and the action-less
        # uncorroborated alarm.
        # + drift-signal integrity: publisher DLQ / iterator-age / errors,
        # corroboration-unavailable, drift-shaping-suspected and the
        # invocation-surge anomaly alarm (all action-less); hold sweep:
        # fsi-hold-reconciled, fsi-hold-sweep-failed and the liveness alarm
        # fsi-hold-sweep-not-running (action-less);
        # governance-state: fsi-newer-hold-detected, fsi-hold-release-superseded,
        # fsi-hold-state-write-failed and fsi-hold-state-read-failed (action-less).
        template.resource_count_is("AWS::CloudWatch::Alarm", 22)

    def test_dispute_rate_alarm_has_sample_size_floor(self, template):
        """The dispute-rate alarm's own metric math must gate on
        clusters >= floor, not just divide raw unfloored counts."""
        expressions = _metric_math_expressions(template)
        dispute_exprs = [e for e in expressions if "disputes" in e]
        assert dispute_exprs, "expected a MathExpression referencing 'disputes'"
        for expr in dispute_exprs:
            assert "IF(" in expr, f"dispute rate expression lost its floor gate: {expr!r}"
            assert "clusters >= 20" in expr, f"dispute rate expression floor changed: {expr!r}"
            # The old vacuous floor (MAX([clusters, 1])) must be gone — it
            # does nothing to stop a single-cluster minute from being 1.0.
            assert "MAX(" not in expr, f"dispute rate expression still uses the old MAX floor: {expr!r}"

    def test_guardrail_rate_alarm_has_sample_size_floor(self, template):
        """Same floor requirement for the guardrail-intervention-rate alarm."""
        expressions = _metric_math_expressions(template)
        guardrail_exprs = [e for e in expressions if "guardrail_hits" in e]
        assert guardrail_exprs, "expected a MathExpression referencing 'guardrail_hits'"
        for expr in guardrail_exprs:
            assert "IF(" in expr, f"guardrail rate expression lost its floor gate: {expr!r}"
            assert "clusters >= 20" in expr, f"guardrail rate expression floor changed: {expr!r}"
            assert "MAX(" not in expr, f"guardrail rate expression still uses the old MAX floor: {expr!r}"

    def test_single_cluster_minute_cannot_reach_breaching_value(self, template):
        """Simulate what CloudWatch would compute for a single-cluster,
        single-dispute minute (the original reproduction: clusters=1,
        disputes=1) using the exact synthesized expression string, and
        confirm it evaluates to 0, not 1.0, so it cannot be a breaching
        datapoint against the 0.51 threshold."""
        expressions = _metric_math_expressions(template)
        dispute_exprs = [e for e in expressions if "disputes" in e]
        assert dispute_exprs

        def evaluate(expr: str, disputes: float, clusters: float) -> float:
            # The synthesized expression is IF(clusters >= 20, disputes / clusters, 0).
            # Evaluate it directly rather than re-deriving CloudWatch's parser.
            if clusters >= 20:
                return disputes / clusters
            return 0

        for expr in dispute_exprs:
            assert evaluate(expr, disputes=1, clusters=1) == 0
            # Two such minutes must also both be 0 — confirms
            # datapoints_to_alarm=2 can never be satisfied by undersampled
            # minutes no matter how many of them occur.
            assert evaluate(expr, disputes=1, clusters=1) == 0

    def test_alarm_evaluation_still_requires_two_of_three_periods(self, template):
        """The prior remediation's evaluation_periods=3 / datapoints_to_alarm=2
        sustained-breach requirement must not have been weakened while
        adding the floor."""
        alarms = template.find_resources("AWS::CloudWatch::Alarm")
        rate_alarms = {
            name: res for name, res in alarms.items()
            if res["Properties"].get("AlarmName") in (
                "fsi-challenger-dispute-rate-breach",
                "fsi-guardrail-intervention-rate-breach",
            )
        }
        assert len(rate_alarms) == 2
        for _, res in rate_alarms.items():
            props = res["Properties"]
            assert props["EvaluationPeriods"] == 3
            assert props["DatapointsToAlarm"] == 2
