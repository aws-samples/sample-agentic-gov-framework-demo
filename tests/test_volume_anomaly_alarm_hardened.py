"""
Test: VolumeAnomalyAlarm (fsi-detection-volume-anomaly) is hardened against
a single-datapoint trip.

The sibling dispute/guardrail alarms were hardened earlier with evaluation_periods=3 / datapoints_to_alarm=2 and
treat_missing_data=NOT_BREACHING. This third alarm was missed: it was left
as raw Maximum / evaluation_periods=1 / default missing-data handling, and
its ARN is still on the circuit breaker's TRUSTED_ALARM_ARNS allow-list, so
one injected DetectionVolumeMultiplier datapoint could trip the fleet-wide
governance hold.
"""
import json
import os
import subprocess
import sys

import pytest
from aws_cdk.assertions import Template

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_ROOT = os.path.join(PROJECT_ROOT, "cdk")

# Same subprocess-synth pattern as test_alarm_metric_math_floor.py — the
# stack's Lambda code assets are resolved relative to cwd at launch, which a
# plain os.chdir() in this test process cannot change for the jsii Node.js
# subprocess CDK spins up.
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


def _volume_alarm_properties(template):
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    for _, resource in alarms.items():
        props = resource.get("Properties", {})
        if props.get("AlarmName") == "fsi-detection-volume-anomaly":
            return props
    raise AssertionError("fsi-detection-volume-anomaly alarm not found in template")


class TestVolumeAnomalyAlarmHardened:
    def test_evaluation_periods_is_three(self, template):
        props = _volume_alarm_properties(template)
        assert props["EvaluationPeriods"] == 3

    def test_datapoints_to_alarm_is_two(self, template):
        props = _volume_alarm_properties(template)
        assert props["DatapointsToAlarm"] == 2

    def test_treat_missing_data_is_not_breaching(self, template):
        props = _volume_alarm_properties(template)
        assert props["TreatMissingData"] == "notBreaching"

    def test_threshold_and_comparison_unchanged(self, template):
        """The 3x baseline trigger condition itself must be unchanged —
        only the single-datapoint resistance is being added."""
        props = _volume_alarm_properties(template)
        assert props["Threshold"] == 3.0
        assert props["ComparisonOperator"] == "GreaterThanThreshold"

    def test_still_on_trusted_alarm_arns_allowlist(self, template):
        """The breaker's TRUSTED_ALARM_ARNS must still include this alarm
        — hardening it must not accidentally drop it from the trusted
        automatic-trigger set."""
        functions = template.find_resources("AWS::Lambda::Function")
        breaker = None
        for _, resource in functions.items():
            if resource.get("Properties", {}).get("FunctionName") == "fsi-circuit-breaker":
                breaker = resource
                break
        assert breaker is not None
        env_vars = breaker["Properties"]["Environment"]["Variables"]
        trusted_arns = env_vars["TRUSTED_ALARM_ARNS"]
        # TRUSTED_ALARM_ARNS is synthesized as an Fn::Join intrinsic (the
        # account id / region are tokens resolved only at deploy time), not
        # a plain string — search its literal join parts instead.
        join_parts = trusted_arns["Fn::Join"][1]
        literal_parts = [p for p in join_parts if isinstance(p, str)]
        assert any("fsi-detection-volume-anomaly" in p for p in literal_parts)
