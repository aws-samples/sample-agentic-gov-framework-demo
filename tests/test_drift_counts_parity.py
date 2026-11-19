"""
validate_drift_counts is duplicated in the drift metric publisher and the
circuit breaker (separate Lambda assets). One case table runs
through both, and the shared constants agree with the CDK alarm floor.
"""
import importlib
import os
import sys
from decimal import Decimal

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import circuit_breaker.handler as cb  # noqa: E402
import lambdas.drift_metric_publisher.handler as pub  # noqa: E402

BASE = {"clusters": 25, "disputes": 15, "guardrail_hits": 2, "challenger_failures": 1, "output_rejections": 1}

CASES = [
    BASE,
    {k: Decimal(v) for k, v in BASE.items()},
    {**BASE, "clusters": 0, "disputes": 0, "guardrail_hits": 0, "challenger_failures": 0, "output_rejections": 0},
    {**BASE, "clusters": 10000},
    {**BASE, "clusters": 10001},
    {**BASE, "disputes": 26},
    {**BASE, "disputes": -1},
    {**BASE, "disputes": True},
    {**BASE, "disputes": "15"},
    {**BASE, "disputes": 1.0},
    {**BASE, "disputes": Decimal("1.5")},
    {**BASE, "disputes": Decimal("NaN")},
    {**BASE, "disputes": Decimal("Infinity")},
    {**BASE, "extra": 0},
    {k: v for k, v in BASE.items() if k != "clusters"},
    None,
    [],
    "x",
]


@pytest.mark.parametrize("case", CASES)
def test_validators_agree(case):
    assert pub.validate_drift_counts(case) == cb.validate_drift_counts(case)


def test_constants_agree():
    assert pub.DRIFT_COUNT_KEYS == cb.DRIFT_COUNT_KEYS
    assert pub.MAX_COUNT == cb.MAX_DRIFT_COUNT
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "cdk"))
    try:
        agents_stack = importlib.import_module("agents_stack")
    finally:
        sys.path.remove(os.path.join(PROJECT_ROOT, "cdk"))
    assert pub.MIN_CLUSTERS_FOR_RATE == cb.MIN_CLUSTERS_FOR_CORROBORATION == agents_stack.MIN_CLUSTERS_FOR_ALARM_RATE


def test_compute_drift_counts_output_validates():
    import lambdas.compliance_agent.handler as ch
    clusters = [{"challenger_opinion": "DISPUTE"}, {"guardrail_triggered": True}, {"challenger_failed": True}]
    counts = ch.compute_drift_counts(clusters)
    assert pub.validate_drift_counts(counts) == counts == cb.validate_drift_counts(counts)
