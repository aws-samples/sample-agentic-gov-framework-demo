"""
Test: ChallengerDisputeCount excludes operational challenger failures.

A failed challenger call is recorded as challenger_opinion="DISPUTE" (so
routing fails safe to NEEDS_REVIEW), but the old publisher counted it in
ChallengerDisputeCount. A caller able to force Bedrock failures could then
manufacture a dispute rate of 1.0 and trip the fleet-wide kill switch.
Failures must be counted only in ChallengerFailureCount. The datapoints now
come from the stored drift_counts via fsi-drift-metric-publisher,
so this checks compute_drift_counts -> build_metric_data.
"""
import os
import sys
from unittest.mock import MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from datetime import datetime, timezone

import lambdas.compliance_agent.handler as compliance_handler
import lambdas.drift_metric_publisher.handler as publisher


def _published(clusters, monkeypatch):
    counts = publisher.validate_drift_counts(compliance_handler.compute_drift_counts(clusters))
    metric_data = publisher.build_metric_data(counts, datetime.now(timezone.utc))
    return {m["MetricName"]: m["Value"] for m in metric_data}


def test_failed_challenger_not_counted_as_dispute(monkeypatch):
    failed = {"challenger_opinion": "DISPUTE", "challenger_failed": True}
    metrics = _published([dict(failed) for _ in range(25)], monkeypatch)
    assert metrics["ChallengerDisputeCount"] == 0
    assert metrics["ChallengerFailureCount"] == 25
    assert metrics["ClustersAssessed"] == 25
    assert metrics["ChallengerDisputeRate"] == 0


def test_genuine_disputes_still_counted(monkeypatch):
    clusters = (
        [{"challenger_opinion": "DISPUTE", "challenger_failed": False}] * 3
        + [{"challenger_opinion": "DISPUTE"}] * 2  # no failure flag -> genuine
        + [{"challenger_opinion": "DISPUTE", "challenger_failed": True}] * 4
        + [{"challenger_opinion": "AGREE", "challenger_failed": False}] * 1
    )
    metrics = _published(clusters, monkeypatch)
    assert metrics["ChallengerDisputeCount"] == 5
    assert metrics["ChallengerFailureCount"] == 4


def test_failed_challenger_still_routes_to_needs_review():
    """The routing fail-safe must be unchanged: a failed challenger call is
    never treated as AGREE."""
    from lambdas.compliance_agent.handler import assess_cluster

    cluster = {
        "cluster_id": "c-fail",
        "accounts": ["acc1", "acc2"],
        "account_count": 2,
        "typology": "circular_structuring",
        "total_amount_usd": 50000,
        "time_span_seconds": 60,
        "merchant_categories": ["crypto_exchange"],
        "confidence_factors": {"avg_intra_amount": 5000, "circular_ratio": 0.8,
                               "fan_out_max": 2, "fan_in_max": 2},
    }
    mock_client = MagicMock()
    mock_client.converse.side_effect = Exception("Bedrock unavailable")

    result = assess_cluster(cluster, mock_client)
    assert result["challenger_failed"] is True
    assert result["challenger_opinion"] == "DISPUTE"
    assert result["decision"] == "NEEDS_REVIEW"
