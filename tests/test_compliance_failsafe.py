"""
Test: Compliance Agent — Bedrock failure → NEEDS_REVIEW (fail-safe to human).
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestComplianceFailsafe:
    """Verify fail-safe behavior when Bedrock calls fail."""

    def test_challenger_failure_yields_dispute(self):
        """When challenger Bedrock call fails, default to DISPUTE."""
        from lambdas.compliance_agent.handler import assess_cluster

        cluster = {
            "cluster_id": "test-123",
            "accounts": ["acc1", "acc2"],
            "account_count": 2,
            "typology": "circular_structuring",
            "total_amount_usd": 50000,
            "time_span_seconds": 60,
            "merchant_categories": ["crypto_exchange"],
            "confidence_factors": {"avg_intra_amount": 5000, "circular_ratio": 0.8, "fan_out_max": 2, "fan_in_max": 2},
        }

        # Mock bedrock client that raises on all calls
        mock_client = MagicMock()
        mock_client.converse.side_effect = Exception("Bedrock unavailable")

        result = assess_cluster(cluster, mock_client)

        # Both calls fail → challenger defaults to DISPUTE → NEEDS_REVIEW
        assert result["decision"] == "NEEDS_REVIEW"

    def test_sar_failure_still_runs_challenger(self):
        """SAR failure doesn't prevent challenger from running."""
        from lambdas.compliance_agent.handler import assess_cluster

        cluster = {
            "cluster_id": "test-456",
            "accounts": ["acc1", "acc2"],
            "account_count": 2,
            "typology": "layering_shell",
            "total_amount_usd": 30000,
            "time_span_seconds": 90,
            "merchant_categories": ["wire_transfer"],
            "confidence_factors": {"avg_intra_amount": 3000, "circular_ratio": 0.5, "fan_out_max": 3, "fan_in_max": 3},
        }

        mock_client = MagicMock()
        mock_client.converse.side_effect = Exception("Bedrock timeout")

        result = assess_cluster(cluster, mock_client)

        # SAR failed, challenger failed → still produces a result
        assert "sar_narrative" in result
        assert "challenger_opinion" in result
        assert result["decision"] == "NEEDS_REVIEW"
