"""
Test: Detection Agent wrapper — verify output schema matches contract.
"""
import json
import os
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.detection_agent.handler import handler


class TestDetectionWrapper:
    """Verify detection agent output matches interface contract."""

    def test_local_mode_returns_valid_schema(self):
        """Output in local mode matches the contract schema."""
        result = handler({"mode": "local"})

        assert "detection_id" in result
        assert "timestamp" in result
        assert "transaction_count" in result
        assert "gpu_time_seconds" in result
        assert "flagged_clusters" in result
        assert isinstance(result["flagged_clusters"], list)

    def test_detection_id_is_uuid(self):
        """detection_id is a valid UUID format."""
        result = handler({"mode": "local"})
        import uuid
        # Should not raise
        uuid.UUID(result["detection_id"])

    def test_timestamp_is_iso8601(self):
        """timestamp is ISO 8601 format."""
        from datetime import datetime
        result = handler({"mode": "local"})
        # Should not raise
        datetime.fromisoformat(result["timestamp"].replace("Z", "+00:00"))

    def test_flagged_cluster_schema(self, cached_detection):
        """Each flagged cluster has required fields."""
        required_fields = [
            "cluster_id", "typology", "accounts", "account_count",
            "total_amount_usd", "time_span_seconds", "merchant_categories",
            "confidence_factors"
        ]
        for cluster in cached_detection["flagged_clusters"]:
            for field in required_fields:
                assert field in cluster, f"Missing field: {field}"

    def test_confidence_factors_schema(self, cached_detection):
        """confidence_factors has the required sub-fields."""
        required_factors = ["avg_intra_amount", "circular_ratio", "fan_out_max", "fan_in_max"]
        for cluster in cached_detection["flagged_clusters"]:
            cf = cluster["confidence_factors"]
            for factor in required_factors:
                assert factor in cf, f"Missing confidence factor: {factor}"

    def test_pagerank_top_10(self, cached_detection):
        """pagerank_top_10 is a list of dicts with node and score."""
        pr = cached_detection["pagerank_top_10"]
        assert isinstance(pr, list)
        assert len(pr) == 10
        for entry in pr:
            assert "node" in entry
            assert "score" in entry
            assert isinstance(entry["score"], (int, float))

    def test_typology_values(self, cached_detection):
        """Typology is one of the known values."""
        valid_typologies = {"circular_structuring", "layering_shell"}
        for cluster in cached_detection["flagged_clusters"]:
            assert cluster["typology"] in valid_typologies
