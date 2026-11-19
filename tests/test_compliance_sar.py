"""
Test: Compliance Agent — SAR generation produces valid narrative.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestComplianceSAR:
    """Verify SAR generation in compliance agent."""

    def test_sar_narrative_present(self, cached_compliance):
        """Each cluster has a non-empty SAR narrative."""
        for cluster in cached_compliance["clusters_assessed"]:
            assert "sar_narrative" in cluster
            assert len(cluster["sar_narrative"]) > 50

    def test_sar_narrative_formal_tone(self, cached_compliance):
        """SAR narrative uses formal regulatory language."""
        for cluster in cached_compliance["clusters_assessed"]:
            narrative = cluster["sar_narrative"]
            # Should contain regulatory indicators
            assert any(word in narrative.lower() for word in
                      ["monitoring", "transaction", "identified", "suspicious", "filing"])

    def test_sar_no_full_account_ids(self, cached_compliance):
        """SAR narrative does not expose full account IDs from detection."""
        # The detection cached output uses acc-XXXX format
        for cluster in cached_compliance["clusters_assessed"]:
            narrative = cluster["sar_narrative"]
            # Real account IDs should be masked in SAR
            assert "acc-7f3a" not in narrative
            assert "acc-2b1c" not in narrative

    def test_model_metadata_captured(self, cached_compliance):
        """SAR call captures model_id, latency, guardrail_action."""
        for cluster in cached_compliance["clusters_assessed"]:
            sar_meta = cluster["model_metadata"]["sar_call"]
            assert "model_id" in sar_meta
            assert "latency_ms" in sar_meta
            assert "guardrail_action" in sar_meta
            assert isinstance(sar_meta["latency_ms"], (int, float))
