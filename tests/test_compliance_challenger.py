"""
Test: Compliance Agent — Challenger returns AGREE/DISPUTE with rationale.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestComplianceChallenger:
    """Verify challenger model behavior."""

    def test_challenger_opinion_valid(self, cached_compliance):
        """Challenger opinion is AGREE or DISPUTE."""
        valid_opinions = {"AGREE", "DISPUTE"}
        for cluster in cached_compliance["clusters_assessed"]:
            assert cluster["challenger_opinion"] in valid_opinions

    def test_challenger_rationale_present(self, cached_compliance):
        """Challenger provides non-empty rationale."""
        for cluster in cached_compliance["clusters_assessed"]:
            assert "challenger_rationale" in cluster
            assert len(cluster["challenger_rationale"]) > 20

    def test_challenger_metadata_captured(self, cached_compliance):
        """Challenger call captures model_id, latency, guardrail_action."""
        for cluster in cached_compliance["clusters_assessed"]:
            chal_meta = cluster["model_metadata"]["challenger_call"]
            assert "model_id" in chal_meta
            assert "latency_ms" in chal_meta
            assert "guardrail_action" in chal_meta

    def test_prompt_independence(self, cached_compliance):
        """SAR and challenger have different prompt fingerprints."""
        for cluster in cached_compliance["clusters_assessed"]:
            sar_fp = cluster["model_metadata"]["sar_call"].get("prompt_fingerprint")
            chal_fp = cluster["model_metadata"]["challenger_call"].get("prompt_fingerprint")
            assert sar_fp != chal_fp, "Prompts must be methodologically independent"
