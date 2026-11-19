"""
Test: Compliance Agent — Divergence logic (DISPUTE → NEEDS_REVIEW).
"""
import json
import pytest
import sys
import os
from unittest.mock import MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def _make_converse_response(payload: dict) -> dict:
    """Build a Bedrock Converse-shaped response wrapping a JSON payload,
    matching the structure invoke_bedrock() parses in handler.py."""
    return {
        "stopReason": "end_turn",
        "output": {"message": {"content": [{"text": json.dumps(payload)}]}},
    }


class TestComplianceDivergence:
    """Verify divergence logic between SAR and challenger."""

    def test_dispute_results_in_needs_review(self, cached_compliance):
        """When challenger DISPUTEs, decision must be NEEDS_REVIEW."""
        for cluster in cached_compliance["clusters_assessed"]:
            if cluster["challenger_opinion"] == "DISPUTE":
                assert cluster["decision"] == "NEEDS_REVIEW", \
                    f"DISPUTE should yield NEEDS_REVIEW, got {cluster['decision']}"

    def test_agree_results_in_file_sar(self, cached_compliance):
        """When challenger AGREEs (and no guardrail trigger), decision is FILE_SAR."""
        for cluster in cached_compliance["clusters_assessed"]:
            if cluster["challenger_opinion"] == "AGREE" and not cluster.get("guardrail_triggered"):
                assert cluster["decision"] == "FILE_SAR", \
                    f"AGREE should yield FILE_SAR, got {cluster['decision']}"

    def test_guardrail_trigger_results_in_needs_review(self):
        """When guardrail triggers, decision must be NEEDS_REVIEW regardless of opinion."""
        # Simulate a guardrail-triggered scenario
        from lambdas.compliance_agent.handler import handler
        # In local mode, we verify from cached data
        result = handler({"mode": "local"})
        for cluster in result.get("clusters_assessed", []):
            if cluster.get("guardrail_triggered"):
                assert cluster["decision"] == "NEEDS_REVIEW"

    def test_has_both_agree_and_dispute(self, cached_compliance):
        """Cached output contains both AGREE and DISPUTE for demo purposes."""
        opinions = [c["challenger_opinion"] for c in cached_compliance["clusters_assessed"]]
        assert "AGREE" in opinions, "Cached output should have at least one AGREE"
        assert "DISPUTE" in opinions, "Cached output should have at least one DISPUTE"

    def test_live_agree_verdict_files_sar(self, monkeypatch):
        """A genuine, parseable AGREE verdict from the challenger must reach
        FILE_SAR through assess_cluster(), not be swallowed by an exception.

        Regression test: challenger_rationale_prefix was only
        assigned on the DISPUTE/unrecognized branch, so a real AGREE verdict
        raised UnboundLocalError, which the broad except Exception coerced to
        DISPUTE/challenger_failed=True — silently killing the FILE_SAR path
        in live mode. Verified directly against a mocked Bedrock client
        returning a real AGREE verdict (see security-review-high.md)."""
        import lambdas.compliance_agent.handler as handler_module

        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "test-guardrail-id")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        # invoke_bedrock now enforces the approved-models registry
        # — use the registry's real champion/challenger ids so
        # this test still exercises the live AGREE path rather than being
        # rejected as an unapproved model.
        monkeypatch.setattr(handler_module, "MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
        monkeypatch.setattr(handler_module, "CHALLENGER_MODEL_ID", "us.amazon.nova-pro-v1:0")

        cluster = {
            "cluster_id": "test-agree-1",
            "accounts": ["acc1", "acc2"],
            "account_count": 2,
            "typology": "circular_structuring",
            "total_amount_usd": 50000,
            "time_span_seconds": 60,
            "merchant_categories": ["crypto_exchange"],
            "confidence_factors": {"avg_intra_amount": 5000, "circular_ratio": 0.8, "fan_out_max": 2, "fan_in_max": 2},
        }

        mock_client = MagicMock()
        mock_client.converse.side_effect = [
            _make_converse_response({"sar_narrative": "Transaction monitoring identified a suspicious circular structuring pattern warranting a filing."}),
            _make_converse_response({"verdict": "AGREE", "confidence": "HIGH",
                                     "rationale": "Independently concurs."}),
        ]

        result = handler_module.assess_cluster(cluster, mock_client)

        assert result["challenger_opinion"] == "AGREE"
        assert result["challenger_failed"] is False
        assert result["decision"] == "FILE_SAR"
        assert "CHALLENGER FAILED" not in result["challenger_rationale"]
