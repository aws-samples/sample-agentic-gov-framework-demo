"""
Test: Executor Agent — FILE_SAR routes to filing, NEEDS_REVIEW routes to queue.
"""
import pytest
import json
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.executor_agent.handler import handler


class TestExecutorRouting:
    """Verify executor routes decisions correctly."""

    def test_file_sar_routes_to_filing(self):
        """FILE_SAR decision produces FILED action."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-test",
                "detection_id": "det-test",
                "clusters_assessed": [{
                    "cluster_id": "cluster-1",
                    "decision": "FILE_SAR",
                    "sar_narrative": "Test SAR",
                }]
            }
        }
        result = handler(event)
        assert result["total_filed"] == 1
        assert result["actions"][0]["action_taken"] == "FILED"

    def test_needs_review_routes_to_queue(self):
        """NEEDS_REVIEW decision produces ESCALATED action."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-test",
                "detection_id": "det-test",
                "clusters_assessed": [{
                    "cluster_id": "cluster-2",
                    "decision": "NEEDS_REVIEW",
                    "challenger_rationale": "Possible legitimate activity",
                }]
            }
        }
        result = handler(event)
        assert result["total_escalated"] == 1
        assert result["actions"][0]["action_taken"] == "ESCALATED"

    def test_provenance_chain_present(self):
        """Actions include full provenance chain."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-abc",
                "detection_id": "det-xyz",
                "clusters_assessed": [{
                    "cluster_id": "cluster-3",
                    "decision": "FILE_SAR",
                    "sar_narrative": "Test",
                }]
            }
        }
        result = handler(event)
        action = result["actions"][0]
        assert "provenance_chain" in action
        assert "det-xyz" in action["provenance_chain"]
        assert "comp-abc" in action["provenance_chain"]

    def test_mixed_decisions(self):
        """Multiple clusters with different decisions are routed correctly."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-mixed",
                "detection_id": "det-mixed",
                "clusters_assessed": [
                    {"cluster_id": "c1", "decision": "FILE_SAR", "sar_narrative": "SAR 1"},
                    {"cluster_id": "c2", "decision": "NEEDS_REVIEW", "challenger_rationale": "Disputed"},
                    {"cluster_id": "c3", "decision": "FILE_SAR", "sar_narrative": "SAR 2"},
                ]
            }
        }
        result = handler(event)
        assert result["total_filed"] == 2
        assert result["total_escalated"] == 1
