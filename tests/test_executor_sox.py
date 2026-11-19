"""
Test: Executor Agent — SOX enforcement rejects override/approve signals.
"""
import pytest
import json
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.executor_agent.handler import (
    handler, check_sox_violation, check_sox_violation_payload,
)


class TestExecutorSOX:
    """Verify SOX separation of duties enforcement (structured key checks)."""

    def test_override_signal_rejected(self):
        """A forbidden override KEY in the envelope is rejected."""
        event = {
            "mode": "local",
            "override_decision": True,
            "compliance_output": {"clusters_assessed": []}
        }
        result = handler(event)
        assert result.get("error") == "SOX_VIOLATION"

    def test_force_approve_rejected(self):
        """A forbidden 'force_approve' KEY in the envelope is rejected."""
        event = {
            "mode": "local",
            "force_approve": True,
            "compliance_output": {"clusters_assessed": []}
        }
        result = handler(event)
        assert result.get("error") == "SOX_VIOLATION"

    def test_override_key_inside_payload_rejected(self):
        """A forbidden override KEY inside the resolved compliance_output is
        rejected even when it is not in the envelope."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "c",
                "detection_id": "d",
                "clusters_assessed": [],
                "override_decision": "FILE_SAR",
            },
        }
        result = handler(event)
        assert result.get("error") == "SOX_VIOLATION"

    def test_override_key_inside_cluster_rejected(self):
        """A forbidden override KEY inside a cluster is rejected per-cluster."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "c",
                "detection_id": "d",
                "clusters_assessed": [{
                    "cluster_id": "x",
                    "decision": "FILE_SAR",
                    "force_approve": True,
                }],
            },
        }
        result = handler(event)
        assert result.get("error") == "SOX_VIOLATION"

    def test_model_prose_value_does_not_over_match(self):
        """A denylisted WORD inside a SAR narrative / challenger rationale is
        ordinary model prose and must NOT suppress the batch — the old
        substring scan falsely rejected this."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-prose",
                "detection_id": "det-prose",
                "clusters_assessed": [{
                    "cluster_id": "c1",
                    "decision": "FILE_SAR",
                    "sar_narrative": "The prior analyst approved an override of the modify request; "
                                     "we recommend filing to bypass further delay and cancel_sar ambiguity.",
                    "challenger_rationale": "Concur; nothing to reopen or skip_review.",
                }],
            },
        }
        result = handler(event)
        assert "error" not in result, f"Model prose should not trip SOX, got {result}"
        assert result["total_filed"] == 1

    def test_clean_input_passes(self):
        """Clean input without forbidden keys proceeds normally."""
        event = {
            "mode": "local",
            "compliance_output": {
                "compliance_id": "comp-clean",
                "detection_id": "det-clean",
                "clusters_assessed": [{
                    "cluster_id": "c1",
                    "decision": "FILE_SAR",
                    "sar_narrative": "Clean SAR",
                }]
            }
        }
        result = handler(event)
        assert "error" not in result
        assert result["total_filed"] == 1

    def test_envelope_unexpected_key_rejected(self):
        """An unexpected top-level key (smuggled signal) is rejected."""
        violation = check_sox_violation({"mode": "local", "bypass": True})
        assert violation is not None

    def test_payload_clean_with_prose_passes_structured_check(self):
        """check_sox_violation_payload passes a clean payload whose values
        contain denylisted words."""
        payload = {
            "compliance_id": "c",
            "detection_id": "d",
            "clusters_assessed": [{
                "cluster_id": "c1",
                "decision": "FILE_SAR",
                "sar_narrative": "approved to modify and bypass",
            }],
        }
        assert check_sox_violation_payload(payload) is None
