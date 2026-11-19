"""
Test: Guardrail enforcement — verify account IDs blocked in model output.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestGuardrailCompliance:
    """Verify guardrail configuration and enforcement."""

    def test_guardrail_config_in_compliance_handler(self):
        """Compliance agent handler configures guardrail on Bedrock calls."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "guardrailConfig" in code
        assert "guardrailIdentifier" in code
        assert "guardrailVersion" in code

    def test_guardrail_checks_stop_reason(self):
        """Handler checks for guardrail_intervened stop reason."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "guardrail_intervened" in code

    def test_guardrail_triggered_flag_in_output(self, cached_compliance):
        """Each cluster assessment includes guardrail_triggered flag."""
        for cluster in cached_compliance["clusters_assessed"]:
            assert "guardrail_triggered" in cluster
            assert isinstance(cluster["guardrail_triggered"], bool)

    def test_cached_output_no_raw_account_ids(self, cached_compliance):
        """SAR narratives in cached output don't contain raw detection account IDs."""
        # Detection uses acc-XXXX format IDs
        for cluster in cached_compliance["clusters_assessed"]:
            narrative = cluster.get("sar_narrative", "")
            # Check that raw account IDs from detection are not exposed
            assert "acc-7f3a" not in narrative
            assert "acc-aa11" not in narrative
