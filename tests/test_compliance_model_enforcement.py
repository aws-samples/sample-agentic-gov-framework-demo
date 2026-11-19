"""
Test: Compliance Agent — approved-models registry is enforced at the
Bedrock invocation point, not just at the deploy-time gate.
"""
import os
import sys
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.compliance_agent.handler as handler_module

# invoke_bedrock takes (kind, text) prompt segments with at least one
# untrusted segment (sent as guardContent).
PROMPT = [(handler_module.TRUSTED, "instructions"), (handler_module.UNTRUSTED, "data")]


class TestModelEnforcement:
    """invoke_bedrock() must reject any model_id that is not on the
    approved-models registry, including the old unapproved default."""

    def test_unapproved_model_rejected(self, monkeypatch):
        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "test-guardrail-id")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        mock_client = MagicMock()
        with pytest.raises(handler_module.UnapprovedModelError):
            handler_module.invoke_bedrock(
                mock_client, PROMPT, "system", "sar",
                use_guardrail=True, model_id="us.meta.llama3-3-70b-instruct-v1:0",
            )
        # The unapproved model must never reach Bedrock.
        mock_client.converse.assert_not_called()

    def test_empty_model_id_rejected(self, monkeypatch):
        """An unset BEDROCK_MODEL_ID/CHALLENGER_MODEL_ID must fail closed,
        not silently fall back to a hard-coded default."""
        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "test-guardrail-id")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        monkeypatch.setattr(handler_module, "MODEL_ID", "")
        mock_client = MagicMock()
        with pytest.raises(handler_module.UnapprovedModelError):
            handler_module.invoke_bedrock(
                mock_client, PROMPT, "system", "sar", use_guardrail=True,
            )
        mock_client.converse.assert_not_called()

    def test_approved_champion_model_passes_validation(self, monkeypatch):
        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "test-guardrail-id")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        mock_client = MagicMock()
        mock_client.converse.return_value = {
            "stopReason": "end_turn",
            "output": {"message": {"content": [{"text": "{}"}]}},
        }
        result = handler_module.invoke_bedrock(
            mock_client, PROMPT, "system", "sar",
            use_guardrail=True, model_id="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        )
        mock_client.converse.assert_called_once()
        assert result["guardrail_intervened"] is False

    def test_approved_challenger_model_passes_validation(self, monkeypatch):
        monkeypatch.setattr(handler_module, "GUARDRAIL_ID", "test-guardrail-id")
        monkeypatch.setattr(handler_module, "GUARDRAIL_VERSION", "1")
        mock_client = MagicMock()
        mock_client.converse.return_value = {
            "stopReason": "end_turn",
            "output": {"message": {"content": [{"text": "{}"}]}},
        }
        handler_module.invoke_bedrock(
            mock_client, PROMPT, "system", "challenger",
            use_guardrail=True, model_id="us.amazon.nova-pro-v1:0",
        )
        mock_client.converse.assert_called_once()
