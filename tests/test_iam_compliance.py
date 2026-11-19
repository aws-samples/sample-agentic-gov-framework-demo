"""
Test: IAM Boundary — Compliance agent cannot write to SAR filing or disable agents.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestIAMCompliance:
    """Structural assertion: compliance agent has bounded permissions."""

    def test_no_sar_filing_write(self):
        """Compliance agent does not write to S3 SAR bucket."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "SAR_BUCKET" not in code
        assert "s3.put_object" not in code
        assert "s3_client" not in code

    def test_no_iam_role_modification(self):
        """Compliance agent cannot modify IAM roles."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "attach_role_policy" not in code
        assert "detach_role_policy" not in code

    def test_has_bedrock_access(self):
        """Compliance agent does invoke Bedrock (it needs this permission)."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "compliance_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "bedrock-runtime" in code or "converse" in code
