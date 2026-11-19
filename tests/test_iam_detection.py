"""
Test: IAM Boundary — Detection agent has no bedrock:InvokeModel permission (structural).
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestIAMDetection:
    """Structural assertion: detection agent code cannot invoke Bedrock."""

    def test_no_bedrock_runtime_client(self):
        """Detection handler does not create a bedrock-runtime client."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "detection_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "bedrock-runtime" not in code
        assert "bedrock_runtime" not in code

    def test_no_invoke_model(self):
        """Detection handler does not call invoke_model or converse."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "detection_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "invoke_model" not in code
        assert ".converse(" not in code

    def test_no_sar_writing(self):
        """Detection agent cannot write to SAR filing."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "detection_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "SAR_BUCKET" not in code
        assert "sar-filing" not in code
