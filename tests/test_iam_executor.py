"""
Test: IAM Boundary — Executor agent cannot invoke Bedrock or read transaction source.
"""
import pytest
import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


class TestIAMExecutor:
    """Structural assertion: executor agent has bounded permissions."""

    def test_no_bedrock_access(self):
        """Executor does not create bedrock-runtime client."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "executor_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "bedrock-runtime" not in code
        assert "bedrock_runtime" not in code
        assert "invoke_model" not in code

    def test_no_transaction_reading(self):
        """Executor does not read raw transactions."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "executor_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "transactions.jsonl" not in code
        assert "load_transactions" not in code

    def test_no_detection_modification(self):
        """Executor cannot modify detection results."""
        handler_path = os.path.join(
            PROJECT_ROOT, "lambdas", "executor_agent", "handler.py"
        )
        with open(handler_path, encoding="utf-8") as f:
            code = f.read()
        assert "detection-results" not in code or "put_item" not in code
