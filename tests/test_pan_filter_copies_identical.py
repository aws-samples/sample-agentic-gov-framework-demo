"""
PAN filter — three-copy byte identity.

lambdas/pan_filter/pan_filter.py and lambdas/pan_filter/handler.py are
canonical; the copies are regenerated with ``cp`` and must be byte-identical.
"""
import hashlib
import os

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sha256(rel_path: str) -> str:
    with open(os.path.join(PROJECT_ROOT, rel_path), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


@pytest.mark.parametrize("copy_path", [
    "lambdas/detection_agent/pan_filter.py",
    "lambdas/executor_agent/pan_filter/pan_filter.py",
    "lambdas/audit_archiver/pan_filter.py",
    "governance_common/pan_filter.py",
])
def test_pan_filter_module_copy_identical(copy_path):
    assert _sha256(copy_path) == _sha256("lambdas/pan_filter/pan_filter.py"), (
        f"{copy_path} differs: cp lambdas/pan_filter/pan_filter.py {copy_path}"
    )


def test_pan_filter_handler_copy_identical():
    assert _sha256("lambdas/executor_agent/pan_filter/handler.py") == _sha256(
        "lambdas/pan_filter/handler.py"
    ), "cp lambdas/pan_filter/handler.py lambdas/executor_agent/pan_filter/handler.py"
