"""
Test configuration — shared fixtures for the FSI Agentic Compliance test suite.
"""
import os
import sys
import json
import pytest

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

CACHED_DIR = os.path.join(PROJECT_ROOT, "cached_output")


@pytest.fixture(autouse=True)
def _allow_local_dev_txn_ref_key(monkeypatch):
    """The PAN filter's txn_ref now fails closed unless the key resolves from
    Secrets Manager (TXN_REF_HMAC_SECRET_ARN) or the explicit
    ALLOW_LOCAL_DEV_TXN_REF_KEY opt-in is set. The test suite
    runs locally with no AWS access, so enable the local-dev-only key
    fallback by default and clear the ARN and the (unsupported) plaintext key
    for every test. Tests that specifically exercise the key-resolution logic
    (tests/test_txn_ref_hmac.py) set TXN_REF_HMAC_SECRET_ARN and stub
    ``_fetch_secret_string`` per test, which takes precedence because this
    fixture only sets a default the individual test is free to change."""
    monkeypatch.setenv("ALLOW_LOCAL_DEV_TXN_REF_KEY", "true")
    monkeypatch.delenv("TXN_REF_HMAC_KEY", raising=False)
    monkeypatch.delenv("TXN_REF_HMAC_SECRET_ARN", raising=False)
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    # The other deployed-runtime markers (governance_common.deployed_runtime).
    monkeypatch.delenv("LAMBDA_TASK_ROOT", raising=False)
    monkeypatch.delenv("GATE_ARTIFACT_SHA256", raising=False)


@pytest.fixture(autouse=True)
def _allow_local_dev_signing(monkeypatch):
    """Governance readers (registry loader, gate, console, demos) verify the
    committed local-dev data/approved_models.json.sig, which is honoured only
    with ALLOW_LOCAL_DEV_SIGNING=true outside a deployed runtime.
    Mirror the txn_ref fixture: enable it by default; a test
    that pins the refusal deletes it with monkeypatch.delenv."""
    monkeypatch.setenv("ALLOW_LOCAL_DEV_SIGNING", "true")



@pytest.fixture(autouse=True)
def _reset_registry_latch(monkeypatch):
    """model_assurance keeps an in-process registry_version latch;
    each test starts without one."""
    import model_assurance
    monkeypatch.setattr(model_assurance, "_ACCEPTED_REGISTRY", None)


@pytest.fixture
def cached_detection():
    """Load cached detection result."""
    path = os.path.join(CACHED_DIR, "detection_result.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def cached_compliance():
    """Load cached compliance result."""
    path = os.path.join(CACHED_DIR, "compliance_result.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def cached_drift():
    """Load cached drift metrics."""
    path = os.path.join(CACHED_DIR, "drift_metrics.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)
