"""
Test: Model Assurance (D5.2) — approved-models registry validation.

Exact, version-pinned matching: only models on the registry, with status
'approved' and unexpired, are allowed.
"""
import os
import sys
from datetime import date

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from model_assurance import (
    load_registry,
    validate_model,
    approved_model_ids,
    normalize_model_id,
    DEFAULT_REGISTRY_PATH,
)

APPROVED = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"


@pytest.fixture
def registry():
    """A synthetic registry with one approved, one revoked, one expired entry."""
    return {
        "registry_version": "test-1",
        "approved_models": [
            {"model_id": APPROVED, "status": "approved",
             "approved_on": "2026-01-01", "expires_on": "2099-01-01"},
            {"model_id": "us.anthropic.claude-revoked-v1:0", "status": "revoked",
             "approved_on": "2025-01-01", "expires_on": "2099-01-01"},
            {"model_id": "us.anthropic.claude-expired-v1:0", "status": "approved",
             "approved_on": "2024-01-01", "expires_on": "2025-01-01"},
        ],
    }


class TestValidateModel:
    def test_approved_model_passes(self, registry):
        ok, reason = validate_model(APPROVED, registry)
        assert ok is True
        assert "approved" in reason.lower()

    def test_unknown_model_fails(self, registry):
        ok, reason = validate_model("us.anthropic.claude-opus-9-99999999-v9:0", registry)
        assert ok is False
        assert "not on the approved" in reason.lower()

    def test_wrong_version_fails(self, registry):
        # Same family, different version suffix — must fail (version pinning).
        ok, reason = validate_model("us.anthropic.claude-sonnet-4-5-20250929-v2:0", registry)
        assert ok is False

    def test_unpinned_base_id_fails(self, registry):
        # Base id without the region/version pin is a different string — fails.
        ok, reason = validate_model("anthropic.claude-sonnet-4-5", registry)
        assert ok is False

    def test_revoked_status_fails(self, registry):
        ok, reason = validate_model("us.anthropic.claude-revoked-v1:0", registry)
        assert ok is False
        assert "not 'approved'" in reason or "status" in reason.lower()

    def test_expired_model_fails(self, registry):
        ok, reason = validate_model("us.anthropic.claude-expired-v1:0", registry,
                                    today=date(2026, 6, 1))
        assert ok is False
        assert "expired" in reason.lower()

    def test_expiry_boundary_still_valid_before_expiry(self, registry):
        # Not yet expired: today before expires_on.
        ok, _ = validate_model("us.anthropic.claude-expired-v1:0", registry,
                               today=date(2024, 12, 31))
        assert ok is True

    def test_empty_model_id_fails(self, registry):
        ok, reason = validate_model("", registry)
        assert ok is False

    def test_whitespace_and_case_normalized(self, registry):
        ok, _ = validate_model(f"  {APPROVED.upper()}  ", registry)
        assert ok is True


class TestRegistry:
    def test_default_registry_loads(self):
        reg = load_registry()
        assert isinstance(reg.get("approved_models"), list)
        assert len(reg["approved_models"]) >= 1

    def test_default_registry_approves_configured_model(self):
        """The model the compliance handler defaults to must be on the registry."""
        reg = load_registry()
        ok, _ = validate_model(APPROVED, reg)
        assert ok is True

    def test_approved_model_ids_excludes_non_approved(self, registry):
        ids = approved_model_ids(registry)
        assert APPROVED in ids
        assert "us.anthropic.claude-revoked-v1:0" not in ids

    def test_missing_registry_raises(self):
        with pytest.raises(FileNotFoundError):
            load_registry("/nonexistent/path/approved_models.json")

    def test_default_registry_path_points_to_data(self):
        assert DEFAULT_REGISTRY_PATH.endswith(os.path.join("data", "approved_models.json"))
