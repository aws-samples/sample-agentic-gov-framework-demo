"""
Test: Compliance Gate — vacuous-pass regression on missing source files.

Every `if os.path.exists(handler_path):` structural check in
check_boundary/check_audit/check_access_control had no `else` branch — so
deleting or renaming one of the checked handler.py files made the
corresponding assertion vanish from self.results entirely rather than FAIL,
and the gate's pass/fail is computed only over assertions that actually ran
(failed = total - passed). A missing source file must now record a
`passed: False` entry, matching the existing _load_evidence_or_fail
fail-closed philosophy for cached_output/*.json evidence.
"""
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import compliance_gate as gate_module


def _missing_path(*parts):
    """A path that structurally looks like one of the gate's own
    PROJECT_ROOT-relative handler paths but does not exist."""
    return os.path.join(PROJECT_ROOT, "tests", "__does_not_exist__", *parts)


class TestCheckBoundaryMissingDetectionHandler:
    def test_missing_detection_handler_records_failed_assertion(self, monkeypatch):
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_boundary()

        matches = [
            r for r in gate.results
            if "detection_agent/handler.py missing" in r["description"]
        ]
        assert len(matches) == 1
        assert matches[0]["passed"] is False


class TestCheckAuditMissingExecutorHandler:
    def test_missing_executor_handler_records_failed_assertion(self, monkeypatch):
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_audit()

        matches = [
            r for r in gate.results
            if r["domain"] == "Audit" and "executor_agent/handler.py missing" in r["description"]
        ]
        assert len(matches) == 1
        assert matches[0]["passed"] is False


class TestCheckAccessControlMissingHandlers:
    def test_missing_detection_handler_records_failed_assertion(self, monkeypatch):
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_access_control()

        matches = [
            r for r in gate.results
            if r["domain"] == "Access Control" and "detection_agent/handler.py missing" in r["description"]
        ]
        assert len(matches) == 1
        assert matches[0]["passed"] is False

    def test_missing_compliance_handler_records_failed_assertion(self, monkeypatch):
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_access_control()

        matches = [
            r for r in gate.results
            if r["domain"] == "Access Control" and "compliance_agent/handler.py missing" in r["description"]
        ]
        assert len(matches) == 1
        assert matches[0]["passed"] is False

    def test_missing_executor_handler_records_two_distinct_failed_assertions(self, monkeypatch):
        """The executor handler path is checked twice in check_access_control
        (Bedrock check, then SOX check) — each is its own assertion domain
        and must get its own else, even though the file check is redundant."""
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_access_control()

        matches = [
            r for r in gate.results
            if r["domain"] == "Access Control" and "executor_agent/handler.py missing" in r["description"]
        ]
        assert len(matches) == 2
        assert all(m["passed"] is False for m in matches)

    def test_missing_circuit_breaker_handler_records_failed_assertion(self, monkeypatch):
        monkeypatch.setattr(gate_module, "PROJECT_ROOT", _missing_path())
        gate = gate_module.ComplianceGate()
        gate.check_access_control()

        matches = [
            r for r in gate.results
            if r["domain"] == "Access Control" and "circuit_breaker/handler.py missing" in r["description"]
        ]
        assert len(matches) == 1
        assert matches[0]["passed"] is False


class TestUnmodifiedRepoStillPasses:
    """No regression: with the real, unmodified PROJECT_ROOT, every one of
    the 7 checks finds its file and does not record a missing-file failure."""

    def test_no_missing_file_failures_on_real_repo(self):
        gate = gate_module.ComplianceGate()
        gate.check_boundary()
        gate.check_audit()
        gate.check_access_control()

        missing_file_failures = [
            r for r in gate.results
            if r["description"].endswith("missing - cannot verify control")
            or "cannot verify control" in r["description"]
        ]
        assert missing_file_failures == []
