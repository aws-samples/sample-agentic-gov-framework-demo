"""
Test: Release gate rejects empty evidence lists.

_load_evidence_or_fail only type-checked the evidence value, so
{"clusters_assessed": []} was recorded as "Evidence file present" PASS and
every per-item assertion silently vanished (zero items -> zero assertions).
An empty list must be a FAIL.
"""
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import compliance_gate as gate_module


def _write(tmp_path, payload):
    out = tmp_path / "cached_output"
    out.mkdir(exist_ok=True)
    (out / "compliance_result.json").write_text(json.dumps(payload), encoding="utf-8")


def test_empty_list_is_fail_not_vacuous_pass(tmp_path, monkeypatch):
    _write(tmp_path, {"clusters_assessed": []})
    monkeypatch.setattr(gate_module, "PROJECT_ROOT", str(tmp_path))
    gate = gate_module.ComplianceGate()
    data = gate_module._load_evidence_or_fail(
        gate, "Boundary", "cached_output/compliance_result.json", "clusters_assessed",
    )
    assert data is None
    assert len(gate.results) == 1
    assert gate.results[0]["passed"] is False
    assert not any(r["passed"] for r in gate.results)


def test_non_empty_list_passes(tmp_path, monkeypatch):
    _write(tmp_path, {"clusters_assessed": [{"cluster_id": "c1"}]})
    monkeypatch.setattr(gate_module, "PROJECT_ROOT", str(tmp_path))
    gate = gate_module.ComplianceGate()
    data = gate_module._load_evidence_or_fail(
        gate, "Boundary", "cached_output/compliance_result.json", "clusters_assessed",
    )
    assert data == {"clusters_assessed": [{"cluster_id": "c1"}]}
    assert gate.results == [{
        "domain": "Boundary",
        "description": "Evidence file present: cached_output/compliance_result.json",
        "passed": True,
    }]


def test_non_dict_top_level_is_fail(tmp_path, monkeypatch):
    _write(tmp_path, [])
    monkeypatch.setattr(gate_module, "PROJECT_ROOT", str(tmp_path))
    gate = gate_module.ComplianceGate()
    data = gate_module._load_evidence_or_fail(
        gate, "Boundary", "cached_output/compliance_result.json", "clusters_assessed",
    )
    assert data is None
    assert gate.results[0]["passed"] is False
