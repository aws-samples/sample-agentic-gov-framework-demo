"""
Caller-supplied transaction_file replaced by a dataset_id allowlist.
Neither the shim nor the handler lets a request
name a file; the CLI entry point keeps path confinement.
"""
import importlib.util
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from _detection_fixtures import load_detection_shim, post  # noqa: E402

BAD_FILES = ["../../etc/passwd", "/etc/passwd", "data/../cached_output/detection_result.json",
             "transactions_small.jsonl", "%2e%2e/x.json"]
BAD_DATASET_IDS = ["../sample-small", "sample-small/../x", "SAMPLE-SMALL", "sample_small",
                   "sample-small\x00", "a" * 33, {"a": 1}, 7, None, ["sample-small"], ""]


def _forbid(*a, **k):
    raise AssertionError("no file access is allowed for this request")


@pytest.fixture
def no_file_access(monkeypatch):
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    monkeypatch.setattr(h, "load_transactions", _forbid)
    # handler.py imports fraud_detection as a top-level module (its own
    # sys.path entry); patch that module object too.
    monkeypatch.setattr(sys.modules["fraud_detection"], "_resolve_confined_path", _forbid)


@pytest.fixture
def shim(monkeypatch):
    module = load_detection_shim()
    calls = []
    monkeypatch.setattr(module, "_get_handler", lambda: (lambda event: calls.append(event) or {"ok": 1}))
    module.handler_calls = calls
    return module


@pytest.mark.parametrize("path", BAD_FILES)
def test_transaction_file_refused_by_shim(shim, path):
    status, body = post(shim, {"transaction_file": path})
    assert status == 400
    assert body == {"error": "transaction_file is not accepted; use dataset_id"}
    assert shim.handler_calls == []


@pytest.mark.parametrize("path", BAD_FILES)
def test_transaction_file_refused_by_handler(no_file_access, path):
    with pytest.raises(ValueError, match="^transaction_file is not accepted$"):
        h.handler({"mode": "cpu", "transaction_file": path})


@pytest.mark.parametrize("dataset_id", BAD_DATASET_IDS, ids=repr)
def test_bad_dataset_id_refused_by_handler(no_file_access, dataset_id):
    with pytest.raises(ValueError, match="^unknown dataset_id$"):
        h.handler({"mode": "cpu", "dataset_id": dataset_id})


@pytest.mark.parametrize("dataset_id", [d for d in BAD_DATASET_IDS if d is not None], ids=repr)
def test_bad_dataset_id_never_reaches_a_file(shim, dataset_id):
    status, body = post(shim, {"dataset_id": dataset_id})
    assert status == 400
    assert body == {"error": "invalid dataset_id"}
    assert shim.handler_calls == []


def test_unknown_but_well_formed_dataset_id_forwarded_then_refused(shim):
    status, _ = post(shim, {"dataset_id": "other-set"})
    assert status == 200
    assert shim.handler_calls == [{"mode": "cpu", "dataset_id": "other-set"}]
    with pytest.raises(ValueError, match="^unknown dataset_id$"):
        h.handler({"mode": "cpu", "dataset_id": "other-set"})


def test_shim_forwards_valid_dataset_id_only(shim):
    status, _ = post(shim, {"dataset_id": "sample-small"})
    assert status == 200
    assert shim.handler_calls == [{"mode": "cpu", "dataset_id": "sample-small"}]


@pytest.mark.parametrize("event", [{"mode": "cpu", "dataset_id": "sample-small"}, {"mode": "cpu"}],
                         ids=["explicit", "default"])
def test_sample_small_loads_allowlisted_file(monkeypatch, event):
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    seen = []
    real = h.load_transactions

    def spy(path):
        seen.append(path)
        return real(path)

    monkeypatch.setattr(h, "load_transactions", spy)
    monkeypatch.setattr(h, "detect_fraud_cpu", lambda txns: ([], 0.0, []))
    out = h.handler(event)
    assert seen == ["transactions_small.jsonl"]
    assert out["transaction_count"] == 218


def test_run_detection_from_file_keeps_confinement(monkeypatch):
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    with pytest.raises(ValueError, match="outside the allowed data directory"):
        h.run_detection_from_file("/etc/hosts.json", "cpu")
    out = h.run_detection_from_file(os.path.join(PROJECT_ROOT, "data", "transactions_small.jsonl"), "cpu")
    assert len(out["flagged_clusters"]) == 2


def test_detection_zip_ships_the_dataset(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "_deploy_dataset_allowlist", os.path.join(PROJECT_ROOT, "cdk", "deploy_agentcore_runtimes.py"))
    deploy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deploy)
    monkeypatch.setattr(deploy.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0))
    root = Path(PROJECT_ROOT)
    cfg = next(a for a in deploy.AGENTS if a["name"] == "DetectionAgent")
    assert (root / "data" / "transactions_small.jsonl", "data/transactions_small.jsonl") in cfg["root_files"]
    # Package from a copy of the tree so nothing is written into the repo.
    ignore = shutil.ignore_patterns("__pycache__", "lib", "*.pyc")
    for rel in ("agentcore", "lambdas", "governance_common", "data"):
        shutil.copytree(root / rel, tmp_path / rel, ignore=ignore)
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)

    def reroot(value):
        if isinstance(value, Path):
            return tmp_path / value.relative_to(root)
        if isinstance(value, (list, tuple)):
            return type(value)(reroot(v) for v in value)
        return value

    zip_path = deploy.package_agent({k: reroot(v) for k, v in cfg.items()}, tmp_path / "build" / "agentcore")
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
    assert "data/transactions_small.jsonl" in names
    assert "lambdas/detection_agent/fraud_detection.py" in names
    assert "lambdas/detection_agent/txn_schema.py" in names
