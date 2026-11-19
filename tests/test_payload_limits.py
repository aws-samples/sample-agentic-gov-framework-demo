"""
Test: payload size limits are enforced.

Unit: governance_common.payload_limits (iterative structure walk, JSON
parsing, concurrency gate). Shims: each of the three /invocations shims,
driven through the existing do_POST harness, returns 411 for chunked bodies,
413 for oversize Content-Length (without reading the body) and for structure
limits, 400 without echoing caller bytes, and 429 + Retry-After when the
concurrency gate is full. Packaging: every agent zip ships governance_common
and the shim imports it from the zip layout alone.
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from governance_common import payload_limits as pl

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SHIMS = {
    "detection": PROJECT_ROOT / "agentcore" / "detection_agent" / "main.py",
    "compliance": PROJECT_ROOT / "agentcore" / "compliance_agent" / "main.py",
    "executor": PROJECT_ROOT / "agentcore" / "executor_agent" / "main.py",
}


# ─── Unit: payload_limits ────────────────────────────────────────────────────

def _nested_list(depth):
    root = current = []
    for _ in range(depth - 1):
        child = []
        current.append(child)
        current = child
    return root


class TestCheckStructure:
    def test_ten_thousand_deep_list_raises_limit_error_not_recursion(self):
        with pytest.raises(pl.PayloadLimitError) as info:
            pl.check_structure(_nested_list(10_000))
        assert info.value.code == pl.TOO_DEEP

    def test_depth_boundary(self):
        pl.check_structure(_nested_list(32))
        with pytest.raises(pl.PayloadLimitError) as info:
            pl.check_structure(_nested_list(33))
        assert info.value.code == pl.TOO_DEEP

    def test_node_limit(self):
        pl.check_structure({"x": [0] * 249_998})  # 1 + 1 + 249,998 = 250,000 nodes
        with pytest.raises(pl.PayloadLimitError) as info:
            pl.check_structure({"x": [0] * 249_999})
        assert info.value.code == pl.TOO_MANY_NODES

    def test_string_and_key_length(self):
        pl.check_structure({"x": "a" * 65_536})
        for obj in ({"x": "a" * 65_537}, {"k" * 65_537: 1}, ["a" * 65_537]):
            with pytest.raises(pl.PayloadLimitError) as info:
                pl.check_structure(obj)
            assert info.value.code == pl.STRING_TOO_LONG

    def test_custom_limits(self):
        with pytest.raises(pl.PayloadLimitError):
            pl.check_structure({"a": {"b": 1}}, max_depth=1)
        pl.check_structure({"a": {"b": 1}}, max_depth=2)

    def test_error_is_a_value_error_with_code(self):
        err = pl.PayloadLimitError(pl.TOO_MANY_ITEMS)
        assert isinstance(err, ValueError) and err.code == "TOO_MANY_ITEMS"


class TestParseJsonBody:
    def test_empty_body_is_empty_object(self):
        assert pl.parse_json_body(b"") == {}

    def test_valid_object(self):
        assert pl.parse_json_body(b'{"a": [1, 2]}') == {"a": [1, 2]}

    @pytest.mark.parametrize("body", [b"{", b"[1, 2]", b'"x"', b"\xff\xfe\x00", b"[" * 100_000])
    def test_invalid_or_non_object_is_invalid_json(self, body):
        with pytest.raises(pl.PayloadLimitError) as info:
            pl.parse_json_body(body)
        assert info.value.code == pl.INVALID_JSON

    def test_structure_limits_apply(self):
        with pytest.raises(pl.PayloadLimitError) as info:
            pl.parse_json_body(json.dumps({"x": "a" * 70_000}).encode())
        assert info.value.code == pl.STRING_TOO_LONG


class TestConcurrencyGate:
    def test_non_blocking_and_bounded(self):
        gate = pl.ConcurrencyGate(2)
        assert gate.try_acquire() and gate.try_acquire()
        assert not gate.try_acquire()
        gate.release()
        assert gate.try_acquire()
        gate.release()
        gate.release()
        with pytest.raises(ValueError):
            gate.release()  # bounded: never more slots than the limit

    def test_context_manager(self):
        gate = pl.ConcurrencyGate(1)
        with gate:
            with pytest.raises(pl.ConcurrencyGateFull):
                with gate:
                    pass
        assert gate.try_acquire()

    @pytest.mark.parametrize("limit", [0, -1, "4", None])
    def test_invalid_limit(self, limit):
        with pytest.raises(ValueError):
            pl.ConcurrencyGate(limit)

    @pytest.mark.parametrize("raw,expected", [(None, 4), ("", 4), ("2", 2), ("0", 4), ("-3", 4), ("x", 4)])
    def test_limit_from_env(self, monkeypatch, raw, expected):
        if raw is None:
            monkeypatch.delenv("MAX_CONCURRENT_INVOCATIONS", raising=False)
        else:
            monkeypatch.setenv("MAX_CONCURRENT_INVOCATIONS", raw)
        assert pl.concurrency_limit_from_env() == expected


def test_request_ref_re_accepts_lowercase_uuid4_only():
    assert pl.REQUEST_REF_RE.fullmatch("3f2b8c1e-9a4d-4c2b-8f1e-0123456789ab")
    for bad in ("3F2B8C1E-9A4D-4C2B-8F1E-0123456789AB", "3f2b8c1e-9a4d-1c2b-8f1e-0123456789ab",
                "3f2b8c1e-9a4d-4c2b-7f1e-0123456789ab", "x3f2b8c1e-9a4d-4c2b-8f1e-0123456789ab", ""):
        assert not pl.REQUEST_REF_RE.fullmatch(bad)


# ─── Shims through the do_POST harness ───────────────────────────────────────

def _load_shim(name):
    spec = importlib.util.spec_from_file_location(f"_payload_limits_shim_{name}", SHIMS[name])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _UntouchedReader:
    def read(self, *a, **k):
        raise AssertionError("request body must not be read")


@pytest.fixture(params=sorted(SHIMS))
def shim(request, monkeypatch):
    module = _load_shim(request.param)
    calls = []

    def fake_handler(event):
        calls.append(event)
        return {"ok": True}

    monkeypatch.setattr(module, "_get_handler", lambda: fake_handler)
    module.handler_calls = calls
    return module


def _post(shim, body=b"", headers=None, rfile=None):
    req = object.__new__(shim.AgentHandler)
    req.path = "/invocations"
    req.headers = headers if headers is not None else {"Content-Length": str(len(body))}
    req.rfile = rfile if rfile is not None else io.BytesIO(body)
    req.wfile = io.BytesIO()
    statuses, sent_headers = [], []
    req.send_response = statuses.append
    req.send_header = lambda k, v: sent_headers.append((k, v))
    req.end_headers = lambda: None
    req.do_POST()
    raw = req.wfile.getvalue()
    return statuses, dict(sent_headers), (json.loads(raw) if raw else None), raw


def test_oversize_content_length_is_413_without_reading(shim):
    statuses, _, body, _ = _post(shim, headers={"Content-Length": str(shim.MAX_BODY_BYTES + 1)},
                                 rfile=_UntouchedReader())
    assert statuses == [413]
    assert body == {"error": "Payload Too Large", "max_bytes": shim.MAX_BODY_BYTES}
    assert shim.handler_calls == []


def test_chunked_body_is_411_without_reading(shim):
    statuses, _, body, _ = _post(shim, headers={"Transfer-Encoding": "chunked"}, rfile=_UntouchedReader())
    assert statuses == [411]
    assert body == {"error": "Length Required"}
    assert shim.handler_calls == []


def test_33_deep_json_is_413_too_deep(shim):
    payload = ('{"a":' + "[" * 32 + "]" * 32 + "}").encode()
    statuses, _, body, _ = _post(shim, payload)
    assert statuses == [413]
    assert body == {"error": "Payload structure exceeds limits", "code": "TOO_DEEP"}
    assert shim.handler_calls == []


def test_too_many_nodes_is_413(shim):
    payload = json.dumps({"x": [0] * 250_001}).encode()
    assert len(payload) <= shim.MAX_BODY_BYTES
    statuses, _, body, _ = _post(shim, payload)
    assert statuses == [413]
    assert body["code"] == "TOO_MANY_NODES"
    assert shim.handler_calls == []


def test_long_string_is_413(shim):
    statuses, _, body, _ = _post(shim, json.dumps({"x": "a" * 70_000}).encode())
    assert statuses == [413]
    assert body["code"] == "STRING_TOO_LONG"
    assert shim.handler_calls == []


@pytest.mark.parametrize("payload", [b'{"caller-secret-bytes": ', b'["caller-secret-bytes"]',
                                     b"[" * 100_000])
def test_invalid_json_is_400_without_echo(shim, payload):
    statuses, _, body, raw = _post(shim, payload)
    assert statuses == [400]
    assert body == {"error": "Invalid JSON"}
    assert b"caller-secret-bytes" not in raw and b"detail" not in raw
    assert shim.handler_calls == []


def test_full_gate_is_429_with_retry_after(shim):
    acquired = 0
    while shim._GATE.try_acquire():
        acquired += 1
    assert acquired == shim._GATE.limit
    try:
        statuses, headers, body, _ = _post(shim, b'{"prompt": "hi"}')
    finally:
        for _ in range(acquired):
            shim._GATE.release()
    assert statuses == [429]
    assert headers["Retry-After"] == "2"
    assert body == {"error": "Too Many Requests"}
    assert shim.handler_calls == []


def test_valid_request_still_served_and_gate_released(shim):
    key = {"detection": "transactions_inline", "compliance": "detection_output",
           "executor": "compliance_output"}
    shim_kind = next(k for k, p in SHIMS.items() if Path(shim.__file__) == p)
    payload = json.dumps({key[shim_kind]: [] if shim_kind == "detection" else {}}).encode()
    statuses, _, body, _ = _post(shim, payload)
    assert statuses == [200]
    assert body == {"ok": True}
    assert len(shim.handler_calls) == 1
    assert all(shim._GATE.try_acquire() for _ in range(shim._GATE.limit))
    for _ in range(shim._GATE.limit):
        shim._GATE.release()


def test_handler_exception_releases_gate(shim, monkeypatch):
    monkeypatch.setattr(shim, "_get_handler", lambda: (lambda event: 1 / 0))
    statuses, _, body, _ = _post(shim, b'{"detection_output": {}, "compliance_output": {}, "mode": "x"}')
    assert statuses == [500] and body["error"] == "AGENT_ERROR"
    assert all(shim._GATE.try_acquire() for _ in range(shim._GATE.limit))
    for _ in range(shim._GATE.limit):
        shim._GATE.release()


def test_gate_limit_from_env(monkeypatch):
    monkeypatch.setenv("MAX_CONCURRENT_INVOCATIONS", "2")
    assert _load_shim("detection")._GATE.limit == 2
    monkeypatch.delenv("MAX_CONCURRENT_INVOCATIONS")
    assert _load_shim("compliance")._GATE.limit == 4


@pytest.mark.parametrize("name", sorted(SHIMS))
def test_shims_still_bind_loopback_by_default(name):
    source = SHIMS[name].read_text(encoding="utf-8")
    assert 'os.environ.get("BIND_HOST", "127.0.0.1")' in source
    assert "0.0.0.0" not in source  # nosec B104 -- asserts the shim source does NOT contain 0.0.0.0; nothing binds


# ─── Packaging: governance_common ships in every agent zip ───────────────────

def _load_deploy():
    cdk_dir = str(PROJECT_ROOT / "cdk")
    sys.path.insert(0, cdk_dir)
    try:
        spec = importlib.util.spec_from_file_location(
            "_deploy_agentcore_runtimes_payload_limits", PROJECT_ROOT / "cdk" / "deploy_agentcore_runtimes.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(cdk_dir)
    return module


def _reroot(value, old_root: Path, new_root: Path):
    if isinstance(value, Path):
        return new_root / value.relative_to(old_root)
    if isinstance(value, list):
        return [_reroot(v, old_root, new_root) for v in value]
    if isinstance(value, tuple):
        return tuple(_reroot(v, old_root, new_root) for v in value)
    return value


@pytest.fixture
def packaged_zips(tmp_path, monkeypatch):
    """Build every real AGENTS zip from a copy of the tree (pip monkeypatched,
    no network, nothing written into the repo)."""
    deploy = _load_deploy()
    ignore = shutil.ignore_patterns("__pycache__", "lib", "*.pyc")
    for rel in ("agentcore", "lambdas", "governance_common", "data"):
        shutil.copytree(PROJECT_ROOT / rel, tmp_path / rel, ignore=ignore)
    shutil.copy2(PROJECT_ROOT / "model_assurance.py", tmp_path / "model_assurance.py")
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    pip_calls = []
    monkeypatch.setattr(deploy.subprocess, "run",
                        lambda argv, **kw: pip_calls.append(list(argv)) or subprocess.CompletedProcess(argv, 0))
    zips = {}
    for cfg in deploy.AGENTS:
        rerooted = {k: _reroot(v, PROJECT_ROOT, tmp_path) for k, v in cfg.items()}
        # local_dev=True: the tree copy carries only the committed local-dev
        # registry signature; a deploy build would need the .kms.sig
        # (tests/test_deploy_requires_gate_artifact.py).
        zips[cfg["name"]] = deploy.package_agent(rerooted, tmp_path / "build" / "agentcore", local_dev=True)
    assert pip_calls, "pip must have been invoked (and intercepted)"
    return deploy, zips


def test_each_agent_zip_contains_governance_common(packaged_zips):
    _, zips = packaged_zips
    expected = {f"governance_common/{p.name}" for p in (PROJECT_ROOT / "governance_common").glob("*.py")}
    assert {"governance_common/signing.py", "governance_common/payload_limits.py",
            "governance_common/__init__.py"} <= expected
    assert set(zips) == {"DetectionAgent", "ComplianceAgent", "ExecutorAgent"}
    for name, zip_path in zips.items():
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
        assert expected <= names, (name, sorted(expected - names))
        assert "main.py" in names


def test_shim_imports_governance_common_from_zip_layout(packaged_zips, tmp_path_factory):
    """The deployed layout alone (zip root, no repo root on sys.path) is enough
    for every shim's top-level imports."""
    _, zips = packaged_zips
    for name, zip_path in zips.items():
        root = tmp_path_factory.mktemp(f"zip-{name}") / "task"
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(root)
        # -I: no PYTHONPATH, no cwd/script dir, so only the zip root is added;
        # the module must resolve from inside the extracted zip.
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "import main, governance_common; assert main._GATE.limit == 3; "
                "assert governance_common.__file__.startswith(sys.argv[1]), governance_common.__file__; "
                "assert main.parse_json_body.__module__ == 'governance_common.payload_limits'")
        result = subprocess.run(  # nosec B603 -- static argv, list form, no shell
            [sys.executable, "-I", "-c", code, str(root)],
            cwd=root, capture_output=True, text=True, timeout=60, check=False,
            env={"PATH": os.environ.get("PATH", ""), "MAX_CONCURRENT_INVOCATIONS": "3"},
        )
        assert result.returncode == 0, (name, result.stderr)


def test_deploy_env_sets_shim_concurrency():
    deploy = _load_deploy()
    limits = {a["name"]: a["env_vars"]["MAX_CONCURRENT_INVOCATIONS"] for a in deploy.AGENTS}
    assert limits == {"DetectionAgent": "2", "ComplianceAgent": "4", "ExecutorAgent": "4"}
    for agent in deploy.AGENTS:
        assert agent["packages"] == [deploy.PROJECT_ROOT / "governance_common"]


def test_missing_package_dir_fails_packaging(tmp_path, monkeypatch):
    deploy = _load_deploy()
    monkeypatch.setattr(deploy, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(deploy.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0))
    code_dir = tmp_path / "agent"
    code_dir.mkdir()
    (code_dir / "main.py").write_text("x = 1\n", encoding="utf-8")
    cfg = {"name": "X", "code_dir": code_dir, "packages": [tmp_path / "governance_common"]}
    with pytest.raises(FileNotFoundError):
        deploy.package_agent(cfg, tmp_path / "build" / "agentcore")


# ─── Compliance cluster cap ───────────────────────────────────────

def test_compliance_26_clusters_is_413_without_any_boto3_client(monkeypatch):
    import lambdas.compliance_agent.handler as ch

    def boom(*a, **k):
        raise AssertionError("no AWS client may be built before the cluster cap")

    monkeypatch.setenv("WRITE_AUDIT", "true")
    monkeypatch.setattr(ch.boto3, "client", boom)
    monkeypatch.setattr(ch.boto3, "resource", boom)
    monkeypatch.setattr(ch.boto3, "Session", boom)
    shim = _load_shim("compliance")
    monkeypatch.setattr(shim, "_get_handler", lambda: ch.handler)
    clusters = [{"cluster_id": f"c{i}"} for i in range(26)]
    statuses, _, body, _ = _post(shim, json.dumps(
        {"detection_output": {"detection_id": "det-1", "flagged_clusters": clusters}}).encode())
    assert statuses == [413]
    assert body == {"error": "PAYLOAD_TOO_LARGE", "max_clusters": 25}
    assert ch.MAX_CLUSTERS_PER_REQUEST == 25


# ─── Executor cluster cap ─────────────────────────────────────────
def _no_aws(monkeypatch, module):
    def boom(*a, **k):
        raise AssertionError("no AWS client may be built before the cluster cap")
    monkeypatch.setattr(module.boto3, "client", boom)
    monkeypatch.setattr(module.boto3, "resource", boom)
    monkeypatch.setattr(module.boto3, "Session", boom)


def test_executor_101_clusters_is_413_without_any_aws_call(monkeypatch):
    import lambdas.executor_agent.handler as ex
    _no_aws(monkeypatch, ex)
    monkeypatch.setattr(ex, "write_audit_record",
                        lambda record: (_ for _ in ()).throw(AssertionError("no audit write")))
    shim = _load_shim("executor")
    monkeypatch.setattr(shim, "_get_handler", lambda: ex.handler)
    clusters = [{"cluster_id": f"c{i}", "decision": "FILE_SAR"} for i in range(101)]
    statuses, _, body, _ = _post(shim, json.dumps({"compliance_output": {
        "compliance_id": "comp-1", "detection_id": "det-1", "clusters_assessed": clusters}}).encode())
    assert statuses == [413]
    assert body == {"error": "PAYLOAD_TOO_LARGE", "max_clusters": 100}
    assert ex.MAX_CLUSTERS_PER_REQUEST == 100


def test_executor_100_clusters_passes_the_cap(monkeypatch):
    import lambdas.executor_agent.handler as ex
    monkeypatch.setattr(ex, "write_audit_record_local", lambda record: None)
    monkeypatch.setattr(ex, "execute_file_sar", lambda cluster, mode: {"status": "filed_locally"})
    clusters = [{"cluster_id": f"c{i}", "decision": "FILE_SAR"} for i in range(100)]
    out = ex.handler({"mode": "local", "compliance_output": {
        "compliance_id": "comp-1", "detection_id": "det-1", "clusters_assessed": clusters}})
    assert out["total_filed"] == 100


def test_executor_shim_keeps_sox_403(monkeypatch):
    shim = _load_shim("executor")
    monkeypatch.setattr(shim, "_get_handler", lambda: (lambda event: {"error": "SOX_VIOLATION"}))
    statuses, _, body, _ = _post(shim, json.dumps({"compliance_output": {}}).encode())
    assert statuses == [403] and body == {"error": "SOX_VIOLATION"}


def test_compliance_zip_contains_output_schema(packaged_zips):
    _, zips = packaged_zips
    with zipfile.ZipFile(zips["ComplianceAgent"]) as zf:
        names = set(zf.namelist())
    assert {"lambdas/compliance_agent/output_schema.py", "lambdas/compliance_agent/handler.py"} <= names
