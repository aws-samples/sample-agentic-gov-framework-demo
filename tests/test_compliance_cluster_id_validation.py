"""
Test: compliance agent validates cluster_id at ingestion.

The stored cluster_id becomes the executor's routing / completion identity.
A caller-supplied empty, non-string, over-long or odd-charset cluster_id
used to be persisted to compliance-decisions verbatim. The handler now
rejects the request before any Bedrock call or DynamoDB write, and the
HTTP shim returns only the generic AGENT_ERROR + error_id (never the
exception text or the offending value).
"""
import importlib.util
import io
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import lambdas.compliance_agent.handler as compliance_handler


_SECRET_ID = "arn:aws:iam::123456789012:role/secret-cluster-id"

INVALID_IDS = [
    pytest.param("", id="empty"),
    pytest.param(5, id="int"),
    pytest.param(None, id="none"),
    pytest.param({"a": 1}, id="dict"),
    pytest.param(["c1"], id="list"),
    pytest.param("x" * 129, id="overlong"),
    pytest.param("has space", id="space"),
    pytest.param("../../etc/passwd", id="path"),
    pytest.param(_SECRET_ID, id="colon-arn"),
]

VALID_IDS = ["c1", "cluster-3", "test-agree-1", "cluster_a.b",
             "e2f3a4b5-6c7d-8e9f-0a1b-2c3d4e5f6a7b", "x" * 128]


@pytest.fixture
def no_aws(monkeypatch):
    """Fail the test if the handler reaches Bedrock or DynamoDB."""
    def boom(*a, **k):
        raise AssertionError("must reject before any AWS call")

    monkeypatch.setattr(compliance_handler.boto3, "client", boom)
    monkeypatch.setattr(compliance_handler.boto3, "resource", boom)
    monkeypatch.setattr(compliance_handler, "write_to_dynamodb", boom)


def _event(cluster_id):
    return {
        "mode": "live",
        "detection_output": {
            "detection_id": "det-1",
            "flagged_clusters": [
                {"cluster_id": "c1", "transactions": []},
                {"cluster_id": cluster_id, "transactions": []},
            ],
        },
    }


class TestHandlerRejectsInvalidClusterIds:
    @pytest.mark.parametrize("cluster_id", INVALID_IDS)
    def test_invalid_cluster_id_rejected_before_aws(self, no_aws, cluster_id):
        with pytest.raises(ValueError) as exc_info:
            compliance_handler.handler(_event(cluster_id))
        message = str(exc_info.value)
        assert "flagged_clusters[1].cluster_id is invalid" in message
        if isinstance(cluster_id, str) and cluster_id:
            assert cluster_id not in message

    @pytest.mark.parametrize("cluster_id", VALID_IDS)
    def test_valid_cluster_ids_accepted(self, cluster_id):
        compliance_handler.validate_cluster_ids([{"cluster_id": cluster_id}])

    def test_absent_cluster_id_still_accepted(self):
        compliance_handler.validate_cluster_ids([{"transactions": []}])

    def test_empty_batch_unchanged(self, monkeypatch):
        result = compliance_handler.handler(
            {"mode": "live", "detection_output": {"detection_id": "d", "flagged_clusters": []}}
        )
        assert result["clusters_assessed"] == []


def _load_shim():
    path = os.path.join(PROJECT_ROOT, "agentcore", "compliance_agent", "main.py")
    spec = importlib.util.spec_from_file_location("compliance_agentcore_main_cluster_id", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestShimDoesNotLeakValidationText:
    def test_invalid_cluster_id_returns_generic_agent_error(self, monkeypatch, no_aws):
        shim = _load_shim()
        monkeypatch.setattr(shim, "_get_handler", lambda: compliance_handler.handler)
        monkeypatch.setenv("AGENT_MODE", "live")

        body = json.dumps(_event(_SECRET_ID)).encode()
        req = object.__new__(shim.AgentHandler)
        req.path = "/invocations"
        req.headers = {"Content-Length": str(len(body))}
        req.rfile = io.BytesIO(body)
        req.wfile = io.BytesIO()
        statuses = []
        req.send_response = statuses.append
        req.send_header = lambda *a: None
        req.end_headers = lambda: None

        req.do_POST()

        assert statuses == [500]
        response = json.loads(req.wfile.getvalue())
        assert response["error"] == "AGENT_ERROR"
        assert "error_id" in response
        raw = req.wfile.getvalue().decode()
        assert _SECRET_ID not in raw
        assert "cluster_id" not in raw
