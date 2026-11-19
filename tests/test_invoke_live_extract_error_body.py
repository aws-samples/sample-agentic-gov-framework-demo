"""
Test: app/invoke_live.py live-mode SOX rejection handling for the executor.

Verified live: AgentCore does NOT forward the runtime's response body on a
non-2xx status. When the executor's HTTP shim sends 403 for a SOX_VIOLATION
the caller gets a RuntimeClientError whose e.response is ONLY
{"Error": {"Code": "RuntimeClientError",
           "Message": "Received error (403) from runtime. Please check ..."},
 "ResponseMetadata": {"HTTPStatusCode": 424, ...}, "message": ...}
with no nested body. The primary tests below use that real shape.

_invoke_agentcore must:
- read the status only from a strict anchored match of Error.Message
  (never a substring "403" in a request id / free text);
- corroborate a 403 from the executor's own executor-audit record
  (matched on event_hash, recent timestamp) before reporting it as verified;
- report an unverified SOX result (action_id None) if the record is absent;
- raise every other status, and any 403 from a non-executor agent;
- still honor an explicit nested {"error": "SOX_VIOLATION"} body (fallback).

Every call runs under an explicit session: the fake session's
.client()/.resource() return the mocks, and the audit lookup is an index
Query on executor-audit by_day_ts (never a Scan); the mocked query returns
what the old scan returned (the index projects violation_type).
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import app.invoke_live as invoke_live


class _FakeStreamingBody:
    """Mimics botocore's StreamingBody — a one-shot .read()."""
    def __init__(self, data: bytes):
        self._data = data

    def read(self):
        return self._data


class FakeRuntimeClientError(Exception):
    def __init__(self, response):
        super().__init__("RuntimeClientError")
        self.response = response


def _real_error_response(status: int, request_id: str = "11111111-2222-3333-4444-555555555555"):
    """The exact shape the real AgentCore service returns (no nested body)."""
    msg = (f"Received error ({status}) from runtime. "
           "Please check your CloudWatch logs for more information.")
    return {
        "Error": {"Code": "RuntimeClientError", "Message": msg},
        "ResponseMetadata": {"RequestId": request_id, "HTTPStatusCode": 424,
                             "HTTPHeaders": {}, "RetryAttempts": 0},
        "message": msg,
    }


class _FakeTable:
    def __init__(self, items):
        self.items = items
        self.queries = 0

    def query(self, **kwargs):
        assert kwargs["IndexName"] == "by_day_ts"
        self.queries += 1
        return {"Items": list(self.items)}

    def scan(self, **kwargs):
        raise AssertionError("the SOX audit lookup must never scan the table")


class _FakeSession:
    def __init__(self, client, resource):
        self._client, self._resource = client, resource

    def client(self, service, **kwargs):
        return self._client

    def resource(self, service, **kwargs):
        assert service == "dynamodb"
        return self._resource


@pytest.fixture
def harness(monkeypatch):
    """Explicit fake session: agentcore client raises the configured error;
    the dynamodb resource returns a fake executor-audit table. Ambient
    boto3 is forbidden."""
    import boto3
    state = {"error_response": None, "table": _FakeTable([])}

    client = MagicMock()
    client.exceptions.RuntimeClientError = FakeRuntimeClientError

    def fake_invoke(**kwargs):
        raise FakeRuntimeClientError(state["error_response"])

    client.invoke_agent_runtime.side_effect = fake_invoke

    resource = MagicMock()
    resource.Table.side_effect = lambda name: state["table"]

    def _no_ambient(*a, **k):
        raise AssertionError("ambient boto3 must never be used")
    for name in ("client", "resource", "Session"):
        monkeypatch.setattr(boto3, name, _no_ambient)
    monkeypatch.setattr(invoke_live, "_get_runtime_arn", lambda name, **k: "arn:aws:fake")
    monkeypatch.setattr(invoke_live, "AUDIT_LOOKUP_DELAYS", (0, 0))
    state["session"] = _FakeSession(client, resource)
    return state


def _sox_payload(signal="override", text="Override SAR decision"):
    """Same request test_sox_rejection_live sends."""
    return {
        "mode": "live",
        "action": signal,
        "payload": text,
        "compliance_output": {
            "compliance_id": "sox-test",
            "detection_id": "sox-test",
            "clusters_assessed": [{
                "cluster_id": "sox-test-cluster",
                "decision": "FILE_SAR",
                "sar_narrative": "Test SAR",
                signal: True,
            }],
        },
    }


def _audit_record(payload, action_id="real-action-id-1", ts=None, action_taken="SOX_VIOLATION_REJECTED"):
    ts = ts or datetime.now(timezone.utc)
    return {
        "action_id": action_id,
        "timestamp": ts.isoformat(),
        "action_taken": action_taken,
        "violation_type": "Unexpected key 'action' in request envelope (not on allow-list)",
        "event_hash": invoke_live._event_digest(invoke_live._executor_event_for_digest(payload)),
    }


class TestRealErrorShape:
    def test_403_with_audit_record_returns_verified_result_with_real_action_id(self, harness):
        payload = _sox_payload()
        harness["error_response"] = _real_error_response(403)
        harness["table"] = _FakeTable([_audit_record(payload, "real-action-id-1")])

        result = invoke_live._invoke_agentcore("ExecutorAgent", payload, session=harness["session"])

        assert result["error"] == "SOX_VIOLATION"
        assert result["http_status"] == 403
        assert result["audit_verified"] is True
        assert result["action_id"] == "real-action-id-1"
        assert "Unexpected key 'action'" in result["violation_type"]
        assert result["message"].startswith("Executor cannot modify decisions. Violation:")

    def test_picks_most_recent_matching_record(self, harness):
        payload = _sox_payload()
        now = datetime.now(timezone.utc)
        harness["error_response"] = _real_error_response(403)
        harness["table"] = _FakeTable([
            _audit_record(payload, "older", ts=now - timedelta(seconds=1)),
            _audit_record(payload, "newest", ts=now + timedelta(seconds=1)),
        ])
        result = invoke_live._invoke_agentcore("ExecutorAgent", payload, session=harness["session"])
        assert result["action_id"] == "newest"

    def test_403_without_audit_record_is_unverified_and_has_no_action_id(self, harness):
        payload = _sox_payload()
        other = _sox_payload(signal="modify", text="different request")
        old = datetime.now(timezone.utc) - timedelta(minutes=10)
        harness["error_response"] = _real_error_response(403)
        harness["table"] = _FakeTable([
            _audit_record(other, "other-request"),                        # different event_hash
            _audit_record(payload, "stale", ts=old),                       # too old
            _audit_record(payload, "wrong-type", action_taken="ROUTED"),   # not a SOX record
        ])

        result = invoke_live._invoke_agentcore("ExecutorAgent", payload, session=harness["session"])

        assert result["error"] == "SOX_VIOLATION"
        assert result["http_status"] == 403
        assert result["audit_verified"] is False
        assert result["action_id"] is None
        assert "could not be located" in result["message"]
        # Retried per AUDIT_LOOKUP_DELAYS: 2 attempts x (1 day, or 2 within
        # AUDIT_CLOCK_SKEW_SECONDS of UTC midnight).
        assert harness["table"].queries in (2, 4)

    def test_audit_lookup_failure_is_unverified_not_crash(self, harness):
        class BrokenTable:
            def query(self, **kwargs):
                raise RuntimeError("AccessDenied")

        harness["error_response"] = _real_error_response(403)
        harness["table"] = BrokenTable()
        result = invoke_live._invoke_agentcore("ExecutorAgent", _sox_payload(), session=harness["session"])
        assert result["audit_verified"] is False
        assert result["action_id"] is None

    @pytest.mark.parametrize("status", [400, 404, 413, 424, 500, 502])
    def test_non_403_statuses_are_raised(self, harness, status):
        harness["error_response"] = _real_error_response(status)
        with pytest.raises(FakeRuntimeClientError):
            invoke_live._invoke_agentcore("ExecutorAgent", _sox_payload(), session=harness["session"])

    @pytest.mark.parametrize("message", [
        "Received error (500) from runtime. request id 403-abc-403",
        "Upstream returned 403 Forbidden",
        "request 0403-ffff failed: Received error (403) from runtime.",
        "Received error (403) from runtime",          # missing trailing '.'
        "xReceived error (403) from runtime. Please check",
    ])
    def test_403_lookalikes_are_not_treated_as_403(self, harness, message):
        resp = _real_error_response(500, request_id="403-403-403")
        resp["Error"]["Message"] = message
        resp["message"] = message
        harness["error_response"] = resp
        with pytest.raises(FakeRuntimeClientError):
            invoke_live._invoke_agentcore("ExecutorAgent", _sox_payload(), session=harness["session"])

    def test_403_with_wrong_error_code_is_raised(self, harness):
        resp = _real_error_response(403)
        resp["Error"]["Code"] = "AccessDeniedException"
        harness["error_response"] = resp
        with pytest.raises(FakeRuntimeClientError):
            invoke_live._invoke_agentcore("ExecutorAgent", _sox_payload(), session=harness["session"])

    @pytest.mark.parametrize("agent", ["ComplianceAgent", "DetectionAgent"])
    def test_403_from_non_executor_agent_is_raised(self, harness, agent):
        payload = _sox_payload()
        harness["error_response"] = _real_error_response(403)
        harness["table"] = _FakeTable([_audit_record(payload)])
        with pytest.raises(FakeRuntimeClientError):
            invoke_live._invoke_agentcore(agent, payload, session=harness["session"])

    def test_test_sox_rejection_live_uses_executor_and_verifies(self, harness, monkeypatch):
        sent = {}
        orig = invoke_live._invoke_agentcore

        def spy(agent, payload, *, session):
            sent["agent"], sent["payload"] = agent, payload
            harness["table"] = _FakeTable([_audit_record(payload, "spy-id")])
            return orig(agent, payload, session=session)

        harness["error_response"] = _real_error_response(403)
        monkeypatch.setattr(invoke_live, "_invoke_agentcore", spy)
        result = invoke_live.test_sox_rejection_live("cancel_sar", "Cancel SAR filing",
                                                     session=harness["session"])
        assert sent["agent"] == invoke_live.EXECUTOR_AGENT
        assert result["audit_verified"] is True
        assert result["action_id"] == "spy-id"


class TestEventDigestMatchesExecutor:
    def test_digest_matches_executor_handler(self):
        from lambdas.executor_agent.handler import _event_digest as executor_digest
        event = invoke_live._executor_event_for_digest(_sox_payload())
        assert invoke_live._event_digest(event) == executor_digest(event)

    def test_rebuilt_event_mirrors_http_shim(self):
        payload = _sox_payload()
        event = invoke_live._executor_event_for_digest(payload)
        assert event == {
            "mode": "live",
            "compliance_output": payload["compliance_output"],
            "action": payload["action"],
            "payload": payload["payload"],
        }


class TestNestedBodyFallback:
    """If the service ever forwards the runtime's body, an explicit
    SOX_VIOLATION body is still honored."""

    def test_nested_streaming_body_is_honored(self, harness):
        sox_body = {"error": "SOX_VIOLATION", "message": "blocked", "action_id": "a-123"}
        resp = _real_error_response(403)
        resp["response"] = _FakeStreamingBody(json.dumps(sox_body).encode("utf-8"))
        harness["error_response"] = resp

        result = invoke_live._invoke_agentcore("ExecutorAgent", _sox_payload(), session=harness["session"])
        assert result["error"] == "SOX_VIOLATION"
        assert result["http_status"] == 403
        assert result["action_id"] == "a-123"

    def test_extract_reads_nested_body_key(self):
        sox_body = {"error": "SOX_VIOLATION", "message": "blocked"}
        exc = FakeRuntimeClientError({
            "Error": {"Code": "RuntimeClientError"},
            "body": _FakeStreamingBody(json.dumps(sox_body).encode("utf-8")),
        })
        assert invoke_live._extract_error_body(exc) == sox_body

    def test_real_shape_has_no_body(self):
        exc = FakeRuntimeClientError(_real_error_response(403))
        assert invoke_live._extract_error_body(exc) is None

    def test_plain_agent_dict_accepted(self):
        exc = FakeRuntimeClientError({"error": "SOX_VIOLATION", "message": "blocked"})
        assert invoke_live._extract_error_body(exc) == {"error": "SOX_VIOLATION", "message": "blocked"}

    def test_no_response_attribute_returns_none(self):
        assert invoke_live._extract_error_body(Exception("plain")) is None
