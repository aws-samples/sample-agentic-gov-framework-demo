"""
Compliance -> executor seam. Every compliance output
branch, and the cached compliance output, must pass the executor's SOX
payload check, so the pipeline stays runnable under the executor's value
rules.
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.compliance_agent.handler as ch  # noqa: E402
import lambdas.executor_agent.handler as ex  # noqa: E402
from governance_common.payload_limits import new_request_ref  # noqa: E402
from _compliance_fixtures import (  # noqa: E402
    FakeAws, FakeBedrock, cluster, detection_output,
)

REF = new_request_ref()  # never PAN-shaped (a random uuid4 is ~2 %)


class _GuardrailBedrock(FakeBedrock):
    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {"stopReason": "guardrail_intervened", "output": {"message": {"content": []}}}


class _FailingChallenger(FakeBedrock):
    def converse(self, **kwargs):
        if kwargs["modelId"] != ch.MODEL_ID:
            raise RuntimeError("bedrock down")
        return super().converse(**kwargs)


def _branch(monkeypatch, name):
    durable = name in ("verified", "unverified")
    aws = FakeAws().install(monkeypatch, ch, durable=durable)
    det = detection_output([cluster("c1"), cluster("c2")])
    if name == "verified":
        aws.store_detection(det)
    if name == "unverified":
        monkeypatch.setenv("ALLOW_UNVERIFIED_EVALUATION", "true")
    if name == "challenger_failed":
        aws.bedrock = _FailingChallenger(aws)
    if name == "output_rejected":
        aws.bedrock = FakeBedrock(aws, sar_text="nope", challenger_text='Sure {"verdict":"AGREE"}')
    if name == "guardrail_hit":
        aws.bedrock = _GuardrailBedrock(aws)
    return ch.handler({"mode": "live", "detection_output": det, "request_ref": REF})


BRANCHES = ["normal", "challenger_failed", "output_rejected", "guardrail_hit",
            "unverified", "not_checked", "verified"]


@pytest.mark.parametrize("name", BRANCHES)
def test_every_compliance_branch_passes_executor_sox_check(monkeypatch, name):
    out = _branch(monkeypatch, name)
    assert "error" not in out
    assert out["request_ref"] == REF
    assert ex.check_sox_violation_payload(out) is None
    assert ex.check_sox_violation({"mode": "live", "compliance_output": out}) is None
    # Any new cluster-level data lives inside model_metadata only.
    for c in out["clusters_assessed"]:
        assert set(c) <= ex.ALLOWED_CLUSTER_KEYS, set(c) - ex.ALLOWED_CLUSTER_KEYS


def test_branch_outputs_cover_expected_shapes(monkeypatch):
    seen = {name: _branch(monkeypatch, name) for name in BRANCHES}
    assert seen["verified"]["provenance_status"] == "VERIFIED" and "dispatch_token" in seen["verified"]
    assert seen["unverified"]["provenance_status"] == "UNVERIFIED"
    assert seen["not_checked"]["provenance_status"] == "NOT_CHECKED"
    assert all(c["challenger_failed"] for c in seen["challenger_failed"]["clusters_assessed"])
    assert all(c["guardrail_triggered"] for c in seen["guardrail_hit"]["clusters_assessed"])
    assert all(c["model_metadata"]["challenger_call"].get("output_validation")
               for c in seen["output_rejected"]["clusters_assessed"])


def test_cached_compliance_output_passes_executor_sox_check():
    with open(os.path.join(PROJECT_ROOT, "cached_output", "compliance_result.json"), encoding="utf-8") as f:
        cached = json.load(f)
    assert ex.check_sox_violation_payload(cached) is None
    assert ex.check_sox_violation_payload(ch.handler({"mode": "local"})) is None


def test_new_payload_keys_are_pass_through_only():
    assert {"provenance_status", "dispatch_token", "request_ref"} <= ex.ALLOWED_PAYLOAD_KEYS
    assert ex.ALLOWED_ENVELOPE_KEYS == {"mode", "compliance_output"}
