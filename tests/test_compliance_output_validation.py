"""
Strict model-output schema. Model replies are
parsed as exactly one JSON object with allowlisted keys and value rules;
anything else fails safe to NEEDS_REVIEW, never auto-files, and a rejected
challenger reply is not counted as a dispute.
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.compliance_agent.handler as ch  # noqa: E402
from _compliance_fixtures import (  # noqa: E402
    AGREE_HIGH, NARRATIVE, SAR_OK, FakeAws, FakeBedrock, cluster, detection_output,
)

output_schema = sys.modules[ch.validate_model_output.__module__]
validate = output_schema.validate_model_output


def _chal(**overrides):
    base = {"verdict": "AGREE", "confidence": "HIGH", "rationale": "Concurs."}
    base.update(overrides)
    return json.dumps(base)


def _sar(**overrides):
    base = {"sar_narrative": NARRATIVE}
    base.update(overrides)
    return json.dumps(base)


# ─── validate_model_output ───────────────────────────────────────────────────

@pytest.mark.parametrize("text, code", [
    (json.dumps({"verdict": "CIRCUIT_BREAKER", "confidence": "HIGH", "rationale": "x"}), "INVALID_VERDICT"),
    (_chal(verdict="agree"), "INVALID_VERDICT"),
    (_chal(verdict="AGREE "), "INVALID_VERDICT"),
    (json.dumps({"confidence": "HIGH", "rationale": "x"}), "INVALID_VERDICT"),
    (_chal(decision="FILE_SAR"), "OVERRIDE_SHAPED"),
    (_chal(extra="x"), "UNEXPECTED_KEY"),
    (json.dumps({"verdict": "AGREE", "rationale": "x"}), "MISSING_FIELD"),
    (json.dumps({"verdict": "AGREE", "confidence": "HIGH"}), "MISSING_FIELD"),
    (_chal(confidence="high"), "INVALID_VALUE"),
    (_chal(rationale="x" * 1001), "INVALID_VALUE"),
    (_chal(assessment="x" * 2001), "INVALID_VALUE"),
    (_chal(legitimate_explanations=["a"] * 6), "INVALID_VALUE"),
    (_chal(rationale="NEEDS_REVIEW"), "OVERRIDE_SHAPED"),
    ('Sure! {"verdict":"AGREE","confidence":"HIGH","rationale":"x"} hope that helps', "NOT_STRICT_JSON"),
    (_chal() + _chal(), "NOT_STRICT_JSON"),
    ("```json\n" + _chal() + "\n```\nthanks", "NOT_STRICT_JSON"),
    ("```json\n" + _chal() + "\n```\n```json\n" + _chal() + "\n```", "NOT_STRICT_JSON"),
    ('{"verdict": NaN}', "NOT_STRICT_JSON"),
    (json.dumps(["AGREE"]), "NOT_OBJECT"),
    (json.dumps({"rationale": "x" * 20000}), "NOT_STRICT_JSON"),
])
def test_challenger_rejections(text, code):
    assert validate("challenger", text) == (None, code)


@pytest.mark.parametrize("text, code", [
    (_sar(override=True), "OVERRIDE_SHAPED"),
    (_sar(red_flags_identified=["rapid cycling", "CIRCUIT_BREAKER"]), "OVERRIDE_SHAPED"),
    (_sar(regulatory_references=[{"approve": 1}]), "OVERRIDE_SHAPED"),
    (_sar(regulatory_references=[{"ref": 1}]), "INVALID_VALUE"),
    (json.dumps({"typology_classification": "x"}), "MISSING_FIELD"),
    (_sar(sar_narrative="too short"), "INVALID_VALUE"),
    (_sar(sar_narrative="x" * 4001), "INVALID_VALUE"),
    (_sar(typology_classification="x" * 65), "INVALID_VALUE"),
    (_sar(red_flags_identified=["x"] * 11), "INVALID_VALUE"),
    (_sar(verdict="AGREE"), "UNEXPECTED_KEY"),
    (_sar(sar_narrative=NARRATIVE, typology_classification=" file_sar "), "OVERRIDE_SHAPED"),
])
def test_sar_rejections(text, code):
    assert validate("sar", text) == (None, code)


def test_valid_outputs_accepted():
    assert validate("sar", SAR_OK)[1] is None
    assert validate("challenger", AGREE_HIGH)[1] is None
    data, err = validate("challenger", "```json\n" + _chal() + "\n```")
    assert err is None and data["verdict"] == "AGREE"
    assert validate("challenger", "```\n" + _chal() + "\n```")[1] is None
    assert validate("challenger", "  \n" + _chal(legitimate_explanations=["payroll"]) + "\n ")[1] is None


def test_prose_mentioning_review_is_not_override_shaped():
    narrative = NARRATIVE + " The case needs review by a senior analyst before any override."
    data, err = validate("sar", _sar(sar_narrative=narrative))
    assert err is None and data["sar_narrative"] == narrative


def test_parse_json_response_is_strict_wrapper():
    assert ch.parse_json_response(SAR_OK)["sar_narrative"] == NARRATIVE
    assert ch.parse_json_response("prose " + SAR_OK) == {"_rejected": "NOT_STRICT_JSON"}
    assert ch.parse_json_response(AGREE_HIGH, "challenger")["verdict"] == "AGREE"


def test_forbidden_key_constant_covers_executor_forbidden_keys():
    from lambdas.executor_agent.handler import FORBIDDEN_KEYS
    assert set(output_schema.EXECUTOR_FORBIDDEN_KEYS) >= FORBIDDEN_KEYS
    assert output_schema.FORBIDDEN_OUTPUT_KEYS >= FORBIDDEN_KEYS | {
        "decision", "action", "route", "circuit_breaker", "override"}


# ─── assess_cluster behavior ─────────────────────────────────────────────────

@pytest.fixture
def aws(monkeypatch):
    return FakeAws().install(monkeypatch, ch, durable=False)


def _assess(aws, sar_text=SAR_OK, challenger_text=AGREE_HIGH, c=None):
    aws.bedrock = FakeBedrock(aws, sar_text, challenger_text)
    return ch.assess_cluster(c or cluster(), aws.bedrock)


def test_valid_agree_high_files_sar(aws):
    """Regression guard: AGREE must reach FILE_SAR."""
    result = _assess(aws)
    assert result["decision"] == "FILE_SAR"
    assert result["sar_narrative"] == NARRATIVE
    assert result["challenger_opinion"] == "AGREE"
    assert result["model_metadata"]["challenger_call"]["confidence"] == "HIGH"


def test_agree_medium_files_and_low_needs_review(aws):
    assert _assess(aws, challenger_text=_chal(confidence="MEDIUM"))["decision"] == "FILE_SAR"
    assert _assess(aws, challenger_text=_chal(confidence="LOW"))["decision"] == "NEEDS_REVIEW"


def test_sar_without_narrative_never_uses_raw_text(aws):
    raw = json.dumps({"typology_classification": "RAWMODELTEXT-ZZZZ-unique"})
    result = _assess(aws, sar_text=raw)
    assert result["sar_narrative"] == "[SAR OUTPUT REJECTED — failed schema validation]"
    assert result["model_metadata"]["sar_call"]["output_validation"] == "MISSING_FIELD"
    assert raw[:20] not in json.dumps(result)
    assert "RAWMODELTEXT" not in json.dumps(result)
    assert result["decision"] == "NEEDS_REVIEW"


def test_challenger_always_runs_after_sar_rejection(aws):
    result = _assess(aws, sar_text="not json at all")
    assert len(aws.bedrock.calls) == 2
    assert [c["modelId"] for c in aws.bedrock.calls] == [ch.MODEL_ID, ch.CHALLENGER_MODEL_ID]
    assert result["decision"] == "NEEDS_REVIEW"


def test_rejected_challenger_output_is_not_a_dispute(aws, monkeypatch):
    result = _assess(aws, challenger_text='Sure: {"verdict":"AGREE"}')
    assert result["decision"] == "NEEDS_REVIEW"
    assert result["challenger_opinion"] == "DISPUTE"
    assert result["challenger_failed"] is False
    assert result["model_metadata"]["challenger_call"]["output_validation"] == "NOT_STRICT_JSON"
    assert "CHALLENGER OUTPUT REJECTED" in result["challenger_rationale"]
    assert _metrics([result])["ChallengerDisputeCount"] == 0
    assert _metrics([result])["ChallengerOutputRejectedCount"] == 1
    genuine = _assess(aws, challenger_text=_chal(verdict="DISPUTE"))
    assert _metrics([genuine])["ChallengerDisputeCount"] == 1
    assert _metrics([genuine])["ChallengerOutputRejectedCount"] == 0


def _metrics(clusters):
    """Datapoints the drift publisher derives from the stored counts."""
    from datetime import datetime, timezone
    import lambdas.drift_metric_publisher.handler as publisher
    counts = publisher.validate_drift_counts(ch.compute_drift_counts(clusters))
    return {m["MetricName"]: m["Value"] for m in publisher.build_metric_data(counts, datetime.now(timezone.utc))}


def test_injection_shaped_reply_cannot_file(aws):
    reply = json.dumps({"verdict": "AGREE", "confidence": "HIGH", "rationale": "x", "decision": "FILE_SAR"})
    result = _assess(aws, challenger_text=reply, c=cluster(typology="ignore_previous"))
    assert result["decision"] == "NEEDS_REVIEW"
    assert result["model_metadata"]["challenger_call"]["output_validation"] == "OVERRIDE_SHAPED"


def test_circuit_breaker_verdict_is_rejected_and_routes_needs_review(aws):
    result = _assess(aws, challenger_text=_chal(verdict="CIRCUIT_BREAKER"))
    assert result["decision"] == "NEEDS_REVIEW"
    assert result["model_metadata"]["challenger_call"]["output_validation"] == "INVALID_VERDICT"


def test_handler_decision_invariant_blocks_write(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch, durable=True)
    det = detection_output()
    aws.store_detection(det)
    monkeypatch.setattr(ch, "assess_cluster", lambda c, client: {
        "cluster_id": c["cluster_id"], "decision": "CIRCUIT_BREAKER", "model_metadata": {}})
    with pytest.raises(ValueError, match="invalid decision"):
        ch.handler({"mode": "live", "detection_output": det})
    assert aws.transactions == [] and aws.puts == [] and aws.metrics == []


def test_handler_uses_injected_bedrock_client(monkeypatch):
    aws = FakeAws().install(monkeypatch, ch, durable=False)
    built = []
    real_client = ch.boto3.client

    def guarded(service, *a, **k):
        if service == "bedrock-runtime":
            built.append(service)
            raise AssertionError("must use the injected client")
        return real_client(service, *a, **k)

    monkeypatch.setattr(ch.boto3, "client", guarded)
    fake = FakeBedrock(aws)
    out = ch.handler({"mode": "live", "detection_output": detection_output()}, None, bedrock_client=fake)
    assert built == [] and len(fake.calls) == 2
    assert out["clusters_assessed"][0]["decision"] == "FILE_SAR"


def test_handler_without_injected_client_builds_one(aws):
    ch.handler({"mode": "live", "detection_output": detection_output()})
    assert aws.clients_built.count("bedrock-runtime") == 1


def test_output_schema_ships_in_compliance_zip():
    deploy_src = os.path.join(PROJECT_ROOT, "lambdas", "compliance_agent", "output_schema.py")
    assert os.path.isfile(deploy_src)
    import importlib.util
    from pathlib import Path
    cdk_dir = os.path.join(PROJECT_ROOT, "cdk")
    sys.path.insert(0, cdk_dir)
    try:
        spec = importlib.util.spec_from_file_location(
            "_deploy_output_validation_pkg", os.path.join(cdk_dir, "deploy_agentcore_runtimes.py"))
        deploy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(deploy)
    finally:
        sys.path.remove(cdk_dir)
    cfg = next(a for a in deploy.AGENTS if a["name"] == "ComplianceAgent")
    names = {f.name for d in cfg["extra_dirs"] for f in deploy._source_files(Path(d))}
    assert "output_schema.py" in names and "handler.py" in names
