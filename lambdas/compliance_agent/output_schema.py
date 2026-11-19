"""
Strict model-output validation for the compliance agent.

validate_model_output(call_type, raw_text) -> (data | None, error_code | None)

- Extraction is strict: the whole (stripped) reply must be one JSON object,
  optionally inside exactly one ``` / ```json fenced block with nothing after
  the closing fence. No substring search, no prose before or after.
- Key allowlists per call type; an extra key is UNEXPECTED_KEY.
- Value rules per field (types, lengths, the exact challenger verdict).
- Override-shaped content (a forbidden key at any depth, or a whole string
  value equal to a routing token) is OVERRIDE_SHAPED. Values are compared by
  exact equality, never substring, so ordinary prose is unaffected.

Error codes never contain model text.
"""
import json
import re

MAX_OUTPUT_BYTES = 16 * 1024

NOT_STRICT_JSON = "NOT_STRICT_JSON"
NOT_OBJECT = "NOT_OBJECT"
UNEXPECTED_KEY = "UNEXPECTED_KEY"
MISSING_FIELD = "MISSING_FIELD"
INVALID_VALUE = "INVALID_VALUE"
INVALID_VERDICT = "INVALID_VERDICT"
OVERRIDE_SHAPED = "OVERRIDE_SHAPED"

# By value, not imported, to avoid a cross-agent import: the executor's
# FORBIDDEN_KEYS (lambdas/executor_agent/handler.py) plus routing-shaped
# names. tests/test_compliance_output_validation.py keeps the two in sync.
EXECUTOR_FORBIDDEN_KEYS = frozenset({
    "override", "override_decision", "approve", "force_approve",
    "change_decision", "modify", "modify_compliance", "reopen",
    "skip_review", "bypass", "cancel_sar",
})
FORBIDDEN_OUTPUT_KEYS = EXECUTOR_FORBIDDEN_KEYS | {
    "decision", "action", "route", "circuit_breaker", "override",
}
OVERRIDE_VALUES = frozenset({
    "CIRCUIT_BREAKER", "FILE_SAR", "NEEDS_REVIEW", "OVERRIDE", "APPROVE",
    "FORCE_APPROVE", "SKIP_REVIEW",
})

SAR_KEYS = frozenset({
    "sar_narrative", "typology_classification", "regulatory_references",
    "red_flags_identified",
})
CHALLENGER_KEYS = frozenset({
    "legitimate_explanations", "assessment", "verdict", "confidence", "rationale",
})
VERDICTS = frozenset({"AGREE", "DISPUTE"})
CONFIDENCES = frozenset({"HIGH", "MEDIUM", "LOW"})

_FENCE_RE = re.compile(r"```(?:json)?\n(.*)\n```", re.DOTALL)


def _reject_constant(_name):
    raise ValueError("non-finite constant")


def _extract(raw_text):
    if not isinstance(raw_text, str):
        return None
    text = raw_text.strip()
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        return None
    if text.startswith("```"):
        match = _FENCE_RE.fullmatch(text)
        if match is None or "```" in match.group(1):
            return None
        text = match.group(1)
    try:
        return (json.loads(text, parse_constant=_reject_constant),)
    except ValueError:
        return None


def _walk(value):
    """Yield (keys, strings) found at any depth, iteratively."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                yield "key", key
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            yield "str", item


def _str_list(value, max_items, max_len):
    return (isinstance(value, list) and len(value) <= max_items
            and all(isinstance(v, str) and len(v) <= max_len for v in value))


def _check_sar(data):
    narrative = data.get("sar_narrative")
    if narrative is None:
        return MISSING_FIELD
    if not (isinstance(narrative, str) and 50 <= len(narrative) <= 4000):
        return INVALID_VALUE
    typology = data.get("typology_classification")
    if typology is not None and not (isinstance(typology, str) and len(typology) <= 64):
        return INVALID_VALUE
    for field in ("regulatory_references", "red_flags_identified"):
        if field in data and not _str_list(data[field], 10, 128):
            return INVALID_VALUE
    return None


def _check_challenger(data):
    verdict = data.get("verdict")
    if not (isinstance(verdict, str) and verdict in VERDICTS):
        return INVALID_VERDICT
    confidence = data.get("confidence")
    rationale = data.get("rationale")
    if confidence is None or rationale is None:
        return MISSING_FIELD
    if not (isinstance(confidence, str) and confidence in CONFIDENCES):
        return INVALID_VALUE
    if not (isinstance(rationale, str) and len(rationale) <= 1000):
        return INVALID_VALUE
    assessment = data.get("assessment")
    if assessment is not None and not (isinstance(assessment, str) and len(assessment) <= 2000):
        return INVALID_VALUE
    if "legitimate_explanations" in data and not _str_list(data["legitimate_explanations"], 5, 500):
        return INVALID_VALUE
    return None


def validate_model_output(call_type: str, raw_text):
    """Validate one model reply. Returns (data, None) or (None, error_code)."""
    if call_type == "sar":
        allowed, check = SAR_KEYS, _check_sar
    elif call_type == "challenger":
        allowed, check = CHALLENGER_KEYS, _check_challenger
    else:
        raise ValueError("unknown call_type")

    extracted = _extract(raw_text)
    if extracted is None:
        return None, NOT_STRICT_JSON
    data = extracted[0]
    if not isinstance(data, dict):
        return None, NOT_OBJECT

    walked = list(_walk(data))
    if any(kind == "key" and str(v).lower() in FORBIDDEN_OUTPUT_KEYS for kind, v in walked):
        return None, OVERRIDE_SHAPED
    if any(key not in allowed for key in data):
        return None, UNEXPECTED_KEY
    error = check(data)
    if error is not None:
        return None, error
    if any(kind == "str" and v.strip().upper() in OVERRIDE_VALUES for kind, v in walked):
        return None, OVERRIDE_SHAPED
    return data, None
