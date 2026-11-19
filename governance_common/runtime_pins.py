"""
Pinned AgentCore runtime ARNs (stdlib only).

cdk/deploy_agentcore_runtimes.py writes the ARNs of the three runtimes it
created or updated to one SSM String parameter, RUNTIME_ARNS_PARAMETER. The
console (app/invoke_live.py) invokes only those ARNs: nothing resolves a
runtime by name at invoke time, so a runtime registered later under a
matching name is never used. The parameter sits under /fsi/governance/,
whose writes the documented SCP limits to the deploy role
(docs/SECURITY_OPERATIONAL_STEPS.md).

The value is a JSON object with exactly the three agent names as keys. Every
ARN must be an AgentCore runtime ARN in the expected account and region whose
runtime name is the key it is stored under; anything else is refused.
"""
import json
import re

RUNTIME_ARNS_PARAMETER = "/fsi/governance/agentcore-runtime-arns"
AGENT_NAMES = ("DetectionAgent", "ComplianceAgent", "ExecutorAgent")
MAX_PARAMETER_CHARS = 4096

# AgentCore control-plane pattern for agentRuntimeArn (aws partition only).
_RUNTIME_ARN_RE = re.compile(
    r"^arn:aws:bedrock-agentcore:([a-z0-9-]+):(\d{12}):runtime/([a-zA-Z][a-zA-Z0-9_]{0,47})-[a-zA-Z0-9]{10}$")


class RuntimePinsError(ValueError):
    """The pinned runtime ARNs are missing or invalid (fail closed)."""


def check_runtime_arns(arns, *, account: str, region: str) -> dict:
    """Validate a {agent name: runtime ARN} mapping; returns a copy."""
    if not isinstance(arns, dict) or set(arns) != set(AGENT_NAMES):
        raise RuntimePinsError("pinned runtime ARNs must name exactly the three agents")
    checked = {}
    for name in AGENT_NAMES:
        arn = arns[name]
        match = _RUNTIME_ARN_RE.fullmatch(arn) if isinstance(arn, str) else None
        if match is None:
            raise RuntimePinsError(f"pinned {name} ARN is not an AgentCore runtime ARN")
        if match.group(1) != region or match.group(2) != account:
            raise RuntimePinsError(f"pinned {name} ARN is not in the expected account and region")
        if match.group(3) != name:
            raise RuntimePinsError(f"pinned {name} ARN names a different runtime")
        checked[name] = arn
    return checked


def parse_runtime_arns(value, *, account: str, region: str) -> dict:
    """Parse and validate the SSM parameter value."""
    if not isinstance(value, str) or len(value) > MAX_PARAMETER_CHARS:
        raise RuntimePinsError("pinned runtime ARNs parameter is malformed")
    try:
        data = json.loads(value)
    except ValueError as exc:
        raise RuntimePinsError("pinned runtime ARNs parameter is not JSON") from exc
    return check_runtime_arns(data, account=account, region=region)


def encode_runtime_arns(arns, *, account: str, region: str) -> str:
    """Validated, canonical parameter value for the deploy to write."""
    return json.dumps(check_runtime_arns(arns, account=account, region=region), sort_keys=True)
