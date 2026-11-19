"""
Deployed-runtime detection for fail-closed guards (stdlib only).

in_deployed_runtime() is True inside a Lambda or AgentCore Runtime container:
- /var/task exists (Lambda and AgentCore direct code deploy extract the
  package there), or
- a runtime marker env var is set: the Lambda runtime's own
  AWS_LAMBDA_FUNCTION_NAME / LAMBDA_TASK_ROOT, or GATE_ARTIFACT_SHA256,
  which cdk/deploy_agentcore_runtimes.py sets on every AgentCore runtime.

Local mode (a shipped fixture with no PAN filter, Bedrock call or durable
audit write) is refused whenever this is True. There is deliberately no
override: an env var that re-enables local mode would be honored by anyone
able to change a runtime's environment.
"""
import os

DEPLOYED_RUNTIME_DIR = "/var/task"
DEPLOYED_RUNTIME_ENV_MARKERS = ("AWS_LAMBDA_FUNCTION_NAME", "LAMBDA_TASK_ROOT", "GATE_ARTIFACT_SHA256")
LOCAL_MODE_REFUSED = "local mode is disabled in the deployed runtime"


def in_deployed_runtime() -> bool:
    return os.path.isdir(DEPLOYED_RUNTIME_DIR) or any(
        os.environ.get(name) for name in DEPLOYED_RUNTIME_ENV_MARKERS)


def refuse_local_mode_in_deployed_runtime(mode) -> None:
    """Raise ValueError (the handlers' existing generic refusal) for
    mode == "local" inside a deployed runtime."""
    if mode == "local" and in_deployed_runtime():
        raise ValueError(LOCAL_MODE_REFUSED)
