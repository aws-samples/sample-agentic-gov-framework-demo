"""
Destroy AgentCore Runtimes — Pre-CDK teardown script.

Run BEFORE `cdk destroy` to remove AgentCore Runtimes (which are not
managed by CloudFormation). Endpoints must be deleted before runtimes.

Usage:
    python cdk/destroy_agentcore_runtimes.py
"""
import boto3
import os
import sys

REGION = os.environ.get("AWS_REGION", "us-east-1")

AGENT_NAMES = ["DetectionAgent", "ComplianceAgent", "ExecutorAgent"]


# Fixed governance targets (the names agents_stack.py creates); no
# environment overrides.
AGENT_ROLES = [
    "detection-agent-role",
    "compliance-agent-role",
    "executor-agent-role",
]
DENY_POLICY_NAME = "governance-hold-deny-all"
HOLD_ABORT_MESSAGE = (
    "A governance hold is active. Complete the two-person release "
    "(make release-request / make release-approve) or the out-of-band runbook "
    "(docs/RUNBOOK_GOVERNANCE_HOLD.md) first."
)


def _held_roles(region: str) -> list:
    """Read-only check (iam:ListAttachedRolePolicies) of which agent roles
    carry governance-hold-deny-all. Teardown never releases a hold itself:
    release needs two verified people. A role that can't be
    read raises, so the caller aborts instead of guessing."""
    iam = boto3.client("iam", region_name=region)
    deny_policy_arn = (
        f"arn:aws:iam::{boto3.client('sts', region_name=region).get_caller_identity()['Account']}"
        f":policy/{DENY_POLICY_NAME}")
    held = []
    for role in AGENT_ROLES:
        try:
            attached = iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
        except Exception as e:  # noqa: BLE001
            response = getattr(e, "response", None)
            if isinstance(response, dict) and response.get("Error", {}).get("Code") == "NoSuchEntity":
                continue  # role not deployed
            raise
        if any(p.get("PolicyArn") == deny_policy_arn for p in attached):
            held.append(role)
    return held


def main():
    print("=" * 60)
    print("  FSI Agentic Compliance — AgentCore Runtime Teardown")
    print("=" * 60)

    agentcore = boto3.client("bedrock-agentcore-control", region_name=REGION)

    # Never tear down (or let CDK delete the deny-all policy) while a hold is
    # active, and never release one from here: abort with the release steps.
    try:
        held = _held_roles(REGION)
    except Exception as e:  # noqa: BLE001
        print(f"\n  ✗ Could not verify the governance hold state ({type(e).__name__}).")
        print("  Aborting teardown: a hold can't be ruled out.")
        sys.exit(1)
    if held:
        print(f"\n  ✗ Governance hold active on: {', '.join(held)}")
        print(f"  {HOLD_ABORT_MESSAGE}")
        sys.exit(1)
    print("\n  No governance hold active.")

    # List all runtimes and find ours (with pagination)
    try:
        all_runtimes = []
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            response = agentcore.list_agent_runtimes(**kwargs)
            all_runtimes.extend(response.get("agentRuntimes", []))
            next_token = response.get("nextToken")
            if not next_token:
                break
    except Exception as e:
        print(f"\n  Could not list runtimes: {e}")
        print("  (This is expected if AgentCore was never deployed)")
        return

    our_runtimes = []
    for rt in all_runtimes:
        if rt.get("agentRuntimeName") in AGENT_NAMES:
            our_runtimes.append(rt)

    if not our_runtimes:
        print("\n  No FSI Compliance AgentCore Runtimes found. Nothing to delete.")
        return

    for rt in our_runtimes:
        runtime_id = rt["agentRuntimeId"]
        name = rt.get("agentRuntimeName", runtime_id)
        print(f"\n  Deleting {name} ({runtime_id})...")

        # Delete non-DEFAULT endpoints first
        try:
            endpoints = agentcore.list_agent_runtime_endpoints(agentRuntimeId=runtime_id)
            for ep in endpoints.get("agentRuntimeEndpointSummaries", []):
                ep_name = ep.get("endpointName", "")
                if ep_name != "DEFAULT":
                    print(f"    Deleting endpoint: {ep_name}")
                    agentcore.delete_agent_runtime_endpoint(
                        agentRuntimeId=runtime_id,
                        endpointName=ep_name,
                    )
        except Exception as e:
            print(f"    Warning: could not list/delete endpoints: {e}")

        # Delete the runtime
        try:
            agentcore.delete_agent_runtime(agentRuntimeId=runtime_id)
            print(f"    ✓ Deleted {name}")
        except Exception as e:
            print(f"    ✗ Failed to delete {name}: {e}")

    print("\n  Teardown complete.")


if __name__ == "__main__":
    main()
