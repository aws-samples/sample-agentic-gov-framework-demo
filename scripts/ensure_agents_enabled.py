#!/usr/bin/env python3
"""
Ensure Agents Enabled — pre-deploy governance-hold check, and the CLI for the
two-person release.

Default (no flag): ONLY detect and report a hold. It exits non-zero and leaves
the hold in place, so a routine `make deploy` can never clear an active
regulatory hold.

Release takes two different people, each under their OWN AWS identity
(`AWS_PROFILE`), against the human breaker entry point
(fsi-circuit-breaker-human):
  --request-release            prints the release request id   (make release-request)
  --approve-release REQUEST_ID approves it (a different person) (make release-approve)

This script never calls iam:DetachRolePolicy itself and never asserts an
identity: each invocation carries a presigned sts:GetCallerIdentity proof with
a single-use nonce, which the Lambda verifies server-side and classifies by IAM
role (circuit_breaker/identity_proof.py, circuit_breaker/authz.py).

Environment variables:
- AWS_REGION                      (default: us-east-1)
- AWS_PROFILE                     (optional; shape-checked before any AWS call)

The governance targets are fixed, never environment overrides: the three
agent role names and the human breaker function are the names
cdk/agents_stack.py creates, and the deny-all ARN is derived from the
caller's account (sts:GetCallerIdentity) plus the fixed policy name.

Exit codes: 0 ok / nothing held / request recorded / release completed;
1 hold detected (detect-only) or the breaker refused the action;
2 bad arguments or AWS profile configuration; 3 the release completed but a
newer hold was recorded during it (re-trip and review, see
docs/RUNBOOK_GOVERNANCE_HOLD.md).
"""
import argparse
import json
import os
import re
import sys

import boto3
from botocore.exceptions import ClientError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker.identity_proof import presign_identity  # noqa: E402
from governance_common.aws_profile_check import ProfileConfigError, check_profile  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")

AGENT_ROLES = [
    "detection-agent-role",
    "compliance-agent-role",
    "executor-agent-role",
]

# Well-known name of the governance-hold policy attached by the circuit breaker.
DENY_POLICY_NAME = "governance-hold-deny-all"
DEFAULT_HUMAN_FUNCTION = "fsi-circuit-breaker-human"
RELEASE_REQUEST_ID_RE = re.compile(r"^[0-9a-f-]{36}$")


def _resolve_deny_policy_arn(iam) -> str:
    """The deny policy ARN: the caller's account (STS) plus the fixed name."""
    account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    return f"arn:aws:iam::{account_id}:policy/{DENY_POLICY_NAME}"


def _check_profile_or_exit():
    """Shape-check AWS_PROFILE (if set) before any AWS call; None if fine."""
    profile = os.environ.get("AWS_PROFILE")
    if not profile:
        return None
    try:
        check_profile(profile, allow_mfa_prompt=True, allow_sso=True)
    except ProfileConfigError as e:
        print(f"[release] {e.message}")
        return 2
    return None


def _invoke_human_breaker(session, payload: dict) -> dict:
    lambda_client = session.client("lambda", region_name=REGION)
    response = lambda_client.invoke(
        FunctionName=DEFAULT_HUMAN_FUNCTION,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    result_payload = response["Payload"].read()
    result = json.loads(result_payload) if result_payload else {}
    if response.get("FunctionError"):
        raise RuntimeError("circuit breaker invocation failed")
    return result


def _proof(session, action: str, target: str) -> dict:
    url, nonce = presign_identity(session, REGION, action, target)
    return {"caller_identity_presigned_url": url, "caller_identity_nonce": nonce}


def request_release(session) -> int:
    result = _invoke_human_breaker(session, {
        "action": "request_release", "mode": "live",
        **_proof(session, "request_release", "active-hold"),
    })
    if result.get("status") != "RELEASE_PENDING":
        print(f"[release] REJECTED by circuit breaker: {result.get('code', '')} "
              f"{result.get('message', '(no message)')}")
        return 1
    print(f"[release] Release requested. Request id: {result['release_request_id']}")
    print(f"[release] Expires at {result.get('expires_at')}. A DIFFERENT person must now run:")
    print(f"[release]   make release-approve REQUEST_ID={result['release_request_id']}")
    return 0


def approve_release(session, request_id: str) -> int:
    result = _invoke_human_breaker(session, {
        "action": "approve_release", "mode": "live", "release_request_id": request_id,
        **_proof(session, "approve_release", request_id),
    })
    if result.get("newer_hold_detected"):
        # A newer hold was claimed while this release detached; the breaker
        # re-attached it. A failed re-attach needs an immediate re-trip.
        failures = result.get("reattach_failures") or {}
        if failures:
            print("[release] A newer hold superseded this release; re-attach FAILED on "
                  f"{', '.join(sorted(failures))}; re-trip now.")
        else:
            print("[release] A newer hold superseded this release; the hold was restored.")
        return 3
    if result.get("status") != "ACTIVE":
        print(f"[release] NOT released: {result.get('code', '')} "
              f"{result.get('message', '(no message)')}")
        return 1
    print(f"[release] Agents re-enabled via circuit breaker: {result.get('message', '')}")
    if result.get("audit_incomplete"):
        print("[release] WARNING: the release completion audit record was not written; "
              "see docs/RUNBOOK_GOVERNANCE_HOLD.md.")
    return 0


def detect_hold() -> int:
    """Read-only check of the agent roles (the default deploy-time path)."""
    iam = boto3.client("iam", region_name=REGION)

    try:
        deny_policy_arn = _resolve_deny_policy_arn(iam)
    except ClientError as e:
        print(f"[hold-check] WARNING: could not determine account/deny-policy ARN: {e}")
        print("[hold-check] Skipping governance-hold check.")
        return 0

    print(f"[hold-check] Checking agent roles for governance hold ({DENY_POLICY_NAME})...")

    held_roles = []
    for role in AGENT_ROLES:
        try:
            attached = iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
        except iam.exceptions.NoSuchEntityException:
            print(f"[hold-check]   {role}: role not found (not deployed yet) — skipping")
            continue
        except ClientError as e:
            print(f"[hold-check]   {role}: could not read policies ({e}) — skipping")
            continue

        if any(p.get("PolicyArn") == deny_policy_arn for p in attached):
            held_roles.append(role)
            print(f"[hold-check]   {role}: GOVERNANCE HOLD detected")
        else:
            print(f"[hold-check]   {role}: ACTIVE (no governance hold)")

    if not held_roles:
        print("[hold-check] All agents already active. Nothing to do.")
        return 0

    print(
        f"[hold-check] {len(held_roles)} role(s) are under an active governance hold: "
        f"{', '.join(held_roles)}."
    )
    print("[hold-check] Deploy stopped. This hold will NOT be cleared automatically.")
    print("[hold-check] Release takes two people: 'make release-request' (operator), then "
          "'make release-approve REQUEST_ID=...' (a different approver).")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the governance hold before deploy, or run one step of the two-person release.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--request-release", action="store_true",
                       help="Request a release of the active hold (prints the request id).")
    group.add_argument("--approve-release", metavar="REQUEST_ID",
                       help="Approve a pending release request (must be a different person).")
    try:
        args = parser.parse_args()
    except SystemExit as e:
        return 2 if e.code else 0

    if not (args.request_release or args.approve_release):
        return detect_hold()

    if args.approve_release is not None and not RELEASE_REQUEST_ID_RE.fullmatch(args.approve_release):
        print("[release] REQUEST_ID must be the 36-character id printed by make release-request.")
        return 2
    profile_problem = _check_profile_or_exit()
    if profile_problem is not None:
        return profile_problem

    session = boto3.Session()
    try:
        if args.request_release:
            return request_release(session)
        return approve_release(session, args.approve_release)
    except Exception as e:  # noqa: BLE001 - report the class only
        print(f"[release] ERROR: circuit breaker invocation failed ({type(e).__name__}).")
        return 1


if __name__ == "__main__":
    sys.exit(main())
