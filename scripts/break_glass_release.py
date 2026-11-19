#!/usr/bin/env python3
"""
Out-of-band governance-hold release (deny-all restore).

Use ONLY when the breaker Lambda (fsi-circuit-breaker-human) is unavailable,
following docs/RUNBOOK_GOVERNANCE_HOLD.md. Single-person by necessity, so it
is compensated by:
  - running only under the MFA-gated fsi-breaker-break-glass role (every
    assumption fires the fsi-break-glass-assumed alarm),
  - a mandatory BREAK_GLASS_RELEASE_STARTED audit record BEFORE any detach
    (no record, no effect),
  - a conditional claim of the governance-state item (the same item the
    breaker's trip and release serialize on), so it never detaches a hold
    that a newer trip has claimed,
  - a BREAK_GLASS_RELEASE_COMPLETED record with per-role results and the
    outcome,
  - the fsi-out-of-band-hold-change alarm on every detach it makes,
  - a second-person incident review within 24 h (runbook).

Usage:
    AWS_PROFILE=<break-glass profile> python scripts/break_glass_release.py \
        --incident-id INC-1234 --i-understand-this-is-out-of-band

Before any write the script checks the local clock against AWS time (the
STS response Date header) and reads the governance-state item.

Exit codes: 0 all three roles verified detached; 1 the identity is not the
break-glass role; 2 bad arguments / AWS profile / local clock off AWS time /
the governance-state read or claim failed / the pre-release audit write
failed (nothing detached); 3 partial detach (see the COMPLETED record); 4 a
newer hold claimed the state before the release (nothing detached); 5 a
newer hold was claimed during the release (the sweep restores it; do NOT
re-run). 5 wins over 3.
"""
import argparse
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import boto3

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker import authz  # noqa: E402
from circuit_breaker import governance_state  # noqa: E402
from circuit_breaker.identity_proof import VerifiedPrincipal  # noqa: E402
from governance_common.aws_profile_check import ProfileConfigError, check_profile  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")
# Fixed governance targets (the names cdk/ creates); no environment overrides.
AUDIT_TABLE = "governance-audit"
STATE_TABLE = "governance-state"
AGENT_ROLES = [
    "detection-agent-role",
    "compliance-agent-role",
    "executor-agent-role",
]
DENY_POLICY_NAME = "governance-hold-deny-all"
RETENTION_EXPIRES = "2033-08-17T00:00:00Z"
INCIDENT_ID_RE_PATTERN = r"^[A-Z][A-Z0-9]{1,15}-[0-9]{1,10}$"

# The STS Date header has 1 s resolution (truncated), so a synced clock
# reads up to 1 s plus the response latency ahead of it: refuse when the
# local clock is more than 2 s behind, or more than 3 s ahead of, AWS time.
MAX_CLOCK_SKEW_SECONDS = 2

EXIT_OK, EXIT_NOT_BREAK_GLASS, EXIT_USAGE, EXIT_PARTIAL, EXIT_SUPERSEDED, EXIT_SUPERSEDED_AFTER = (
    0, 1, 2, 3, 4, 5)


def _parse_args(argv):
    parser = argparse.ArgumentParser(description="Out-of-band governance-hold release (incident only).")
    parser.add_argument("--incident-id", required=True,
                        help="Incident ticket id, e.g. INC-1234 (uppercase prefix, hyphen, number)")
    parser.add_argument("--i-understand-this-is-out-of-band", dest="confirmed", action="store_true",
                        required=True, help="Confirms this bypasses the two-person in-band release")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return None
    if not re.fullmatch(INCIDENT_ID_RE_PATTERN, args.incident_id):
        print("[break-glass] --incident-id must look like INC-1234.")
        return None
    return args


def _clock_skew(identity, local_after):
    """local_after minus the STS response Date header, in seconds, or None
    when the header is missing or unparseable."""
    try:
        date = parsedate_to_datetime(identity["ResponseMetadata"]["HTTPHeaders"]["date"])
    except (KeyError, TypeError, ValueError, IndexError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return (local_after - date).total_seconds()


def _classify_caller(session):
    """(arn, Authz, clock skew) for the current identity; Authz is None if it
    is not the break-glass role (RoleId + path bound via iam:GetRole). The
    skew compares the local clock, read after the STS call returns, with the
    response's Date header (None if absent)."""
    identity = session.client("sts", region_name=REGION).get_caller_identity()
    skew = _clock_skew(identity, datetime.now(timezone.utc))
    arn, user_id, account = identity["Arn"], identity["UserId"], identity["Account"]
    role_id, _, session_name = user_id.partition(":")
    vp = VerifiedPrincipal(arn=arn, role_id=role_id, account=account, session=session_name or None)
    result = authz.classify(vp, account, session.client("iam", region_name=REGION))
    if result is None or result.role_name not in authz.BREAK_GLASS_ROLE_NAMES:
        return arn, None, skew
    return arn, result, skew


def _generation(item):
    return item.get("generation") if item else None


def _as_int(value):
    try:
        return int(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None


def main(argv=None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args is None:
        return EXIT_USAGE
    profile = os.environ.get("AWS_PROFILE")
    if profile:
        try:
            check_profile(profile, allow_mfa_prompt=True, allow_sso=True)
        except ProfileConfigError as e:
            print(f"[break-glass] {e.message}")
            return EXIT_USAGE

    session = boto3.Session()
    try:
        arn, classified, skew = _classify_caller(session)
    except Exception as e:  # noqa: BLE001
        print(f"[break-glass] Could not verify the caller identity ({type(e).__name__}).")
        return EXIT_NOT_BREAK_GLASS
    if classified is None:
        print("[break-glass] Refused: run this under the fsi-breaker-break-glass role "
              "(see docs/RUNBOOK_GOVERNANCE_HOLD.md). Nothing was changed.")
        return EXIT_NOT_BREAK_GLASS

    # 0. The claim and both records carry this machine's time, which the
    # breaker compares with its own: refuse a clock that is off AWS time.
    if skew is None or skew < -MAX_CLOCK_SKEW_SECONDS or skew > MAX_CLOCK_SKEW_SECONDS + 1:
        measured = "unknown" if skew is None else f"{skew:.1f}"
        print(f"[break-glass] Refused: local clock differs from AWS by {measured} s; sync the clock "
              "(NTP) and re-run. Nothing was changed.")
        return EXIT_USAGE

    account = arn.split(":")[4]
    deny_policy_arn = f"arn:aws:iam::{account}:policy/{DENY_POLICY_NAME}"
    dynamodb = session.resource("dynamodb", region_name=REGION)
    table = dynamodb.Table(AUDIT_TABLE)
    state_table = dynamodb.Table(STATE_TABLE)
    iam = session.client("iam", region_name=REGION)
    release_id = str(uuid.uuid4())

    # 1. The governance-state item (consistent read). Detaching without
    # claiming it would be undone by the sweep within one cycle.
    try:
        before = governance_state.read(state_table)
    except Exception as e:  # noqa: BLE001
        print(f"[break-glass] Aborted: state read failed ({type(e).__name__}): fix the break-glass "
              "role's governance-state grant or the table first. Nothing was detached.")
        return EXIT_USAGE
    generation_before = _generation(before)

    # 2. Mandatory audit record BEFORE any effect.
    started = {
        "event_id": f"break-glass#{release_id}",
        "event_type": "BREAK_GLASS_RELEASE_STARTED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "released_by": arn,
        "incident_id": args.incident_id,
        "roles_targeted": list(AGENT_ROLES),
        "retention_expires": RETENTION_EXPIRES,
    }
    if generation_before is not None:
        started["hold_generation"] = generation_before
    try:
        table.put_item(Item=started, ConditionExpression="attribute_not_exists(event_id)")
    except Exception as e:  # noqa: BLE001
        print(f"[break-glass] Aborted: the pre-release audit record could not be written "
              f"({type(e).__name__}). Nothing was detached.")
        return EXIT_USAGE

    def completed_record(outcome, verified, still_held, unreadable, detach_failures, generation_after):
        item = {
            "event_id": f"break-glass#{release_id}#completed",
            "event_type": "BREAK_GLASS_RELEASE_COMPLETED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "released_by": arn,
            "incident_id": args.incident_id,
            "roles_verified_detached": verified,
            "roles_still_held": still_held,
            "roles_unreadable": unreadable,
            "detach_failures": detach_failures,
            "outcome": outcome,
            "retention_expires": RETENTION_EXPIRES,
        }
        if generation_after is not None:
            item["hold_generation_after"] = generation_after
        try:
            table.put_item(Item=item)
        except Exception as e:  # noqa: BLE001
            print(f"[break-glass] WARNING: the completion audit record could not be written "
                  f"({type(e).__name__}); record the outcome in the incident ticket.")

    # 3. Claim the state for the generation read in step 1. Its
    # break_glass_at also adopts any trip that started before it and never
    # claimed the state, so the sweep does not re-attach over this release.
    if before is not None:
        try:
            claim = governance_state.claim_break_glass(
                state_table, generation_before, before.get("hold_event_id"), args.incident_id, arn,
                datetime.now(timezone.utc).isoformat())
        except Exception as e:  # noqa: BLE001
            claim = None
            print(f"[break-glass] governance-state claim failed ({type(e).__name__}).")
        if claim != governance_state.CLAIMED:
            superseded = claim == governance_state.SUPERSEDED
            generation_after = None
            if superseded:
                try:
                    generation_after = _generation(governance_state.read(state_table))
                except Exception:  # noqa: BLE001 - best effort, the record still gets written
                    generation_after = None
            completed_record("SUPERSEDED" if superseded else "STATE_CLAIM_FAILED", [], [], [], {},
                             generation_after)
            if superseded:
                print("[break-glass] Aborted: a newer hold claimed the governance state before this "
                      "release. Nothing was detached; review the newer hold.")
                return EXIT_SUPERSEDED
            print("[break-glass] Aborted: the governance-state item could not be claimed. Nothing was "
                  "detached; fix the role's governance-state grant or the table first.")
            return EXIT_USAGE

    # 4. Detach, then re-read.
    detach_failures = {}
    for role in AGENT_ROLES:
        try:
            iam.detach_role_policy(RoleName=role, PolicyArn=deny_policy_arn)
        except Exception as e:  # noqa: BLE001
            response = getattr(e, "response", None)
            code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
            if code != "NoSuchEntity":  # not attached / role absent: verified below
                detach_failures[role] = type(e).__name__
    still_held, unreadable = [], []
    for role in AGENT_ROLES:
        try:
            attached = iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", [])
        except Exception:  # noqa: BLE001 - unreadable is reported, never assumed detached
            unreadable.append(role)
            continue
        if any(p.get("PolicyArn") == deny_policy_arn for p in attached):
            still_held.append(role)
    verified = [r for r in AGENT_ROLES if r not in still_held and r not in unreadable]

    # 5. Was a newer hold claimed meanwhile? Absent before and present now
    # counts as changed.
    try:
        after = governance_state.read(state_table)
        changed = _generation(after) != generation_before
    except Exception as e:  # noqa: BLE001
        after, changed = None, False
        print(f"[break-glass] WARNING: could not re-read the governance state ({type(e).__name__}); "
              "check it before closing the incident.")
    partial = len(verified) != len(AGENT_ROLES)
    outcome = "SUPERSEDED_AFTER" if changed else ("PARTIAL" if partial else "DETACHED")

    # Completion record with per-role results.
    completed_record(outcome, verified, still_held, unreadable, detach_failures,
                     _as_int(_generation(after)))

    if changed:
        print("[break-glass] A newer hold was claimed during this release; the sweep restores it. "
              "Do NOT re-run; open a second incident review.")
        return EXIT_SUPERSEDED_AFTER
    if partial:
        print(f"[break-glass] PARTIAL: verified detached {verified}; still held {still_held}; "
              f"unreadable {unreadable}.")
        return EXIT_PARTIAL
    print(f"[break-glass] All agent roles verified detached (incident {args.incident_id}). "
          "Second-person review of this incident is required within 24 h.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
