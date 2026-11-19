#!/usr/bin/env python3
"""
Pin the governance signing-key ARNs.

Reads the RegistrySigningKeyArn and GateSigningKeyArn outputs of the
FsiComplianceAgents stack and the caller's account (read-only calls:
cloudformation:DescribeStacks, sts:GetCallerIdentity) and writes
data/signing_key_pins.json atomically, keeping any max_signature_age_seconds
already in the file. Commit the file: signing and every verifier use these
pinned ARNs and never resolve the key aliases.

Usage:
    AWS_PROFILE=<deployer profile> python scripts/pin_signing_keys.py
    AWS_PROFILE=<deployer profile> python scripts/pin_signing_keys.py --check   # exit 1 on a difference
"""
import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from governance_common import signing  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENTS_STACK = "FsiComplianceAgents"
OUTPUTS = {signing.PURPOSE_REGISTRY: "RegistrySigningKeyArn", signing.PURPOSE_GATE: "GateSigningKeyArn"}


def _session():
    """The deployer's own AWS session (AWS_PROFILE); a test seam."""
    import boto3  # deferred
    return boto3.Session()


def build_pins(session, existing_ages) -> dict:
    account = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
    stacks = session.client("cloudformation", region_name=REGION).describe_stacks(
        StackName=AGENTS_STACK)["Stacks"]
    outputs = {o.get("OutputKey"): o.get("OutputValue") for stack in stacks[:1]
               for o in stack.get("Outputs", [])}
    keys = {}
    for purpose, output in OUTPUTS.items():
        if not outputs.get(output):
            raise SystemExit(f"✗ {AGENTS_STACK} has no {output} output; deploy the stack first")
        keys[purpose] = outputs[output]
    pins = {"format": signing.PINS_FORMAT, "account": account, "region": REGION, "keys": keys,
            "max_signature_age_seconds": dict(existing_ages)}
    signing.parse_key_pins(pins)  # same validation every verifier applies
    return pins


def _existing(path):
    try:
        return signing.load_key_pins(path)
    except signing.SignatureInvalidError:
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Pin the signing-key ARNs from the deployed stack")
    parser.add_argument("--pins", default=signing.DEFAULT_PINS_PATH)
    parser.add_argument("--check", action="store_true", help="Exit 1 if the file differs; write nothing")
    args = parser.parse_args(argv)

    current = _existing(args.pins)
    try:
        pins = build_pins(_session(), dict(current.max_ages) if current else {})
    except signing.SignatureInvalidError as exc:
        print(f"✗ {exc}")
        return 1
    if args.check:
        same = current is not None and signing.parse_key_pins(pins) == current
        print("✓ signing key pins match the stack" if same else "✗ signing key pins differ from the stack")
        return 0 if same else 1
    tmp = args.pins + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(pins, sort_keys=True) + "\n")
    os.replace(tmp, args.pins)
    print(f"✓ wrote {os.path.relpath(args.pins, PROJECT_ROOT)}; commit it before signing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
