#!/usr/bin/env python3
"""
Demo: Challenger Divergence — Challenger DISPUTEs → NEEDS_REVIEW.

Runs compliance agent on a borderline cluster where the challenger
provides legitimate business explanations and disputes the detection.
"""
import json
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.compliance_agent.handler import handler

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def build_parser():
    parser = argparse.ArgumentParser(description="Demo: Challenger Divergence")
    parser.add_argument("--local", action=argparse.BooleanOptionalAction, default=True,
                        help="Use cached output (default); --no-local runs live")
    return parser


def run_live():
    """Live: detection then compliance (SAR + challenger on Bedrock), both
    via the deployed AgentCore runtimes under the ambient AWS credentials
    (e.g. AWS_PROFILE)."""
    import boto3
    from app.invoke_live import run_compliance_live, run_detection_live
    session = boto3.Session()
    detection_output = run_detection_live("cpu", session=session)
    if "error" in detection_output:
        return detection_output
    return run_compliance_live(detection_output, session=session)


def main(argv=None):
    args = build_parser().parse_args(argv)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  CHALLENGER DIVERGENCE — SR 11-7 Effective Challenge{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  When challenger DISPUTEs → decision escalates to NEEDS_REVIEW")
    if not args.local:
        print(f"  Mode: {CYAN}LIVE (AgentCore Runtime){RESET}")
    print()

    start_time = time.time()
    result = handler({"mode": "local"}) if args.local else run_live()
    elapsed = time.time() - start_time

    if "error" in result:
        print(f"  {RED}Compliance run failed: {result['error']}{RESET}")
        sys.exit(1)

    # Find the DISPUTE cluster
    dispute_clusters = [
        c for c in result.get("clusters_assessed", [])
        if c.get("challenger_opinion") == "DISPUTE"
    ]
    agree_clusters = [
        c for c in result.get("clusters_assessed", [])
        if c.get("challenger_opinion") == "AGREE"
    ]

    # Show AGREE case first (for contrast)
    if agree_clusters:
        cluster = agree_clusters[0]
        print(f"  {BOLD}Cluster (AGREE):{RESET}")
        print(f"  Challenger opinion: {GREEN}AGREE{RESET}")
        print(f"  Decision: {GREEN}{cluster['decision']}{RESET}")
        print(f"  Rationale: {cluster['challenger_rationale'][:100]}...")
        print()

    # Show DISPUTE case
    if dispute_clusters:
        cluster = dispute_clusters[0]
        print(f"  {BOLD}Cluster (DISPUTE):{RESET}")
        print(f"  Challenger opinion: {YELLOW}DISPUTE{RESET}")
        print(f"  Decision: {YELLOW}{cluster['decision']}{RESET}")
        print(f"\n  {BOLD}Challenger rationale:{RESET}")
        print(f"  {CYAN}{cluster['challenger_rationale']}{RESET}")

        print(f"\n  {BOLD}Why this matters (SR 11-7):{RESET}")
        print(f"  - SAR agent and Challenger use {BOLD}different methodologies{RESET}")
        print(f"  - When they disagree, the system fails SAFE to human review")
        print(f"  - No auto-filing when legitimate explanations exist")

        # Show prompt independence
        metadata = cluster.get("model_metadata", {})
        sar_fp = metadata.get("sar_call", {}).get("prompt_fingerprint", "")
        chal_fp = metadata.get("challenger_call", {}).get("prompt_fingerprint", "")
        if sar_fp and chal_fp and sar_fp != chal_fp:
            print(f"\n  {GREEN}Prompt independence verified:{RESET}")
            print(f"    SAR fingerprint:        {sar_fp}")
            print(f"    Challenger fingerprint: {chal_fp}")
    else:
        source = "cached output" if args.local else "this live run"
        print(f"  {YELLOW}No DISPUTE cluster found in {source}{RESET}")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
