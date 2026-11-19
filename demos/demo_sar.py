#!/usr/bin/env python3
"""
Demo: SAR Generation — Compliance agent generates SAR narrative + guardrail blocks PII.

Shows the SAR narrative, guardrail enforcement, and model metadata.
--local uses cached compliance result.
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
    parser = argparse.ArgumentParser(description="Demo: SAR Generation")
    parser.add_argument("--local", action=argparse.BooleanOptionalAction, default=True,
                        help="Use cached output (default); --no-local runs live")
    parser.add_argument("--detection-file", type=str, default=None)
    return parser


def run_live(detection_file=None):
    """Live: detection (unless a file is given) then compliance, both via the
    deployed AgentCore runtimes under the ambient AWS credentials (e.g.
    AWS_PROFILE). The compliance runtime calls Bedrock and writes the audited
    decision; it assesses only a recorded detection (provenance check)."""
    import boto3
    from app.invoke_live import run_compliance_live, run_detection_live
    session = boto3.Session()
    if detection_file:
        with open(detection_file, encoding="utf-8") as f:
            detection_output = json.load(f)
    else:
        detection_output = run_detection_live("cpu", session=session)
        if "error" in detection_output:
            return detection_output
    return run_compliance_live(detection_output, session=session)


def main(argv=None):
    args = build_parser().parse_args(argv)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  COMPLIANCE AGENT — SAR Narrative Generation{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Bedrock Converse + Guardrail enforcement")
    if not args.local:
        print(f"  Mode: {CYAN}LIVE (AgentCore Runtime){RESET}")
    print()

    start_time = time.time()

    if args.local:
        result = handler({"mode": "local"})
    else:
        result = run_live(args.detection_file)
    elapsed = time.time() - start_time

    if "error" in result:
        print(f"  {RED}Compliance run failed: {result['error']}{RESET}")
        sys.exit(1)

    # Display results
    print(f"  {BOLD}Compliance ID:{RESET} {result['compliance_id']}")
    print(f"  {BOLD}Detection ID:{RESET} {result['detection_id']}")
    print(f"  {BOLD}Clusters assessed:{RESET} {len(result['clusters_assessed'])}")

    for i, cluster in enumerate(result.get("clusters_assessed", []), 1):
        decision = cluster["decision"]
        color = GREEN if decision == "FILE_SAR" else YELLOW

        print(f"\n  {BOLD}--- Cluster {i} ---{RESET}")
        print(f"  {BOLD}Decision:{RESET} {color}{decision}{RESET}")

        # SAR narrative (truncated for display)
        narrative = cluster.get("sar_narrative", "")
        if len(narrative) > 200:
            narrative_display = narrative[:200] + "..."
        else:
            narrative_display = narrative
        print(f"\n  {BOLD}SAR Narrative:{RESET}")
        print(f"  {CYAN}{narrative_display}{RESET}")

        # Guardrail status
        if cluster.get("guardrail_triggered"):
            print(f"\n  {RED}GUARDRAIL TRIGGERED — PII blocked in output{RESET}")
        else:
            print(f"\n  {GREEN}Guardrail: PASS (no PII in output){RESET}")

        # Model metadata
        metadata = cluster.get("model_metadata", {})
        sar_meta = metadata.get("sar_call", {})
        print(f"\n  {BOLD}Model metadata (SAR call):{RESET}")
        print(f"    Model: {sar_meta.get('model_id', 'N/A')}")
        print(f"    Latency: {sar_meta.get('latency_ms', 0)}ms")
        print(f"    Guardrail action: {sar_meta.get('guardrail_action', 'N/A')}")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
