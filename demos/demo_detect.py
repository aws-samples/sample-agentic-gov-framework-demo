#!/usr/bin/env python3
"""
Demo: Detection Agent — GPU fraud ring detection.

Shows GPU timing + clusters found. --local uses cached output.
"""
import json
import os
import sys
import time
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.detection_agent.handler import handler, run_detection_from_file

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def build_parser():
    parser = argparse.ArgumentParser(description="Demo: Detection Agent")
    parser.add_argument("--local", action=argparse.BooleanOptionalAction, default=True,
                        help="Use cached output (default); --no-local runs live")
    parser.add_argument("--mode", choices=["gpu", "cpu", "local"], default="local")
    parser.add_argument("--file", type=str, default=None)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    mode = "local" if args.local else args.mode
    live = mode != "local" and not args.file

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  DETECTION AGENT — Fraud Ring Detection (cuGraph){RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    if live:
        print(f"  Mode: {CYAN}LIVE ({mode.upper()}, AgentCore Runtime){RESET}")
    else:
        print(f"  Mode: {CYAN}{mode.upper()}{RESET}")
    print()

    start_time = time.time()

    # A file is named only through the CLI entry point; handler() takes an
    # allowlisted dataset_id (default "sample-small").
    if args.file and mode != "local":
        result = run_detection_from_file(args.file, mode)
    elif live:
        # Invoke the deployed DetectionAgent runtime (writes the detection
        # audit record) under the ambient AWS credentials, e.g. AWS_PROFILE.
        import boto3
        from app.invoke_live import run_detection_live
        result = run_detection_live(mode, session=boto3.Session())
    else:
        result = handler({"mode": mode})

    elapsed = time.time() - start_time

    if "error" in result:
        print(f"  {RED}Detection failed: {result['error']}{RESET}")
        sys.exit(1)

    # Display results
    print(f"\n  {BOLD}Detection ID:{RESET} {result['detection_id']}")
    print(f"  {BOLD}Transactions processed:{RESET} {result['transaction_count']:,}")
    print(f"  {BOLD}GPU time:{RESET} {result['gpu_time_seconds']:.2f}s")
    print(f"  {BOLD}Clusters flagged:{RESET} {len(result['flagged_clusters'])}")

    if result.get("pan_rejected_count", 0) > 0:
        print(f"  {RED}PAN rejections:{RESET} {result['pan_rejected_count']}")

    # Show clusters
    for i, cluster in enumerate(result.get("flagged_clusters", []), 1):
        typology = cluster["typology"]
        color = RED if typology == "circular_structuring" else YELLOW
        print(f"\n  {color}Cluster {i}: {typology}{RESET}")
        print(f"    Accounts: {cluster['account_count']}")
        print(f"    Amount: ${cluster['total_amount_usd']:,.2f}")
        print(f"    Time span: {cluster['time_span_seconds']}s")
        print(f"    Categories: {', '.join(cluster['merchant_categories'])}")
        cf = cluster.get("confidence_factors", {})
        print(f"    Circular ratio: {cf.get('circular_ratio', 0):.0%}")
        print(f"    Fan-out/in max: {cf.get('fan_out_max', 0)}/{cf.get('fan_in_max', 0)}")

    # PageRank top nodes
    if result.get("pagerank_top_10"):
        print(f"\n  {BOLD}PageRank Top 5:{RESET}")
        for pr in result["pagerank_top_10"][:5]:
            print(f"    {pr['node']}: {pr['score']:.6f}")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
