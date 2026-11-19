#!/usr/bin/env python3
"""
Generate Cached Output — Run once on g4dn instance to populate cached_output/ directory.

Prerequisites:
- GPU mode: NVIDIA RAPIDS (cudf, cugraph) installed
- Bedrock mode: AWS credentials with bedrock:InvokeModel permission
- Transaction data: data/transactions_small.jsonl must exist

Usage:
    python scripts/generate_cached_output.py --mode cpu    # CPU fallback
    python scripts/generate_cached_output.py --mode gpu    # Full GPU run
    python scripts/generate_cached_output.py --mode local  # Just verify cached files exist
"""
import json
import os
import sys
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

CACHED_DIR = os.path.join(PROJECT_ROOT, "cached_output")


def main():
    parser = argparse.ArgumentParser(description="Generate cached outputs")
    parser.add_argument("--mode", choices=["gpu", "cpu", "local"], default="local")
    args = parser.parse_args()

    os.makedirs(CACHED_DIR, exist_ok=True)

    if args.mode == "local":
        # Just verify cached files exist
        files = ["detection_result.json", "compliance_result.json", "drift_metrics.json"]
        for f in files:
            path = os.path.join(CACHED_DIR, f)
            if os.path.exists(path):
                print(f"  OK: {f}")
            else:
                print(f"  MISSING: {f}")
        return

    # Generate detection output
    print("Generating detection output...")
    # CLI-only file entry point: the request-surface handler() no longer
    # accepts a file name.
    from lambdas.detection_agent.handler import run_detection_from_file
    txn_file = os.path.join(PROJECT_ROOT, "data", "transactions_small.jsonl")
    if not os.path.exists(txn_file):
        print(f"Generating transaction data first...")
        from data.synthetic_data import stream_transactions
        stream_transactions(num_normal=500, inject_fraud=True, output_file=txn_file)

    detection_result = run_detection_from_file(txn_file, args.mode)
    with open(os.path.join(CACHED_DIR, "detection_result.json"), "w", encoding="utf-8") as f:
        json.dump(detection_result, f, indent=2, default=str)
    print(f"  Saved detection_result.json ({len(detection_result.get('flagged_clusters', []))} clusters)")

    # Compliance would need live Bedrock — skip if not configured
    print("\nNote: compliance_result.json and drift_metrics.json are pre-staged.")
    print("Run with live Bedrock access to regenerate compliance results.")


if __name__ == "__main__":
    main()
