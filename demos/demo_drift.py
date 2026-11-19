#!/usr/bin/env python3
"""
Demo: Drift Monitoring — Show monitoring metrics from cached data.

Displays current drift metrics, threshold status, and hourly trends.
"""
import json
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

CACHED_DRIFT = os.path.join(PROJECT_ROOT, "cached_output", "drift_metrics.json")


def main():
    parser = argparse.ArgumentParser(description="Demo: Drift Monitoring")
    parser.add_argument("--local", action="store_true", default=True)
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  DRIFT MONITORING — Real-time Governance Metrics{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print()

    start_time = time.time()

    # Load metrics
    if os.path.exists(CACHED_DRIFT):
        with open(CACHED_DRIFT, encoding="utf-8") as f:
            data = json.load(f)
    else:
        print(f"  {RED}No drift metrics found at {CACHED_DRIFT}{RESET}")
        return

    metrics = data.get("metrics", {})
    thresholds = data.get("thresholds", {})
    status = data.get("status", "UNKNOWN")

    # Overall status
    status_color = GREEN if status == "HEALTHY" else RED
    print(f"  {BOLD}System Status:{RESET} {status_color}{status}{RESET}")
    print(f"  Window: {data.get('window_start', 'N/A')} → {data.get('window_end', 'N/A')}")

    # Key metrics vs thresholds
    print(f"\n  {BOLD}Key Metrics vs Thresholds:{RESET}")
    print(f"  {'Metric':<35} {'Value':<10} {'Threshold':<12} {'Status'}")
    print(f"  {'-'*70}")

    # Dispute rate
    dr = metrics.get("dispute_rate", 0)
    dr_thresh = thresholds.get("challenger_dispute_rate", 0.51)
    dr_color = GREEN if dr < dr_thresh else RED
    print(f"  {'Challenger dispute rate':<35} {dr_color}{dr:.0%}{RESET:<10} {'<'+str(int(dr_thresh*100))+'%':<12} {dr_color}{'OK' if dr < dr_thresh else 'BREACH'}{RESET}")

    # Guardrail rate
    gr = metrics.get("guardrail_intervention_rate", 0)
    gr_thresh = thresholds.get("guardrail_intervention_rate", 0.10)
    gr_color = GREEN if gr < gr_thresh else RED
    print(f"  {'Guardrail intervention rate':<35} {gr_color}{gr:.0%}{RESET:<10} {'<'+str(int(gr_thresh*100))+'%':<12} {gr_color}{'OK' if gr < gr_thresh else 'BREACH'}{RESET}")

    # Volume multiplier
    vm = metrics.get("detection_volume_multiplier", 1.0)
    vm_thresh = thresholds.get("detection_volume_multiplier", 3.0)
    vm_color = GREEN if vm < vm_thresh else RED
    print(f"  {'Detection volume multiplier':<35} {vm_color}{vm:.1f}x{RESET:<10} {'<'+str(vm_thresh)+'x':<12} {vm_color}{'OK' if vm < vm_thresh else 'BREACH'}{RESET}")

    # Pipeline stats
    print(f"\n  {BOLD}Pipeline Statistics (1-hour window):{RESET}")
    print(f"    Total detections:        {metrics.get('total_detections', 0)}")
    print(f"    Clusters flagged:        {metrics.get('total_clusters_flagged', 0)}")
    print(f"    SARs generated:          {metrics.get('total_sar_generated', 0)}")
    print(f"    Challenger disputes:     {YELLOW}{metrics.get('total_challenger_disputes', 0)}{RESET}")
    print(f"    Guardrail interventions: {metrics.get('total_guardrail_interventions', 0)}")
    print(f"    Filed SARs:              {GREEN}{metrics.get('file_sar_count', 0)}{RESET}")
    print(f"    Escalated to review:     {YELLOW}{metrics.get('needs_review_count', 0)}{RESET}")
    print(f"    Circuit breaker invocations: {metrics.get('circuit_breaker_invocations', 0)}")

    # Performance
    print(f"\n  {BOLD}Performance:{RESET}")
    print(f"    Avg GPU time:        {metrics.get('avg_gpu_time_seconds', 0):.1f}s")
    print(f"    Avg SAR latency:     {metrics.get('avg_sar_latency_ms', 0)}ms")
    print(f"    Avg challenger lat.: {metrics.get('avg_challenger_latency_ms', 0)}ms")

    # Hourly trend
    trend = data.get("hourly_trend", [])
    if trend:
        print(f"\n  {BOLD}Hourly Trend:{RESET}")
        print(f"  {'Time':<8} {'Detections':<12} {'Disputes':<10} {'Guardrail'}")
        for t in trend:
            print(f"  {t['hour']:<8} {t['detections']:<12} {t['disputes']:<10} {t['guardrail_hits']}")

    elapsed = time.time() - start_time
    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
