#!/usr/bin/env python3
"""
Drift Monitor — Real-time governance metric collection and alerting.

============================================================================
BLUEPRINT 4 — DRIFT CONTROL (observability)
============================================================================
The monitoring/visibility side of drift control. Reads the live governance
metrics (dispute rate, guardrail intervention rate, detection volume) and
evaluates them against the same thresholds the circuit breaker enforces, raising
CRITICAL/WARNING alerts. This is what an operator watches; the CloudWatch
alarms + circuit breaker are what act on the same signals automatically.
============================================================================

Collects metrics from the pipeline and checks against drift thresholds.
In --local mode, reads from cached_output/drift_metrics.json.
In live mode, queries CloudWatch metrics.
"""
import json
import os
import sys
import argparse
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

CACHED_DRIFT = os.path.join(PROJECT_ROOT, "cached_output", "drift_metrics.json")

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


def check_drift(metrics: dict, thresholds: dict) -> dict:
    """Check metrics against thresholds and return status."""
    alerts = []

    if metrics.get("dispute_rate", 0) > thresholds.get("challenger_dispute_rate", 0.51):
        alerts.append({
            "metric": "dispute_rate",
            "value": metrics["dispute_rate"],
            "threshold": thresholds["challenger_dispute_rate"],
            "severity": "CRITICAL",
        })

    if metrics.get("guardrail_intervention_rate", 0) > thresholds.get("guardrail_intervention_rate", 0.10):
        alerts.append({
            "metric": "guardrail_intervention_rate",
            "value": metrics["guardrail_intervention_rate"],
            "threshold": thresholds["guardrail_intervention_rate"],
            "severity": "CRITICAL",
        })

    if metrics.get("detection_volume_multiplier", 1.0) > thresholds.get("detection_volume_multiplier", 3.0):
        alerts.append({
            "metric": "detection_volume_multiplier",
            "value": metrics["detection_volume_multiplier"],
            "threshold": thresholds["detection_volume_multiplier"],
            "severity": "WARNING",
        })

    status = "HEALTHY" if not alerts else "ALERT"
    return {"status": status, "alerts": alerts}


def main():
    parser = argparse.ArgumentParser(description="Drift Monitor")
    parser.add_argument("--local", action="store_true", default=True)
    args = parser.parse_args()

    if args.local and os.path.exists(CACHED_DRIFT):
        with open(CACHED_DRIFT, encoding="utf-8") as f:
            data = json.load(f)
        metrics = data.get("metrics", {})
        thresholds = data.get("thresholds", {})
    else:
        print(f"{YELLOW}No metrics available. Run pipeline first.{RESET}")
        return

    result = check_drift(metrics, thresholds)

    if result["status"] == "HEALTHY":
        print(f"{GREEN}[DRIFT] All metrics within thresholds{RESET}")
    else:
        for alert in result["alerts"]:
            print(f"{RED}[ALERT] {alert['metric']}: {alert['value']} > {alert['threshold']} ({alert['severity']}){RESET}")


if __name__ == "__main__":
    main()
