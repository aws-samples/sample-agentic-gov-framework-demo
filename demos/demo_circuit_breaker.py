#!/usr/bin/env python3
"""
Demo: Circuit Breaker — Trigger circuit breaker → agents disabled → audit logged.

Simulates a drift threshold breach that triggers automated agent disablement.
"""
import json
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from circuit_breaker.handler import handler as circuit_breaker_handler, re_enable

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def main():
    parser = argparse.ArgumentParser(description="Demo: Circuit Breaker")
    parser.add_argument("--local", action="store_true", default=True)
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  CIRCUIT BREAKER — Automated Agent Disable{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Drift thresholds breach → agents revoked → 503 hold")
    print()

    start_time = time.time()

    # Step 1: Check healthy metrics
    print(f"  {BOLD}Step 1: Check healthy metrics (within thresholds){RESET}")
    healthy_metrics = {
        "dispute_rate": 0.25,
        "guardrail_intervention_rate": 0.03,
        "detection_volume_multiplier": 1.5,
    }
    result = circuit_breaker_handler({
        "action": "check",
        "mode": "local",
        "metrics": healthy_metrics,
    })
    print(f"    Status: {GREEN}{result['status']}{RESET}")
    print(f"    Dispute rate: {healthy_metrics['dispute_rate']:.0%} (threshold: 51%)")
    print(f"    Guardrail rate: {healthy_metrics['guardrail_intervention_rate']:.0%} (threshold: 10%)")
    print(f"    Volume multiplier: {healthy_metrics['detection_volume_multiplier']:.1f}x (threshold: 3.0x)")

    # Step 2: Breach threshold
    print(f"\n  {BOLD}Step 2: Simulate threshold breach{RESET}")
    print(f"    {YELLOW}Dispute rate spikes to 52% (exceeds 51% threshold){RESET}")
    breach_metrics = {
        "dispute_rate": 0.52,
        "guardrail_intervention_rate": 0.03,
        "detection_volume_multiplier": 1.5,
    }
    result = circuit_breaker_handler({
        "action": "check",
        "mode": "local",
        "metrics": breach_metrics,
    })

    # Step 3: Show circuit breaker activated
    print(f"\n  {BOLD}Step 3: Circuit breaker fires{RESET}")
    print(f"    Status: {RED}{result['status']}{RESET}")
    print(f"    HTTP: {RED}{result.get('http_status', 'N/A')}{RESET}")
    print(f"    Reason: {result.get('trigger_reason', 'N/A')}")
    print(f"\n    {RED}Roles revoked:{RESET}")
    for role in result.get("roles_revoked", []):
        print(f"      {RED}X{RESET} {role}")
    print(f"\n    {RED}All subsequent requests return 503 Governance Hold{RESET}")

    # Step 4: Check status (confirms hold)
    print(f"\n  {BOLD}Step 4: Verify governance hold state{RESET}")
    status = circuit_breaker_handler({"action": "status", "mode": "local"})
    print(f"    Current state: {RED}{status.get('status', 'UNKNOWN')}{RESET}")

    # Step 5: Re-enable (manual action)
    print(f"\n  {BOLD}Step 5: Manual re-enable (requires human action){RESET}")
    re_result = re_enable(mode="local")
    print(f"    Status: {GREEN}{re_result['status']}{RESET}")
    print(f"    {re_result['message']}")

    elapsed = time.time() - start_time

    print(f"\n  {BOLD}Key insight:{RESET}")
    print(f"  Circuit breaker is AUTOMATED (no human needed to trigger).")
    print(f"  Re-enable is MANUAL (requires human with MFA).")
    print(f"  This is the asymmetric safety guarantee.")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
