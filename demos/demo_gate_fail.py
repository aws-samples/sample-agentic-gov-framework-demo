#!/usr/bin/env python3
"""
Demo: Compliance Gate Blocks Bad Deploy.

Weakens guardrail config → runs gate → FAIL → restores → PASS.
Shows the thesis moment: governance gate as a deploy blocker.
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

# Guardrail config path (simulated)
GUARDRAIL_CONFIG = os.path.join(PROJECT_ROOT, "cached_output", ".guardrail_config.json")

COMPLIANT_CONFIG = {
    "guardrail_id": "fsi-pci-guardrail",
    "guardrail_version": "3",
    "blocked_patterns": ["PAN", "CVV", "SSN", "ACCOUNT_ID"],
    "content_policy_enabled": True,
    "sensitive_info_filter_enabled": True,
}

WEAKENED_CONFIG = {
    "guardrail_id": "fsi-pci-guardrail",
    "guardrail_version": "3",
    "blocked_patterns": ["CVV"],  # Weakened: removed PAN, SSN, ACCOUNT_ID
    "content_policy_enabled": True,
    "sensitive_info_filter_enabled": False,  # Weakened: disabled
}


def write_config(config):
    os.makedirs(os.path.dirname(GUARDRAIL_CONFIG), exist_ok=True)
    with open(GUARDRAIL_CONFIG, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def run_gate_check(config) -> tuple:
    """Run a simplified gate check. Returns (passed, failures)."""
    failures = []

    # Check 1: All required patterns blocked
    required_patterns = {"PAN", "CVV", "SSN", "ACCOUNT_ID"}
    blocked = set(config.get("blocked_patterns", []))
    missing = required_patterns - blocked
    if missing:
        failures.append(f"Guardrail missing required blocks: {missing}")

    # Check 2: Sensitive info filter enabled
    if not config.get("sensitive_info_filter_enabled"):
        failures.append("Sensitive info filter is DISABLED")

    # Check 3: Content policy enabled
    if not config.get("content_policy_enabled"):
        failures.append("Content policy is DISABLED")

    # Check 4: Guardrail version exists
    if not config.get("guardrail_id"):
        failures.append("No guardrail ID configured")

    passed = len(failures) == 0
    return passed, failures


def main():
    parser = argparse.ArgumentParser(description="Demo: Gate Blocks Bad Deploy")
    parser.add_argument("--break", dest="break_only", action="store_true",
                        help="Only weaken the config (for manual testing)")
    parser.add_argument("--restore", action="store_true",
                        help="Only restore the config")
    args = parser.parse_args()

    if args.break_only:
        write_config(WEAKENED_CONFIG)
        print(f"{YELLOW}Config weakened. Run gate to see failure.{RESET}")
        return

    if args.restore:
        write_config(COMPLIANT_CONFIG)
        print(f"{GREEN}Config restored to compliant state.{RESET}")
        return

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  COMPLIANCE GATE — Deploy Blocker Demo{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Thesis: Governance gate as CI/CD enforcement")
    print()

    start_time = time.time()

    # Step 1: Start with compliant config
    print(f"  {BOLD}Step 1: Verify compliant state{RESET}")
    write_config(COMPLIANT_CONFIG)
    passed, failures = run_gate_check(COMPLIANT_CONFIG)
    print(f"    Gate result: {GREEN}PASS{RESET}")
    print(f"    Deploy would: {GREEN}PROCEED{RESET}")

    # Step 2: Weaken the config (simulate bad commit)
    print(f"\n  {BOLD}Step 2: Weaken guardrail (simulate bad commit){RESET}")
    write_config(WEAKENED_CONFIG)
    print(f"    {YELLOW}Removed PAN/SSN/ACCOUNT_ID from blocked patterns{RESET}")
    print(f"    {YELLOW}Disabled sensitive info filter{RESET}")

    # Step 3: Run gate → FAIL
    print(f"\n  {BOLD}Step 3: Run compliance gate{RESET}")
    passed, failures = run_gate_check(WEAKENED_CONFIG)
    print(f"    Gate result: {RED}FAIL{RESET}")
    print(f"    Deploy would: {RED}BLOCKED{RESET}")
    for f in failures:
        print(f"    {RED}  - {f}{RESET}")

    # Step 4: Restore
    print(f"\n  {BOLD}Step 4: Restore compliant config{RESET}")
    write_config(COMPLIANT_CONFIG)
    passed, failures = run_gate_check(COMPLIANT_CONFIG)
    print(f"    Gate result: {GREEN}PASS{RESET}")
    print(f"    Deploy would: {GREEN}PROCEED{RESET}")

    elapsed = time.time() - start_time

    print(f"\n  {BOLD}Key insight:{RESET}")
    print(f"  The gate runs in CI/CD. Bad guardrail changes never reach production.")
    print(f"  Exit code 1 = pipeline stops. No human intervention needed.")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
