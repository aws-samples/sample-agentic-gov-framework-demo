#!/usr/bin/env python3
"""
Demo: PAN Rejection — Ingress filter catches PAN before GPU processing.

Feeds PAN-laden transactions and shows rejection at ingress.
Tests all 6 evasion variants with detailed output showing the technique.
"""
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from lambdas.detection_agent.pan_filter import contains_full_pan, filter_transactions

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# Test vectors — all 6 evasion variants (Luhn-valid test PAN: 4532015112830366)
EVASION_VARIANTS = [
    {
        "name": "Plain 16-digit",
        "pan": "4532015112830366",
        "display": "4532015112830366",
        "technique": "Raw card number with no obfuscation",
    },
    {
        "name": "Dash-separated",
        "pan": "4532-0151-1283-0366",
        "display": "4532-0151-1283-0366",
        "technique": "Dashes inserted between 4-digit groups",
    },
    {
        "name": "Space-separated",
        "pan": "4532 0151 1283 0366",
        "display": "4532 0151 1283 0366",
        "technique": "Spaces inserted between 4-digit groups",
    },
    {
        "name": "Zero-width chars",
        "pan": "4532\u200b0151\u200b1283\u200b0366",
        "display": "4532[ZWS]0151[ZWS]1283[ZWS]0366",
        "technique": "Unicode zero-width space (U+200B) between groups — invisible to humans",
    },
    {
        "name": "Mixed separators",
        "pan": "4532-0151 1283-0366",
        "display": "4532-0151 1283-0366",
        "technique": "Mix of dashes and spaces to evade fixed-format regex",
    },
    {
        "name": "Unicode full-width",
        "pan": "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16",
        "display": "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16",
        "technique": "Full-width Unicode digits (U+FF10..U+FF19) — renders as wide characters",
    },
]

# Legitimate masked PANs that should NOT be caught
SAFE_VARIANTS = [
    ("Masked with *", "4532-01**-****-0366"),
    ("Masked with x", "4532xxxxxxxx0366"),
    ("BIN + last 4", "453201****0366"),
]


def main():
    parser = argparse.ArgumentParser(description="Demo: PAN Rejection at Ingress")
    parser.add_argument("--evasion", action="store_true", help="Test all 6 evasion variants")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  PAN INGRESS FILTER — PCI-DSS v4.0 Boundary{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Layer 1: Catches PAN BEFORE graph processing")
    print(f"  Test PAN: 4532-0151-1283-0366 (Luhn-valid)")
    print()

    start_time = time.time()
    all_pass = True
    blocked_count = 0

    # Test evasion variants (should be CAUGHT)
    print(f"  {BOLD}Evasion variants — all 6 must be BLOCKED:{RESET}")
    print(f"  {DIM}{'─'*56}{RESET}")

    for i, variant in enumerate(EVASION_VARIANTS, 1):
        txn_text = f'{{"txn_id": "test", "card": "{variant["pan"]}"}}'
        caught = contains_full_pan(txn_text)

        if caught:
            status = f"{RED}BLOCKED{RESET}"
            blocked_count += 1
        else:
            status = f"{YELLOW}MISSED{RESET} "
            all_pass = False

        print(f"\n    {BOLD}#{i} {variant['name']}{RESET}")
        print(f"       Input:     {CYAN}{variant['display']}{RESET}")
        print(f"       Technique: {DIM}{variant['technique']}{RESET}")
        print(f"       Result:    {status}")

    print(f"\n  {DIM}{'─'*56}{RESET}")
    print(f"  {BOLD}Blocked: {RED}{blocked_count}/6{RESET} evasion variants")

    # Test safe variants (should NOT be caught)
    print(f"\n  {BOLD}Safe variants — masked PANs must be ALLOWED:{RESET}")
    print(f"  {DIM}{'─'*56}{RESET}")
    for name, masked in SAFE_VARIANTS:
        txn_text = f'{{"txn_id": "test", "card": "{masked}"}}'
        caught = contains_full_pan(txn_text)
        if not caught:
            print(f"    {GREEN}ALLOWED{RESET} — {name}: {masked}")
        else:
            print(f"    {RED}FALSE POSITIVE{RESET} — {name}: {masked}")
            all_pass = False

    # Test batch filtering — all 6 evasion variants in a single batch
    print(f"\n  {BOLD}Batch filter test (all 6 variants + 2 clean):{RESET}")
    print(f"  {DIM}{'─'*56}{RESET}")
    test_batch = [
        {"txn_id": "CLEAN-001", "sender_id": "acc1", "receiver_id": "acc2", "amount": 500},
        {"txn_id": "PAN-PLAIN", "sender_id": "acc3", "receiver_id": "acc4", "amount": 9000,
         "card_number": "4532015112830366"},
        {"txn_id": "PAN-DASH", "sender_id": "acc5", "receiver_id": "acc6", "amount": 7500,
         "card_number": "4532-0151-1283-0366"},
        {"txn_id": "PAN-SPACE", "sender_id": "acc7", "receiver_id": "acc8", "amount": 6200,
         "card_number": "4532 0151 1283 0366"},
        {"txn_id": "PAN-ZWS", "sender_id": "acc9", "receiver_id": "acc10", "amount": 8100,
         "card_number": "4532\u200b0151\u200b1283\u200b0366"},
        {"txn_id": "PAN-MIXED", "sender_id": "acc11", "receiver_id": "acc12", "amount": 5400,
         "card_number": "4532-0151 1283-0366"},
        {"txn_id": "PAN-UNICODE", "sender_id": "acc13", "receiver_id": "acc14", "amount": 11000,
         "card_number": "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"},
        {"txn_id": "CLEAN-002", "sender_id": "acc15", "receiver_id": "acc16", "amount": 300},
    ]
    clean, rejected, details = filter_transactions(test_batch)
    print(f"    Input:    {len(test_batch)} transactions")
    print(f"    Passed:   {GREEN}{len(clean)}{RESET} (forwarded to detection agent)")
    print(f"    Rejected: {RED}{rejected}{RESET} (PAN detected, blocked at boundary)")
    # Local filter details carry index/rule/reason plus a keyed txn_ref; the
    # raw txn_id is never part of them (it may itself carry a PAN), and the
    # txn_ref is not printed.
    for d in details:
        print(f"      {RED}x{RESET} index={d['index']} rule={d['rule']}: {d['reason']}")

    elapsed = time.time() - start_time

    # Summary
    print(f"\n  {'='*60}")
    if all_pass:
        print(f"  {GREEN}{BOLD}ALL 6 EVASION VARIANTS CAUGHT — PCI-DSS BOUNDARY HOLDS{RESET}")
        print(f"  {DIM}No unmasked PAN can reach the agent context (section 3.4){RESET}")
    else:
        print(f"  {RED}{BOLD}SOME VARIANTS MISSED — BOUNDARY COMPROMISED{RESET}")

    print(f"  Completed in {elapsed:.4f}s")
    print(f"{'='*60}\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
