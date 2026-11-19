#!/usr/bin/env python3
"""
Demo: Model Assurance (D5.2) — only approved models may run.

Uses the REAL approved-models registry (data/approved_models.json) and the
REAL validation logic (model_assurance.validate_model). Shows:
  1. The configured model → APPROVED (deploy would proceed)
  2. A swapped-in unapproved model → BLOCKED (deploy stopped)
  3. A new *version* of an approved model → BLOCKED (version pinning)
  4. Restore to the approved model → PASS

This mirrors the demo-gate-fail beat: good → break → blocked → restore.
"""
import os
import sys
import time
import argparse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from model_assurance import load_verified_registry, validate_model, approved_model_ids
from governance_common.signing import SignatureError

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# The model the compliance agent is configured to use by default.
CONFIGURED_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
# A model that is NOT on the registry at all.
UNAPPROVED_MODEL = "us.meta.llama3-3-70b-instruct-v1:0"
# Same family as the approved model, but a different (unreviewed) version.
WRONG_VERSION_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v2:0"


def _print_check(label: str, model_id: str, ok: bool, reason: str):
    verdict = f"{GREEN}APPROVED{RESET}" if ok else f"{RED}BLOCKED{RESET}"
    deploy = f"{GREEN}PROCEED{RESET}" if ok else f"{RED}BLOCKED{RESET}"
    print(f"    {BOLD}{label}{RESET}")
    print(f"      Model:  {CYAN}{model_id}{RESET}")
    print(f"      Result: {verdict} — deploy would {deploy}")
    print(f"      Reason: {reason}")


def main():
    parser = argparse.ArgumentParser(description="Demo: Model Assurance (D5.2)")
    parser.add_argument("--local", action="store_true", default=True)
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  MODEL ASSURANCE (D5.2) — Approved Models Only{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Only models on the org registry (exact, version-pinned) may run.")
    print()

    start_time = time.time()

    # Load the real registry — only if its signature verifies.
    try:
        registry = load_verified_registry()
    except SignatureError:
        print(f"  {RED}registry signature could not be verified "
              f"(set ALLOW_LOCAL_DEV_SIGNING=true for local demos){RESET}")
        sys.exit(1)
    approved = approved_model_ids(registry)
    print(f"  {BOLD}Approved-models registry{RESET} (version "
          f"{CYAN}{registry.get('registry_version', 'unknown')}{RESET}):")
    for mid in approved:
        print(f"    {GREEN}approved{RESET} {mid}")
    print()

    # Step 1: Configured model → approved
    print(f"  {BOLD}Step 1: Validate the configured model{RESET}")
    ok, reason = validate_model(CONFIGURED_MODEL, registry)
    _print_check("Configured model", CONFIGURED_MODEL, ok, reason)

    # Step 2: Swap in an unapproved model → blocked
    print(f"\n  {BOLD}Step 2: Swap in an unapproved model (simulate bad commit){RESET}")
    print(f"    {YELLOW}Someone points the agent at a model that was never reviewed{RESET}")
    ok, reason = validate_model(UNAPPROVED_MODEL, registry)
    _print_check("Unapproved model", UNAPPROVED_MODEL, ok, reason)

    # Step 3: Wrong version of an approved model → blocked (version pinning)
    print(f"\n  {BOLD}Step 3: Try a NEW VERSION of the approved model{RESET}")
    print(f"    {YELLOW}Same family, bumped version — not yet reviewed{RESET}")
    ok, reason = validate_model(WRONG_VERSION_MODEL, registry)
    _print_check("Unreviewed version", WRONG_VERSION_MODEL, ok, reason)

    # Step 4: Restore → pass
    print(f"\n  {BOLD}Step 4: Restore the approved model{RESET}")
    ok, reason = validate_model(CONFIGURED_MODEL, registry)
    _print_check("Configured model", CONFIGURED_MODEL, ok, reason)

    elapsed = time.time() - start_time

    print(f"\n  {BOLD}Key insight:{RESET}")
    print(f"  Matching is EXACT and version-pinned. A new model — or even a new")
    print(f"  version of an approved one — is blocked until the Model Risk")
    print(f"  Committee reviews it and adds it to the registry.")
    print(f"  This runs in CI/CD (compliance_gate.py) — unapproved models never")
    print(f"  reach production.")

    print(f"\n  {GREEN}Demo completed in {elapsed:.2f}s{RESET}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
