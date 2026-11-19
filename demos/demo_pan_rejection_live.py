#!/usr/bin/env python3
"""
Demo: PAN Rejection — LIVE Lambda invocation.

Invokes the deployed fsi-pan-filter Lambda with PAN-laden payloads
and verifies the ingress filter rejects them at the boundary.

This Lambda is pure-stdlib (no pandas/numpy) — it deploys and cold-starts
in under 1 second.

Requires:
  - Deployed infrastructure (make deploy)
  - AWS credentials with lambda:InvokeFunction permission
"""
import json
import os
import sys
import time
import argparse
import boto3

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

FUNCTION_NAME = "fsi-pan-filter"  # fixed (cdk/agents_stack.py); no env override
REGION = os.environ.get("AWS_REGION", "us-east-1")

# Luhn-valid test PAN: 4532015112830366
EVASION_PAYLOADS = [
    ("Plain 16-digit", "4532015112830366"),
    ("Dash-separated", "4532-0151-1283-0366"),
    ("Space-separated", "4532 0151 1283 0366"),
    ("Zero-width chars", "4532\u200b0151\u200b1283\u200b0366"),
    ("Mixed separators", "4532-0151 1283-0366"),
    ("Unicode full-width", "\uff14\uff15\uff13\uff12\uff10\uff11\uff15\uff11\uff11\uff12\uff18\uff13\uff10\uff13\uff16\uff16"),
]

# Legitimate masked PANs that should NOT be caught
SAFE_VARIANTS = [
    ("Masked with *", "4532-01**-****-0366"),
    ("Masked with x", "4532xxxxxxxx0366"),
    ("BIN + last 4", "453201****0366"),
]


def invoke_pan_filter(client, payload: dict) -> dict:
    """Invoke the PAN filter Lambda."""
    response = client.invoke(
        FunctionName=FUNCTION_NAME,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode("utf-8"),
    )
    response_payload = json.loads(response["Payload"].read())

    if "FunctionError" in response:
        return {"error": response_payload}

    return response_payload


def main():
    parser = argparse.ArgumentParser(description="Demo: PAN Rejection — Live Lambda")
    parser.add_argument("--region", type=str, default=REGION, help="AWS region")
    parser.add_argument("--function", type=str, default=FUNCTION_NAME,
                        help="Lambda function name (default: fsi-pan-filter)")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  PAN INGRESS FILTER — LIVE LAMBDA INVOCATION{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Function: {CYAN}{args.function}{RESET}")
    print(f"  Region:   {CYAN}{args.region}{RESET}")
    print(f"  Verifying PCI-DSS boundary on deployed infrastructure")
    print()

    client = boto3.client("lambda", region_name=args.region)
    start_time = time.time()
    all_pass = True

    # === Test 1: Each evasion variant (single-text mode) ===
    print(f"  {BOLD}Sending PAN-laden text (must be BLOCKED):{RESET}")
    for name, pan in EVASION_PAYLOADS:
        text = f'{{"txn_id": "test", "card": "{pan}"}}'
        try:
            result = invoke_pan_filter(client, {"text": text})

            if result.get("error"):
                print(f"    {YELLOW}ERROR{RESET}   — {name}: {result['error']}")
                all_pass = False
            elif result.get("action") == "BLOCKED":
                print(f"    {RED}BLOCKED{RESET} — {name}: {pan[:8]}...{pan[-4:]}")
            else:
                print(f"    {YELLOW}MISSED{RESET}  — {name}: {pan[:8]}...{pan[-4:]}")
                all_pass = False
        except Exception as e:
            print(f"    {YELLOW}INVOKE ERROR{RESET} — {name}: {e}")
            all_pass = False

    # === Test 2: Safe variants (should NOT be caught) ===
    print(f"\n  {BOLD}Sending masked PANs (must be ALLOWED):{RESET}")
    for name, masked in SAFE_VARIANTS:
        text = f'{{"txn_id": "test", "card": "{masked}"}}'
        try:
            result = invoke_pan_filter(client, {"text": text})

            if result.get("error"):
                print(f"    {YELLOW}ERROR{RESET}   — {name}: {result['error']}")
                all_pass = False
            elif result.get("action") == "ALLOWED":
                print(f"    {GREEN}ALLOWED{RESET} — {name}: {masked}")
            else:
                print(f"    {RED}FALSE POSITIVE{RESET} — {name}: {masked}")
                all_pass = False
        except Exception as e:
            print(f"    {YELLOW}INVOKE ERROR{RESET} — {name}: {e}")
            all_pass = False

    # === Test 3: Batch transaction mode — all 6 variants ===
    print(f"\n  {BOLD}Batch filter test (all 6 evasion variants + 2 clean):{RESET}")
    batch_payload = {
        "transactions": [
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
    }

    try:
        result = invoke_pan_filter(client, batch_payload)

        if result.get("error"):
            print(f"    {YELLOW}ERROR{RESET} — {result['error']}")
            all_pass = False
        else:
            allowed = result.get("allowed_count", 0)
            rejected = result.get("rejected_count", 0)
            print(f"    Input:    {result.get('total_input', '?')} transactions")
            print(f"    Allowed:  {GREEN}{allowed}{RESET}")
            print(f"    Rejected: {RED}{rejected}{RESET}")
            # The Lambda returns rejected indices only (no rule, reason or
            # txn_ref).
            indices = result.get("rejected_indices", [])
            print(f"    Rejected indices: {', '.join(str(i) for i in indices)}")

            if rejected != 6 or allowed != 2:
                all_pass = False
    except Exception as e:
        print(f"    {YELLOW}INVOKE ERROR{RESET} — {e}")
        all_pass = False

    elapsed = time.time() - start_time

    # Summary
    print(f"\n  {'='*60}")
    if all_pass:
        print(f"  {GREEN}{BOLD}LIVE PCI-DSS BOUNDARY VERIFIED — ALL EVASIONS CAUGHT{RESET}")
    else:
        print(f"  {RED}{BOLD}BOUNDARY VERIFICATION FAILED — SEE ABOVE{RESET}")

    invocations = len(EVASION_PAYLOADS) + len(SAFE_VARIANTS) + 1
    print(f"  Round-trip time: {elapsed:.2f}s ({invocations} Lambda invocations)")
    print(f"{'='*60}\n")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
