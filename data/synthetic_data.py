"""
Synthetic Transaction Data Generator.

Ported from NVIDIA-FSI-Demo/Fraud_detection/Synthetic_data.py.
Generates realistic transaction data with injected fraud patterns:
- Circular structuring rings (just-under-threshold rapid transactions)
- Layering / shell company patterns (fan-out then fan-in)

Usage:
    python data/synthetic_data.py
    # Generates transactions_small.jsonl in data/ directory
"""
import json
import random
import uuid
from datetime import datetime, timedelta

# Use simple randomization instead of Faker for portability
FIRST_NAMES = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
               "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
               "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
              "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
              "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]
CITIES = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia",
          "San Antonio", "San Diego", "Dallas", "San Jose", "Austin", "Jacksonville",
          "Fort Worth", "Columbus", "Charlotte", "Indianapolis", "Denver", "Seattle"]

# --- Config ---
NUM_NORMAL_ACCOUNTS = 50000
FRAUD_RING_SIZE = 10
LAYERING_SHELL_COUNT = 6


def random_name():
    return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"  # nosec B311 -- synthetic demo data, not security-sensitive


def generate_accounts(n, is_fraud=False):
    """Generate synthetic accounts."""
    accounts = []
    for _ in range(n):
        accounts.append({
            "account_id": "acc-" + str(uuid.uuid4())[:8],
            "name": random_name(),
            "location": random.choice(CITIES),  # nosec B311 -- synthetic demo data, not security-sensitive
            "account_age_days": random.randint(30, 3650),  # nosec B311 -- synthetic demo data, not security-sensitive
            "is_fraud_ring": is_fraud
        })
    return accounts


# Pre-generate accounts
normal_accounts = generate_accounts(NUM_NORMAL_ACCOUNTS, is_fraud=False)
fraud_accounts = generate_accounts(FRAUD_RING_SIZE, is_fraud=True)
layering_accounts = generate_accounts(LAYERING_SHELL_COUNT, is_fraud=True)
all_accounts = normal_accounts + fraud_accounts + layering_accounts


def generate_normal_txn(accounts):
    """Generate a single normal transaction."""
    sender = random.choice(accounts)  # nosec B311 -- synthetic demo data, not security-sensitive
    receiver = random.choice(accounts)  # nosec B311 -- synthetic demo data, not security-sensitive
    while receiver["account_id"] == sender["account_id"]:
        receiver = random.choice(accounts)  # nosec B311 -- synthetic demo data, not security-sensitive
    return {
        "txn_id": "txn-" + str(uuid.uuid4())[:8],
        "timestamp": datetime.utcnow().isoformat(),
        "sender_id": sender["account_id"],
        "receiver_id": receiver["account_id"],
        "amount": round(random.uniform(10, 5000), 2),  # nosec B311 -- synthetic demo data, not security-sensitive
        "merchant_category": random.choice(["retail", "food", "travel", "utilities", "entertainment"]),  # nosec B311 -- synthetic demo data, not security-sensitive
        "is_fraud": False
    }


def generate_fraud_ring_txns(fraud_accts):
    """
    Generate circular structuring fraud pattern.
    Just under 10K, rapid succession timestamps, crypto/wire categories.
    """
    txns = []
    ring = fraud_accts.copy()
    random.shuffle(ring)
    base_time = datetime.utcnow()
    categories = ["crypto_exchange", "wire_transfer", "crypto_exchange", "wire_transfer", "crypto_exchange"]
    for i in range(len(ring)):
        sender = ring[i]
        receiver = ring[(i + 1) % len(ring)]
        txns.append({
            "txn_id": "txn-" + str(uuid.uuid4())[:8],
            "timestamp": (base_time + timedelta(seconds=i * 6)).isoformat(),
            "sender_id": sender["account_id"],
            "receiver_id": receiver["account_id"],
            "amount": round(random.uniform(900, 9999), 2),  # nosec B311 -- synthetic demo data, not security-sensitive
            "merchant_category": categories[i % len(categories)],
            "is_fraud": True
        })
    return txns


def generate_layering_txns(layering_accts):
    """
    Generate layering / shell company fraud pattern.
    Source fans out to shells, shells consolidate to destination.
    """
    txns = []
    base_time = datetime.utcnow() - timedelta(hours=2)
    source = layering_accts[0]
    destination = layering_accts[-1]
    shells = layering_accts[1:-1]

    # Phase 1: Source fans out to shell accounts
    total_amount = round(random.uniform(40000, 80000), 2)  # nosec B311 -- synthetic demo data, not security-sensitive
    split_amounts = []
    remaining = total_amount
    for i, shell in enumerate(shells):
        if i == len(shells) - 1:
            amt = remaining
        else:
            amt = round(random.uniform(remaining * 0.15, remaining * 0.4), 2)  # nosec B311 -- synthetic demo data, not security-sensitive
            remaining -= amt
        split_amounts.append(amt)
        txns.append({
            "txn_id": "txn-" + str(uuid.uuid4())[:8],
            "timestamp": (base_time + timedelta(minutes=i * 3)).isoformat(),
            "sender_id": source["account_id"],
            "receiver_id": shell["account_id"],
            "amount": amt,
            "merchant_category": random.choice(["wire_transfer", "consulting_fee", "invoice_payment"]),  # nosec B311 -- synthetic demo data, not security-sensitive
            "is_fraud": True
        })

    # Phase 2: Shells forward to destination (integration)
    for i, (shell, amt) in enumerate(zip(shells, split_amounts)):
        forwarded = round(amt * random.uniform(0.92, 0.98), 2)  # nosec B311 -- synthetic demo data, not security-sensitive
        txns.append({
            "txn_id": "txn-" + str(uuid.uuid4())[:8],
            "timestamp": (base_time + timedelta(minutes=len(shells) * 3 + i * 5)).isoformat(),
            "sender_id": shell["account_id"],
            "receiver_id": destination["account_id"],
            "amount": forwarded,
            "merchant_category": random.choice(["wire_transfer", "consulting_fee", "invoice_payment"]),  # nosec B311 -- synthetic demo data, not security-sensitive
            "is_fraud": True
        })

    return txns


def stream_transactions(num_normal=200, inject_fraud=True, output_file=None):
    """Generate transaction dataset and write to JSONL file."""
    print(f"Generating {num_normal} normal transactions...")
    txns = []

    for _ in range(num_normal):
        txns.append(generate_normal_txn(all_accounts))

    if inject_fraud:
        print(">>> INJECTING FRAUD RING <<<")
        fraud_txns = generate_fraud_ring_txns(fraud_accounts)
        insert_positions = sorted(random.sample(range(len(txns)), min(len(fraud_txns), len(txns))))  # nosec B311 -- synthetic demo data, not security-sensitive
        for pos, ftxn in zip(insert_positions, fraud_txns):
            txns.insert(pos, ftxn)

        print(">>> INJECTING LAYERING PATTERN <<<")
        layering_txns = generate_layering_txns(layering_accounts)
        insert_positions = sorted(random.sample(range(len(txns)), min(len(layering_txns), len(txns))))  # nosec B311 -- synthetic demo data, not security-sensitive
        for pos, ltxn in zip(insert_positions, layering_txns):
            txns.insert(pos, ltxn)

    filename = output_file if output_file else "transactions.jsonl"
    with open(filename, "w", encoding="utf-8") as f:
        for txn in txns:
            f.write(json.dumps(txn) + "\n")

    print(f"Written {len(txns)} transactions to {filename}")
    return txns


if __name__ == "__main__":
    import os
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Small dataset for logic testing.
    # NOTE: keep num_normal low enough that the inline payload sent to the
    # AgentCore Runtime stays under the 100 KB InvokeAgentRuntime limit.
    # ~200 normal txns => ~43 KB payload (both fraud patterns still injected).
    stream_transactions(
        num_normal=200, inject_fraud=True,
        output_file=os.path.join(script_dir, "transactions_small.jsonl")
    )
    print("Dataset ready!")
