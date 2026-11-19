"""
Adversarial graphs: canonicalization before
detection, distinct-txn counting, sanity checks on flagged clusters,
input_quality counts, and the sample-data regression (same 2 clusters).
"""
import json
import os
import sys

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lambdas.detection_agent.handler as h  # noqa: E402
from lambdas.detection_agent import fraud_detection  # noqa: E402
from _detection_fixtures import capture_audit, main_item, ring_txns  # noqa: E402


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch):
    monkeypatch.delenv("WRITE_AUDIT", raising=False)
    assert not os.path.isdir("/var/task")


def _run(txns):
    return h.handler({"mode": "cpu", "transactions_inline": txns})


def _mixed_case_ring():
    """5-account ring where every sender is upper case and every receiver
    lower case, so raw ids never match across edges."""
    ring = ring_txns(prefix="acc-ring", n=5)
    for t in ring:
        t["sender_id"] = t["sender_id"].upper()
    return ring


def test_mixed_case_ring_detected_as_one_ring_after_canonicalization():
    out = _run(_mixed_case_ring())
    assert len(out["flagged_clusters"]) == 1
    cluster = out["flagged_clusters"][0]
    assert cluster["typology"] == "circular_structuring"
    assert sorted(cluster["accounts"]) == [f"acc-ring{i}" for i in range(5)]


def test_mixed_case_ring_splits_without_canonicalization():
    flagged, _, _ = fraud_detection.detect_fraud_cpu(_mixed_case_ring())
    assert flagged == []


def test_duplicate_txn_ids_cannot_inflate_volume():
    # A 3-ring at 2,500 each (avg 2,500 < 3,000 threshold) padded with
    # duplicates of one txn_id at 9,000: without dedupe the average would
    # exceed the threshold.
    ring = ring_txns(prefix="acc-d", n=3, amount=2500.0)
    dup = dict(ring[0], amount=9000.0)
    out = _run(ring + [dup, dict(dup), dict(dup)])
    assert out["flagged_clusters"] == []
    assert out["input_quality"]["duplicates_rejected"] == 3
    assert out["schema_rejected_count"] == 3


def test_score_cluster_counts_distinct_txns():
    ring = ring_txns(prefix="acc-s", n=3)
    accounts = [t["sender_id"] for t in ring]
    # Five copies of one txn are one distinct txn: below the 2-txn minimum.
    assert fraud_detection.score_cluster(accounts, [dict(ring[0]) for _ in range(5)]) == (False, None, {})
    # Duplicates never change the scored factors.
    _, _, padded = fraud_detection.score_cluster(accounts, ring + [dict(ring[0], amount=1.0)] * 4)
    _, _, base = fraud_detection.score_cluster(accounts, ring)
    assert padded == base


def test_self_loop_rejected():
    ring = ring_txns(prefix="acc-l", n=3)
    loop = dict(ring[0], txn_id="loop-1", receiver_id=ring[0]["sender_id"])
    out = _run(ring + [loop])
    assert out["schema_rejected_count"] == 1
    assert out["transaction_count"] == 3


def test_cluster_with_two_distinct_txns_not_flagged(monkeypatch):
    # A flagged cluster whose canonical intra-cluster txns are only 2 distinct
    # ids is dropped before it can become provenance-root evidence.
    two = ring_txns(prefix="acc-p", n=3)[:2]
    cluster = {"accounts": ["acc-p0", "acc-p1", "acc-p2"], "account_count": 3,
               "typology": "circular_structuring", "total_amount_usd": 18000.0}
    monkeypatch.setattr(h, "detect_fraud_cpu", lambda txns: ([dict(cluster)], 0.0, []))
    out = _run(two)
    assert out["flagged_clusters"] == []
    # With a third distinct txn the same cluster is kept.
    out = _run(ring_txns(prefix="acc-p", n=3))
    assert len(out["flagged_clusters"]) == 1
    assert out["flagged_clusters"][0]["evidence_flags"] == ["AMOUNT_MISMATCH"]


def test_sanity_amount_mismatch_and_overlap_flags():
    ring = ring_txns(prefix="acc-m", n=3)
    accounts = [t["sender_id"] for t in ring]
    good = {"accounts": accounts, "total_amount_usd": 27000.0}
    bad = {"accounts": accounts, "total_amount_usd": 27000.5}
    kept = h.apply_cluster_sanity_checks([dict(good)], ring)
    assert "evidence_flags" not in kept[0]
    kept = h.apply_cluster_sanity_checks([dict(bad)], ring)
    assert kept[0]["evidence_flags"] == ["AMOUNT_MISMATCH"]
    kept = h.apply_cluster_sanity_checks([dict(good), dict(good)], ring)
    assert [c["evidence_flags"] for c in kept] == [["OVERLAPPING_ACCOUNT"]] * 2


def test_input_quality_counts(monkeypatch):
    items = capture_audit(monkeypatch, h)
    ring = ring_txns(prefix="acc-q", n=3)
    batch = [dict(ring[0], memo="x")] + ring[1:] + [
        dict(ring[1]),                                          # duplicate txn_id
        {"txn_id": "bad-amt", "sender_id": "a", "receiver_id": "b", "amount": True,
         "timestamp": "2026-01-01T00:00:00"},                   # bool amount
        {"txn_id": "bad-str", "sender_id": "a", "receiver_id": "b", "amount": "100",
         "timestamp": "2026-01-01T00:00:00"},                   # str amount
        {"txn_id": "p", "card": "4532015112830366"},            # PAN-rejected
    ]
    out = h.handler({"mode": "cpu", "transactions_inline": batch})
    assert out["input_quality"] == {"transactions_in": 7, "transactions_used": 3,
                                    "schema_rejected": 3, "duplicates_rejected": 1,
                                    "fields_dropped": 1}
    assert out["schema_rejected_count"] == 3
    assert out["fields_dropped"] == 1
    assert out["transaction_count"] == 3
    item = main_item(items, out["detection_id"])
    assert item["input_quality"]["schema_rejected"] == 3
    # Schema rejection refs carry the ORIGINAL input index and a reason code.
    assert item["schema_rejection_refs"] == [
        {"index": 3, "reason_code": "DUPLICATE_TXN_ID"},
        {"index": 4, "reason_code": "AMOUNT"},
        {"index": 5, "reason_code": "AMOUNT"},
    ]
    assert item["record_day"] == out["timestamp"][:10]


def test_mixed_naive_and_aware_timestamps_in_one_ring():
    ring = ring_txns(prefix="acc-z", n=3)
    ring[0]["timestamp"] = "2026-01-01T00:00:00"
    ring[1]["timestamp"] = "2026-01-01T00:00:05+00:00"
    ring[2]["timestamp"] = "2026-01-01T00:00:02.999999"
    out = _run(ring)
    assert len(out["flagged_clusters"]) == 1
    assert out["flagged_clusters"][0]["time_span_seconds"] == 5.0


def test_sample_data_yields_same_two_clusters():
    with open(os.path.join(PROJECT_ROOT, "data", "transactions_small.jsonl"), encoding="utf-8") as f:
        raw = [json.loads(line) for line in f if line.strip()]
    raw_flagged, _, _ = fraud_detection.detect_fraud_cpu(raw)
    out = h.handler({"mode": "cpu", "dataset_id": "sample-small"})

    def shape(clusters):
        return sorted((c["typology"], tuple(sorted(c["accounts"])), c["account_count"],
                       c["total_amount_usd"]) for c in clusters)

    assert len(out["flagged_clusters"]) == 2
    assert shape(out["flagged_clusters"]) == shape(raw_flagged)
    assert {c["typology"] for c in out["flagged_clusters"]} == {"circular_structuring", "layering_shell"}
    assert out["schema_rejected_count"] == 0
    assert out["fields_dropped"] == 218
    assert out["transaction_count"] == 218
    assert all("evidence_flags" not in c for c in out["flagged_clusters"])
