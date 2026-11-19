"""
Fraud Ring Detection — GPU-accelerated graph analysis using NVIDIA cuGraph.

Ported from NVIDIA-FSI-Demo/Fraud_detection/Fraud_ring_detection.py.
Stripped of __main__ block; callable as a library from the detection agent handler.

GPU path requires: cudf, cugraph (NVIDIA RAPIDS)
CPU fallback: networkx, pandas
"""
import json
import os
import time
import warnings
import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict

# Suppress cuGraph transposed storage warning (GPU path only)
warnings.filterwarnings("ignore", message=".*store_transposed.*")

# --- High-risk merchant categories ---
HIGH_RISK_CATEGORIES = {"crypto_exchange", "wire_transfer", "consulting_fee", "invoice_payment"}

# --- Path-confinement for caller-supplied transaction_file ---
# Transaction files may only be read from an allow-listed base directory,
# must end in .json/.jsonl, and are size-capped so a caller cannot turn
# open() into an arbitrary-path existence/errno oracle or point it at
# /dev/zero to exhaust memory. ALLOWED_TXN_DIR defaults to the project's
# data/ directory and can be overridden via env for other deployments —
# but the env override is validated against an expected prefix at import
# time: ALLOWED_TXN_DIR=/ would otherwise remove containment
# entirely, since every resolved path starts with "/".
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_TXN_DIR = os.path.join(_PROJECT_ROOT, "data")


def _validate_allowed_txn_dir(raw_dir: str) -> str:
    """Resolve and validate an ALLOWED_TXN_DIR value.

    Must resolve to a real directory located under this project's root
    (i.e. it must actually be *this* project's data directory, or a
    subdirectory of it) — not an arbitrary, operator-env-configurable path
    that could collapse containment to nothing (e.g. "/" or "/etc").
    """
    resolved = os.path.realpath(raw_dir)
    root_with_sep = _PROJECT_ROOT + os.sep
    if resolved != _PROJECT_ROOT and not resolved.startswith(root_with_sep):
        raise ValueError(
            f"ALLOWED_TXN_DIR ({raw_dir!r} -> {resolved!r}) must resolve under the "
            f"project root ({_PROJECT_ROOT!r}); refusing to use it as the confinement "
            f"boundary."
        )
    return resolved


ALLOWED_TXN_DIR = _validate_allowed_txn_dir(
    os.environ.get("ALLOWED_TXN_DIR", _DEFAULT_TXN_DIR)
)
MAX_TXN_FILE_BYTES = int(os.environ.get("MAX_TXN_FILE_BYTES", str(64 * 1024 * 1024)))  # 64 MiB


def _resolve_confined_path(filepath: str) -> str:
    """Resolve filepath and confirm it is inside ALLOWED_TXN_DIR with an
    allowed suffix. Raises ValueError otherwise.

    The suffix check runs AFTER os.path.realpath(), not before:
    checking the raw caller-supplied path's suffix first let a symlink
    named e.g. "evil.json" — which satisfies the suffix check by name alone
    — resolve to and read any target, anywhere, once realpath was applied
    downstream. Validating the suffix on the already-resolved path removes
    that gap: a symlink's resolved target must itself end in .json/.jsonl
    AND live under ALLOWED_TXN_DIR.
    """
    resolved = os.path.realpath(filepath)
    if not resolved.lower().endswith((".json", ".jsonl")):
        raise ValueError("transaction_file must resolve to a .json or .jsonl file")
    base = ALLOWED_TXN_DIR + os.sep
    if resolved != ALLOWED_TXN_DIR and not resolved.startswith(base):
        raise ValueError("transaction_file is outside the allowed data directory")
    return resolved


def load_transactions(filepath="transactions.jsonl"):
    """Load transactions from a JSONL file confined to ALLOWED_TXN_DIR.

    The path is normalized and must resolve inside the allow-listed base
    directory with a .json/.jsonl suffix; the read is byte-capped so a
    caller-chosen path cannot exhaust memory.

    The file is opened once with O_NOFOLLOW and size-checked via fstat() on
    that single open file descriptor — the previous code
    called os.path.getsize(resolved) and then reopened the same path by
    name, a TOCTOU window in which the path could be swapped out (e.g. for
    a symlink to a different, larger file, or back to one within the size
    cap) between the size check and the read. O_NOFOLLOW also means a
    symlink placed at the resolved path after the realpath() check (but
    before this open) is rejected outright rather than followed.
    """
    # A bare relative default (the pipeline's own data file) is resolved
    # against the allowed dir; any caller-supplied path is confined to it.
    if not os.path.isabs(filepath):
        filepath = os.path.join(ALLOWED_TXN_DIR, os.path.basename(filepath))
    resolved = _resolve_confined_path(filepath)

    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        size = os.fstat(fd).st_size
        if size > MAX_TXN_FILE_BYTES:
            raise ValueError("transaction_file exceeds the maximum allowed size")

        txns = []
        bytes_read = 0
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = None  # ownership transferred to the file object
            for line in f:
                bytes_read += len(line)
                if bytes_read > MAX_TXN_FILE_BYTES:
                    raise ValueError("transaction_file exceeds the maximum allowed size")
                txns.append(json.loads(line))
        return txns
    finally:
        if fd is not None:
            os.close(fd)


def prefilter_transactions(txns):
    """Extract transactions with fraud-signal merchant categories or high amounts."""
    suspicious = []
    for t in txns:
        cat = t.get("merchant_category", "")
        if cat in HIGH_RISK_CATEGORIES or t["amount"] >= 8000:
            suspicious.append(t)
    return suspicious


def score_cluster(account_ids, txns):
    """
    Score a candidate cluster against fraud typology filters.
    Returns (is_suspicious, typology, confidence_factors) tuple.
    """
    community_set = set(account_ids)
    # Distinct transactions only: a repeated txn_id must not
    # inflate the count, volume or averages. The first occurrence wins; a
    # record without a str txn_id is counted once per record.
    intra_txns = []
    seen_txn_ids = set()
    for t in txns:
        if t["sender_id"] in community_set and t["receiver_id"] in community_set:
            txn_id = t.get("txn_id")
            if isinstance(txn_id, str):
                if txn_id in seen_txn_ids:
                    continue
                seen_txn_ids.add(txn_id)
            intra_txns.append(t)
    if len(intra_txns) < 2:
        return False, None, {}

    avg_amount = sum(t["amount"] for t in intra_txns) / len(intra_txns)
    timestamps = [datetime.fromisoformat(t["timestamp"]) for t in intra_txns]
    time_span = (max(timestamps) - min(timestamps)).total_seconds()
    senders = set(t["sender_id"] for t in intra_txns)
    receivers = set(t["receiver_id"] for t in intra_txns)
    circular_ratio = len(senders & receivers) / len(community_set) if community_set else 0

    sender_counts = defaultdict(int)
    receiver_counts = defaultdict(int)
    for t in intra_txns:
        sender_counts[t["sender_id"]] += 1
        receiver_counts[t["receiver_id"]] += 1

    fan_out_max = max(sender_counts.values()) if sender_counts else 0
    fan_in_max = max(receiver_counts.values()) if receiver_counts else 0

    confidence_factors = {
        "avg_intra_amount": round(avg_amount, 2),
        "circular_ratio": round(circular_ratio, 2),
        "fan_out_max": fan_out_max,
        "fan_in_max": fan_in_max,
    }

    # Typology 1: Circular Structuring Ring
    if avg_amount > 3000 and time_span < 120 and circular_ratio >= 0.7:
        return True, "circular_structuring", confidence_factors

    # Typology 2: Layering / Shell Companies
    fan_out = any(c >= 3 for c in sender_counts.values())
    fan_in = any(c >= 3 for c in receiver_counts.values())
    categories = set(t.get("merchant_category", "") for t in intra_txns)
    has_layering_merchants = len(categories & HIGH_RISK_CATEGORIES) >= 2
    total_volume = sum(t["amount"] for t in intra_txns)

    if fan_out and fan_in and has_layering_merchants and total_volume > 20000:
        return True, "layering_shell", confidence_factors

    return False, None, confidence_factors


def build_graph(txns):
    """Build integer-encoded edge list for graph processing."""
    df = pd.DataFrame(txns)[["sender_id", "receiver_id", "amount"]]
    all_nodes = list(set(df["sender_id"].tolist() + df["receiver_id"].tolist()))
    node_map = {node: idx for idx, node in enumerate(all_nodes)}
    reverse_map = {idx: node for node, idx in node_map.items()}
    df["src"] = df["sender_id"].map(node_map)
    df["dst"] = df["receiver_id"].map(node_map)
    return df, node_map, reverse_map, all_nodes


def detect_fraud_gpu(txns):
    """
    GPU-accelerated fraud ring detection using NVIDIA cuGraph.

    Returns:
        tuple: (flagged_clusters, elapsed_seconds, pagerank_top_10)
        - flagged_clusters: list of dicts with cluster details
        - elapsed_seconds: GPU processing time
        - pagerank_top_10: top 10 nodes by PageRank score
    """
    import cudf
    import cugraph

    print("\n[GPU] Building transaction graph with cuGraph...")
    start = time.time()

    # Phase 1: Build FULL graph for PageRank
    df = pd.DataFrame(txns)[["sender_id", "receiver_id", "amount"]]
    all_nodes = list(set(df["sender_id"].tolist() + df["receiver_id"].tolist()))
    node_map = {node: idx for idx, node in enumerate(all_nodes)}
    reverse_map_full = {idx: node for node, idx in node_map.items()}
    src = df["sender_id"].map(node_map).values
    dst = df["receiver_id"].map(node_map).values
    wt = df["amount"].values

    gdf_full = cudf.DataFrame({"src": src, "dst": dst, "weight": wt})
    G_full = cugraph.Graph()
    G_full.from_cudf_edgelist(gdf_full, source="src", destination="dst", edge_attr="weight")
    print(f"[GPU] Full graph: {G_full.number_of_vertices()} nodes, {G_full.number_of_edges()} edges")

    # Run PageRank on full graph
    pagerank_df = cugraph.pagerank(G_full)
    top_pr = pagerank_df.nlargest(10, "pagerank")
    pagerank_top_10 = [
        {"node": reverse_map_full[int(row["vertex"])], "score": round(float(row["pagerank"]), 6)}
        for _, row in top_pr.to_pandas().iterrows()
    ]
    print(f"[GPU] PageRank computed (top score: {pagerank_top_10[0]['score']:.6f})")

    # Phase 2: Pre-filter to suspicious subgraph
    filtered = prefilter_transactions(txns)
    df_sub, node_map_sub, reverse_map_sub, _ = build_graph(filtered)
    gdf = cudf.DataFrame({
        "src": df_sub["src"].values,
        "dst": df_sub["dst"].values,
        "weight": df_sub["amount"].values
    })
    G = cugraph.Graph()
    G.from_cudf_edgelist(gdf, source="src", destination="dst", edge_attr="weight")
    print(f"[GPU] Suspicious subgraph: {G.number_of_vertices()} nodes, {G.number_of_edges()} edges")

    # Phase 3: Connected components on suspicious subgraph
    comp_df = cugraph.connected_components(G, connection="weak")
    comp_df = comp_df.to_pandas()

    community_sizes = comp_df["labels"].value_counts()
    candidate_ids = community_sizes[
        (community_sizes >= 3) & (community_sizes <= 20)
    ].index.tolist()

    flagged_clusters = []
    for label_id in candidate_ids:
        node_ids = comp_df[comp_df["labels"] == label_id]["vertex"].tolist()
        account_ids = [reverse_map_sub[n] for n in node_ids]
        is_fraud, typology, confidence_factors = score_cluster(account_ids, txns)
        if is_fraud:
            # Enrich cluster details
            cluster_set = set(account_ids)
            intra_txns = [
                t for t in txns
                if t["sender_id"] in cluster_set and t["receiver_id"] in cluster_set
            ]
            total_amount = sum(t["amount"] for t in intra_txns)
            timestamps = [datetime.fromisoformat(t["timestamp"]) for t in intra_txns]
            time_span = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0
            categories = list(set(t.get("merchant_category", "") for t in intra_txns))

            flagged_clusters.append({
                "accounts": account_ids,
                "account_count": len(account_ids),
                "typology": typology,
                "total_amount_usd": round(total_amount, 2),
                "time_span_seconds": round(time_span, 1),
                "merchant_categories": categories,
                "confidence_factors": confidence_factors,
            })
            print(f"[GPU] Flagged cluster ({typology}): {len(account_ids)} accounts")

    elapsed = time.time() - start
    print(f"[GPU] Completed in {elapsed:.2f}s | Suspicious clusters found: {len(flagged_clusters)}")
    return flagged_clusters, elapsed, pagerank_top_10


def detect_fraud_cpu(txns):
    """
    CPU fallback fraud detection using NetworkX.

    Returns:
        tuple: (flagged_clusters, elapsed_seconds, pagerank_top_10)
    """
    import networkx as nx

    print("\n[CPU] Building transaction graph...")
    start = time.time()

    # Phase 1: Build FULL graph
    df = pd.DataFrame(txns)
    G_full = nx.from_pandas_edgelist(df, source="sender_id", target="receiver_id",
                                      edge_attr="amount", create_using=nx.DiGraph())
    print(f"[CPU] Full graph: {G_full.number_of_nodes()} nodes, {G_full.number_of_edges()} edges")

    # Run PageRank (pure-Python implementation to avoid scipy dependency in Lambda)
    try:
        pr = nx.pagerank(G_full, max_iter=100, tol=1e-06)
    except ImportError:
        # Fallback: manual power iteration if scipy not available
        N = G_full.number_of_nodes()
        nodes = list(G_full.nodes())
        pr = {n: 1.0 / N for n in nodes}
        damping = 0.85
        for _ in range(100):
            new_pr = {}
            for node in nodes:
                rank_sum = sum(pr[pred] / G_full.out_degree(pred)
                               for pred in G_full.predecessors(node)
                               if G_full.out_degree(pred) > 0)
                new_pr[node] = (1 - damping) / N + damping * rank_sum
            pr = new_pr
    sorted_pr = sorted(pr.items(), key=lambda x: x[1], reverse=True)[:10]
    pagerank_top_10 = [
        {"node": node, "score": round(score, 6)}
        for node, score in sorted_pr
    ]
    print(f"[CPU] PageRank computed (top score: {pagerank_top_10[0]['score']:.6f})")

    # Phase 2: Pre-filter to suspicious subgraph
    filtered = prefilter_transactions(txns)
    G = nx.DiGraph()
    for txn in filtered:
        G.add_edge(txn["sender_id"], txn["receiver_id"], weight=txn["amount"])
    print(f"[CPU] Suspicious subgraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Phase 3: Connected components and scoring
    components = list(nx.connected_components(G.to_undirected()))
    candidates = [c for c in components if 3 <= len(c) <= 20]

    flagged_clusters = []
    for comp in candidates:
        account_ids = list(comp)
        is_fraud, typology, confidence_factors = score_cluster(account_ids, txns)
        if is_fraud:
            cluster_set = set(account_ids)
            intra_txns = [
                t for t in txns
                if t["sender_id"] in cluster_set and t["receiver_id"] in cluster_set
            ]
            total_amount = sum(t["amount"] for t in intra_txns)
            timestamps = [datetime.fromisoformat(t["timestamp"]) for t in intra_txns]
            time_span = (max(timestamps) - min(timestamps)).total_seconds() if len(timestamps) > 1 else 0
            categories = list(set(t.get("merchant_category", "") for t in intra_txns))

            flagged_clusters.append({
                "accounts": account_ids,
                "account_count": len(account_ids),
                "typology": typology,
                "total_amount_usd": round(total_amount, 2),
                "time_span_seconds": round(time_span, 1),
                "merchant_categories": categories,
                "confidence_factors": confidence_factors,
            })
            print(f"[CPU] Flagged cluster ({typology}): {len(account_ids)} accounts")

    elapsed = time.time() - start
    print(f"[CPU] Completed in {elapsed:.2f}s | Suspicious clusters found: {len(flagged_clusters)}")
    return flagged_clusters, elapsed, pagerank_top_10
