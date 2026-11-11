"""Known-relationship samples with explicit multi-upstream motif coverage.

This is a purpose-built experiment family, not an unbiased Internet reduction.
The unmodified first-round proportional samples remain a separate baseline.
"""
import argparse
from collections import Counter, defaultdict, deque
import math
from pathlib import Path
import random

import networkx as nx

from sample_topologies import quotas, run


def sample_motifs(graph, size, seed):
    if type(size) is not int or type(seed) is not int or size < 10 or size > len(graph):
        raise ValueError("Motif sampling needs integer seed and 10 <= size <= population")
    if not nx.is_connected(graph):
        raise ValueError("Motif population must be connected")
    if any(d["relation"] not in ("p2c", "p2p") for _, _, d in graph.edges(data=True)):
        raise ValueError("Motif experiment requires the explicit known-relationship domain")
    rng = random.Random(seed)
    groups = defaultdict(list)
    providers = defaultdict(list)
    for n in sorted(graph):
        groups[graph.nodes[n]["stratum"]].append(n)
        providers[n] = sorted(other for other, row in graph[n].items() if row["relation"] == "p2c" and row["provider"] == other)
    target = quotas(groups, size)
    hub_pool = sorted(graph, key=lambda n: (-graph.degree(n), n))[:max(1, math.ceil(len(graph) / 100))]
    root = rng.choice(hub_pool)
    parent, queue = {root: None}, deque([root])
    while queue:
        current = queue.popleft()
        for nxt in sorted(graph[current]):
            if nxt not in parent:
                parent[nxt] = current
                queue.append(nxt)
    candidates = sorted(n for n in graph if len(providers[n]) >= 2)
    rng.shuffle(candidates)
    goal = size // 10
    if len(candidates) < goal:
        raise ValueError("Insufficient observed multi-provider candidates")
    selected, trace, counts = set(), [], Counter()

    def add(n, reason):
        if n not in selected:
            key = graph.nodes[n]["stratum"]
            selected.add(n)
            counts[key] += 1
            trace.append({"step": len(trace), "asn": n, "stratum": key, "reason": reason})

    add(root, "hub_seed")
    anchors, rejected = [], []
    for anchor in candidates:
        upstream = sorted(rng.sample(providers[anchor], 2))
        path, n = [], anchor
        while n is not None:
            path.append(n)
            n = parent[n]
        bundle = set(path) | set(upstream)
        if len(selected | bundle) > size:
            rejected.append({"asn": anchor, "reason": "bundle_exceeds_node_budget"})
            continue
        for n in reversed(path):
            add(n, "motif_connection_path")
        for n in upstream:
            add(n, "motif_provider")
        anchors.append({"asn": anchor, "providers": upstream})
        if len(anchors) == goal:
            break
    if len(anchors) < goal:
        raise ValueError(f"Cannot satisfy motif coverage within size budget: {len(anchors)}/{goal}")
    frontier = defaultdict(set)
    for n in sorted(selected):
        for nxt in graph[n]:
            if nxt not in selected:
                frontier[graph.nodes[nxt]["stratum"]].add(nxt)
    while len(selected) < size:
        keys = sorted(k for k, vals in frontier.items() if vals)
        if not keys:
            raise ValueError("Motif frontier exhausted")
        deficit = max(target[k] - counts[k] for k in keys)
        key = rng.choice([k for k in keys if target[k] - counts[k] == deficit])
        n = rng.choice(sorted(frontier[key]))
        frontier[key].remove(n)
        add(n, "connected_quota_frontier")
        for nxt in graph[n]:
            if nxt not in selected:
                frontier[graph.nodes[nxt]["stratum"]].add(nxt)
    control_rng = random.Random(seed)
    control = sorted(n for key in sorted(groups) for n in control_rng.sample(groups[key], target[key]))
    return sorted(selected), {"target_strata": target, "achieved_strata": dict(sorted(counts.items())),
                              "hub_pool_size": len(hub_pool), "root_asn": root, "selection_trace": trace,
                              "uniform_control_asns": control, "motif_target": goal, "motif_anchors": anchors,
                              "rejected_anchor_bundles": rejected,
                              "motif_semantics": "Retained inferred adjacency, not proof of real multihoming configuration or Anycast."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--design", type=Path, default=Path(__file__).with_name("motif_design.json"))
    run(parser.parse_args(), sample_motifs, "multi-upstream-motif-frontier-v1")
