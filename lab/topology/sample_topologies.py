"""Reproducible, source-attributed AS samples; never a complete Internet model.

The connected samples are deliberately conditional on connectivity and a hub
seed. Uniform stratified controls expose that selection bias. No outcome from a
SAV mechanism is used to pick nodes. This is offline preparation, not simulation.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import shutil
import sqlite3
import sys
import time

import networkx as nx

from fetch_sources import sha256


VERSION = "k5-topology-sample-v1"
EDGE_FIELDS = ["u", "v", "relation", "provider", "inferred_sources", "observed_sources"]
NODE_FIELDS = ["asn", "degree", "providers", "customers", "peers", "unknown"]


def dump(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def csv_write(path, fields, rows):
    with Path(path).open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fields, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, separators=(",", ":")) if isinstance(v, (list, dict)) else v
                             for k, v in row.items() if k in fields})


def degree_band(n):
    for high, name in ((0, "0"), (1, "1"), (4, "2-4"), (16, "5-16"), (64, "17-64")):
        if n <= high:
            return name
    return "65+"


def role(row):
    # These are inferred structural categories, NOT verified business identities.
    if row["customers"]:
        return "transit_with_upstream" if row["providers"] else "transit_no_known_upstream"
    if row["providers"]:
        return "no_known_customers"
    if row["peers"]:
        return "peer_only_known"
    return "unknown_only" if row["degree"] else "isolated"


def stratum(row):
    return f"{role(row)}|{degree_band(row['degree'])}|{min(row['providers'], 2)}"


def load_graph(db, layer):
    graph = nx.Graph()
    for raw in db.execute("SELECT asn,degree,providers,customers,peers,unknown FROM nodes WHERE layer=? ORDER BY asn", (layer,)):
        row = dict(zip(NODE_FIELDS, raw))
        row.update(full_role=role(row), stratum=stratum(row))
        graph.add_node(row["asn"], **row)
    for raw in db.execute("SELECT u,v,relation,provider,inferred_sources,observed_sources FROM edges WHERE layer=? ORDER BY u,v", (layer,)):
        row = dict(zip(EDGE_FIELDS, raw))
        for field in ("inferred_sources", "observed_sources"):
            row[field] = json.loads(row[field])
        if row["u"] not in graph or row["v"] not in graph:
            raise ValueError("Edge endpoint missing from source nodes")
        if row["relation"] not in ("p2p", "p2c", "unknown", "conflict"):
            raise ValueError("Unsupported source relationship")
        if row["relation"] == "p2c" and row["provider"] not in (row["u"], row["v"]):
            raise ValueError("Invalid provider direction")
        graph.add_edge(row["u"], row["v"], **row)
    for n, d in graph.degree():
        if d != graph.nodes[n]["degree"]:
            raise ValueError(f"Source degree mismatch at {n}")
    return graph


def domain_graph(graph, domain):
    if domain == "union":
        return graph
    if domain != "known":
        raise ValueError("Unknown edge domain")
    result = nx.Graph()
    result.add_nodes_from(graph.nodes(data=True))
    result.add_edges_from((u, v, d) for u, v, d in graph.edges(data=True) if d["relation"] in ("p2p", "p2c"))
    return result


def largest_component(graph):
    # Deterministic tie break; exclusions are reported, not silently discarded.
    components = sorted(nx.connected_components(graph), key=lambda c: (-len(c), min(c)))
    if not components:
        raise ValueError("Empty population")
    return components[0], [len(c) for c in components]


def quotas(groups, size):
    total = sum(len(v) for v in groups.values())
    if not 1 <= size <= total:
        raise ValueError(f"Size {size} outside eligible population {total}")
    targets = {k: size * len(v) // total for k, v in sorted(groups.items())}
    remaining = size - sum(targets.values())
    order = sorted(groups, key=lambda k: (-(size * len(groups[k]) % total), k))
    for k in order[:remaining]:
        targets[k] += 1
    return targets


def sample_nodes(graph, size, seed):
    """graph is one eligible component; full-union attributes stay on nodes."""
    if type(seed) is not int or type(size) is not int:
        raise ValueError("size and seed must be integers")
    if not graph or not nx.is_connected(graph):
        raise ValueError("Sampling population must be one connected component")
    groups = defaultdict(list)
    for n in sorted(graph):
        groups[graph.nodes[n]["stratum"]].append(n)
    target = quotas(groups, size)
    rng = random.Random(seed)
    hub_pool = sorted(graph, key=lambda n: (-graph.degree(n), n))[:max(1, math.ceil(len(graph) / 100))]
    root = rng.choice(hub_pool)
    selected, counts, frontier, trace = set(), Counter(), defaultdict(set), []
    current = root
    for step in range(size):
        key = graph.nodes[current]["stratum"]
        selected.add(current)
        counts[key] += 1
        frontier[key].discard(current)
        trace.append({"step": step, "asn": current, "stratum": key,
                      "reason": "hub_seed" if step == 0 else "connected_quota_frontier"})
        for nxt in graph[current]:
            if nxt not in selected:
                frontier[graph.nodes[nxt]["stratum"]].add(nxt)
        if len(selected) == size:
            break
        keys = sorted(k for k, candidates in frontier.items() if candidates)
        if not keys:
            raise ValueError("Frontier exhausted before target size")
        deficit = max(target[k] - counts[k] for k in keys)
        chosen = rng.choice([k for k in keys if target[k] - counts[k] == deficit])
        current = rng.choice(sorted(frontier[chosen]))
    control_rng = random.Random(seed)
    control = sorted(n for key in sorted(groups) for n in control_rng.sample(groups[key], target[key]))
    return sorted(selected), {"target_strata": target, "achieved_strata": dict(sorted(counts.items())),
                              "hub_pool_size": len(hub_pool), "root_asn": root, "selection_trace": trace,
                              "uniform_control_asns": control}


def histogram_distance(a, b):
    na, nb = sum(a.values()), sum(b.values())
    if not na or not nb:
        return None
    return round(sum(abs(a.get(k, 0) / na - b.get(k, 0) / nb) for k in set(a) | set(b)) / 2, 8)


def relationship_counts(graph):
    roles = {n: Counter() for n in graph}
    for u, v, row in graph.edges(data=True):
        if row["relation"] == "p2c":
            p = row["provider"]
            c = v if p == u else u
            roles[p]["customers"] += 1
            roles[c]["providers"] += 1
        else:
            key = "peers" if row["relation"] == "p2p" else "unknown"
            roles[u][key] += 1
            roles[v][key] += 1
    return roles


def graph_metrics(graph, include_hops=False):
    roles = relationship_counts(graph)
    components = sorted((len(c) for c in nx.connected_components(graph)), reverse=True)
    metrics = {
        "nodes": len(graph), "edges": graph.number_of_edges(), "component_sizes": components,
        "degree_histogram": dict(sorted(Counter(dict(graph.degree()).values()).items())),
        "degree_band_histogram": dict(sorted(Counter(degree_band(d) for _, d in graph.degree()).items())),
        "full_union_degree_band_histogram": dict(sorted(Counter(degree_band(graph.nodes[n]["degree"]) for n in graph).items())),
        "full_union_role_histogram": dict(sorted(Counter(graph.nodes[n]["full_role"] for n in graph).items())),
        "relations": dict(sorted(Counter(d["relation"] for _, _, d in graph.edges(data=True)).items())),
        "inferred_multi_upstream_in_this_graph": sum(roles[n]["providers"] >= 2 for n in graph),
        "inferred_multi_upstream_in_full_union": sum(graph.nodes[n]["providers"] >= 2 for n in graph),
    }
    if include_hops:
        hops = Counter()
        for src in graph:
            for dst, length in nx.single_source_shortest_path_length(graph, src).items():
                if src < dst:
                    hops[length] += 1
        metrics["undirected_adjacency_hops_unordered_pairs"] = dict(sorted(hops.items()))
        metrics["unreachable_unordered_pairs"] = len(graph) * (len(graph) - 1) // 2 - sum(hops.values())
        metrics["hop_semantics"] = "Adjacency hops, not BGP AS_PATH, policy reachability or forwarding."
    return metrics


def make_sample(graph, eligible, domain, layer, size, seed, database_hash, sampler=sample_nodes):
    selected, audit = sampler(eligible, size, seed)
    selected_set = set(selected)
    active = eligible.subgraph(selected)
    induced = graph.subgraph(selected)
    local_roles = relationship_counts(active)
    nodes = []
    for n in selected:
        row = dict(graph.nodes[n])
        row.update(sample_degree=active.degree(n), union_induced_degree=induced.degree(n),
                   boundary_degree=graph.degree(n) - induced.degree(n),
                   sample_providers=local_roles[n]["providers"], sample_customers=local_roles[n]["customers"],
                   sample_peers=local_roles[n]["peers"], sample_unknown=local_roles[n]["unknown"])
        nodes.append(row)
    edges = []
    boundary = []
    # Traversing selected adjacency enumerates ALL cut edges, not just a display cap.
    for n in selected:
        for other in sorted(graph[n]):
            row = dict(graph[n][other])
            if other in selected_set:
                if n < other:
                    row["active"] = active.has_edge(n, other)
                    row["inactive_reason"] = None if row["active"] else "unknown_or_conflicting_relationship"
                    edges.append(row)
            else:
                row.update(inside=n, outside=other)
                boundary.append(row)
    sample = {"schema": VERSION, "layer": layer, "size": size, "seed": seed, "edge_domain": domain,
              "source_database_sha256": database_hash, "nodes": nodes, "edges": edges,
              "sampling": audit, "boundary_policy": "cut_and_record_no_reconnection",
              "boundary_edges": len(boundary), "artificial_edges": 0,
              "execution": {"status": "not_deployed", "policy": "not_compiled",
                            "observed_prefixes": "prefixes.csv, provenance only; do not inject public addresses"}}
    return sample, boundary, active, induced


def write_sample(db, out, graph, eligible, domain, layer, size, seed, database_hash, full_metrics, eligible_metrics, sampler=sample_nodes):
    started = time.perf_counter()
    sample, boundary, active, induced = make_sample(graph, eligible, domain, layer, size, seed, database_hash, sampler)
    # Mandatory replay comparison before any sample is accepted.
    replay, replay_audit = sampler(eligible, size, seed)
    if replay != [n["asn"] for n in sample["nodes"]] or replay_audit != sample["sampling"]:
        raise AssertionError("Seed replay differs")
    out.mkdir(parents=True, exist_ok=False)
    prefix_counts = Counter()
    prefix_rows = []
    for n in sample["nodes"]:
        seen = set()
        for prefix, source in db.execute("SELECT prefix,source FROM prefixes WHERE layer=? AND asn=? ORDER BY prefix,source", (layer, n["asn"])):
            prefix_rows.append({"asn": n["asn"], "prefix": prefix, "source": source})
            seen.add(prefix)
        n["observed_prefix_count"] = len(seen)
        prefix_counts["rows"] += sum(1 for _ in seen)
        prefix_counts["nodes_with_prefix"] += bool(seen)
    control_ids = sample["sampling"]["uniform_control_asns"]
    control = eligible.subgraph(control_ids)
    actual = graph_metrics(active, include_hops=True)
    control_metrics = graph_metrics(control, include_hops=True)
    comparison = {}
    for name in ("degree_band_histogram", "full_union_degree_band_histogram", "full_union_role_histogram", "relations"):
        comparison[name] = {"total_variation_vs_full_union": histogram_distance(actual[name], full_metrics[name]),
                            "total_variation_vs_eligible_domain": histogram_distance(actual[name], eligible_metrics[name]),
                            "uniform_control_vs_eligible": histogram_distance(control_metrics[name], eligible_metrics[name])}
    warnings = ["Connected hub-seeded samples are not unbiased Internet samples.",
                "Seeds share one source graph; overlap is reported, not treated as independent observations.",
                "Known-domain projections omit unknown/conflicting links; omission is not evidence of no real connection.",
                "Prefixes are observed origins, not ownership/authorization; no real BGP policy is inferred."]
    quality = {"schema": VERSION, "size": size, "layer": layer, "edge_domain": domain, "seed": seed,
               "structural_status": "passed", "scientific_representativeness": "not_established",
               "active_graph": actual, "union_induced_edges": induced.number_of_edges(),
               "inactive_induced_edges": induced.number_of_edges() - active.number_of_edges(),
               "full_union_reference": full_metrics, "eligible_reference": eligible_metrics,
               "uniform_control": control_metrics, "distribution_comparison": comparison,
               "quota_l1_error_nodes": sum(abs(v - sample["sampling"]["achieved_strata"].get(k, 0)) for k, v in sample["sampling"]["target_strata"].items()),
               "boundary_edges": len(boundary), "selected_incident_endpoint_loss_fraction": len(boundary) / sum(n["degree"] for n in sample["nodes"]) if boundary else 0,
               "prefix_source_rows": len(prefix_rows), "distinct_as_prefix_pairs": prefix_counts["rows"],
               "nodes_without_observed_prefix": size - prefix_counts["nodes_with_prefix"],
               "policy_reachability": None, "data_plane_reachability": None,
               "checks": {"exact_size": len(active) == size, "domain_connected": nx.is_connected(active),
                          "source_roles_before_cut": True, "seed_replay_equal": True, "no_synthetic_edges": True},
               "limitations": warnings}
    if not all(quality["checks"].values()):
        raise AssertionError("Structural gate failed")
    dump(out / "topology.json", sample)
    csv_write(out / "nodes.csv", list(sample["nodes"][0]), sample["nodes"])
    csv_write(out / "edges.csv", EDGE_FIELDS + ["active", "inactive_reason"], sample["edges"])
    csv_write(out / "boundary.csv", EDGE_FIELDS + ["inside", "outside"], boundary)
    csv_write(out / "prefixes.csv", ["asn", "prefix", "source"], prefix_rows)
    dump(out / "quality.json", quality)
    dump(out / "manifest.json", {"schema": VERSION, "status": "structural_passed_runtime_unverified",
                                 "content_digest": digest(sample), "elapsed_seconds": time.perf_counter() - started,
                                 "artifacts": {p.name: sha256(p) for p in sorted(out.iterdir()) if p.is_file()}})
    return {"id": out.name, "layer": layer, "size": size, "domain": domain, "seed": seed,
            "active_edges": active.number_of_edges(), "unknown_active_edges": actual["relations"].get("unknown", 0),
            "boundary_edges": len(boundary), "quota_l1": quality["quota_l1_error_nodes"],
            "full_role_TV": comparison["full_union_role_histogram"]["total_variation_vs_full_union"],
            "degree_band_TV": comparison["degree_band_histogram"]["total_variation_vs_full_union"],
            "multi_upstream_full": actual["inferred_multi_upstream_in_full_union"],
            "multi_upstream_retained": actual["inferred_multi_upstream_in_this_graph"],
            "nodes_without_observed_prefix": quality["nodes_without_observed_prefix"],
            "topology_sha256": sha256(out / "topology.json")}, set(active)


def run(args, sampler=sample_nodes, algorithm="full-role-stratified-frontier-v1"):
    if args.out.exists():
        raise FileExistsError(f"Refusing existing output: {args.out}")
    design = json.loads(args.design.read_text(encoding="utf-8"))
    if design["algorithm"] != algorithm:
        raise ValueError("Unsupported sampling algorithm")
    for key in ("layers", "sizes", "seeds", "edge_domains"):
        if not design[key] or len(set(design[key])) != len(design[key]):
            raise ValueError(f"Empty/duplicate design dimension: {key}")
    if set(design["layers"]) - {"ipv4", "ipv6"} or set(design["edge_domains"]) - {"union", "known"}:
        raise ValueError("Unsupported graph domain/layer")
    if any(type(n) is not int or n < 2 for n in design["sizes"]) or any(type(n) is not int for n in design["seeds"]):
        raise ValueError("Invalid sizes/seeds")
    source_path = args.data / "map.sqlite"
    delivery = json.loads((args.data / "delivery-manifest.json").read_text(encoding="utf-8"))
    source_hash = sha256(source_path)
    if delivery["status"] != "passed" or source_hash != delivery["data_and_evidence_sha256"]["map.sqlite"]:
        raise ValueError("Source database differs from accepted map")
    args.out.mkdir(parents=True, exist_ok=False)
    code_dir = Path(__file__).parent
    code_hashes = {p.name: sha256(p) for p in sorted(code_dir.glob("*.py"))}
    (args.out / "code").mkdir()
    for name in code_hashes:
        shutil.copyfile(code_dir / name, args.out / "code" / name)
    dump(args.out / "design.json", design)
    db = sqlite3.connect(source_path.resolve().as_uri() + "?mode=ro", uri=True)
    dump(args.out / "sources.json", [json.loads(row[0]) for row in db.execute("SELECT metadata FROM sources ORDER BY id")])
    rows, memberships, populations = [], {}, {}
    for layer in design["layers"]:
        print(f"Loading {layer}", flush=True)
        graph = load_graph(db, layer)
        full_metrics = graph_metrics(graph)
        for domain in design["edge_domains"]:
            domain_view = domain_graph(graph, domain)
            population, components = largest_component(domain_view)
            eligible = domain_view.subgraph(population)
            eligible_metrics = graph_metrics(eligible)
            populations[f"{layer}-{domain}"] = {"components": components, "eligible_nodes": len(population),
                                                "excluded_nodes": sorted(set(graph) - population),
                                                "selection": "largest connected component, ASN tie break"}
            for size in design["sizes"]:
                for seed in design["seeds"]:
                    sample_id = f"{layer}-{domain}-{size}-s{seed}"
                    print(f"Sampling {sample_id}", flush=True)
                    row, members = write_sample(db, args.out / sample_id, graph, eligible, domain, layer, size, seed,
                                                source_hash, full_metrics, eligible_metrics, sampler)
                    rows.append(row)
                    memberships[sample_id] = members
                    print(json.dumps(row), flush=True)
    db.close()
    overlaps = []
    for i, a in enumerate(rows):
        for b in rows[i + 1:]:
            if (a["layer"], a["size"], a["domain"]) == (b["layer"], b["size"], b["domain"]):
                x, y = memberships[a["id"]], memberships[b["id"]]
                overlaps.append({"a": a["id"], "b": b["id"], "intersection": len(x & y), "jaccard": len(x & y) / len(x | y)})
    dump(args.out / "populations.json", populations)
    dump(args.out / "overlaps.json", overlaps)
    csv_write(args.out / "summary.csv", list(rows[0]), rows)
    if sha256(source_path) != source_hash:
        raise ValueError("Source changed during sampling")
    if any(sha256(code_dir / name) != value for name, value in code_hashes.items()):
        raise ValueError("Code changed during sampling")
    dump(args.out / "manifest.json", {"schema": VERSION, "status": "samples_generated_pending_independent_verification",
                                     "created_utc": datetime.now(timezone.utc).isoformat(), "samples": rows,
                                     "source_database_sha256": source_hash, "source_delivery_sha256": sha256(args.data / "delivery-manifest.json"),
                                     "design_sha256": sha256(args.design), "python": sys.version, "platform": platform.platform(),
                                     "networkx": nx.__version__, "command": sys.argv,
                                     "code_sha256": code_hashes,
                                     "artifacts": {p.relative_to(args.out).as_posix(): sha256(p) for p in sorted(args.out.rglob("*")) if p.is_file()}})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--design", type=Path, default=Path(__file__).with_name("sampling_design.json"))
    run(parser.parse_args())
