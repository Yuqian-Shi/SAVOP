"""Independent full-row SQL/CSV verification of generated AS samples.

Does not import the sampling algorithm or its metric functions. Checks graph
facts against the accepted database, including EVERY induced/cut/prefix row.
"""
import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import csv
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys


def hash_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def read_csv(path):
    with Path(path).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def normalize_edge(row):
    return (int(row["u"]), int(row["v"]), row["relation"], int(row["provider"]),
            tuple(json.loads(row["inferred_sources"]) if isinstance(row["inferred_sources"], str) else row["inferred_sources"]),
            tuple(json.loads(row["observed_sources"]) if isinstance(row["observed_sources"], str) else row["observed_sources"]))


def verify(data, samples, out):
    if out.exists():
        raise FileExistsError(out)
    report = {"status": "running", "checks": [], "samples": [], "created_utc": datetime.now(timezone.utc).isoformat()}

    def check(label, truth):
        if not truth:
            raise AssertionError(label)
        report["checks"].append(label)

    source_hash = hash_file(data / "map.sqlite")
    accepted = read_json(data / "delivery-manifest.json")
    batch = read_json(samples / "manifest.json")
    check("source equals accepted database", source_hash == accepted["data_and_evidence_sha256"]["map.sqlite"] == batch["source_database_sha256"])
    check("source acceptance receipt", hash_file(data / "delivery-manifest.json") == batch["source_delivery_sha256"])
    for name, expected in batch["artifacts"].items():
        check("batch artifact: " + name, hash_file(samples / name) == expected)
    code = Path(__file__).parent
    for name, expected in batch["code_sha256"].items():
        snapshot = samples / "code" / name
        if name == "sample_topologies.py" and not snapshot.exists():
            snapshot = samples / "sample_topologies.frozen.py"
        check("sampler code snapshot: " + name, hash_file(snapshot if snapshot.exists() else code / name) == expected)
    for test in ("test_topology.py", "test_sampling.py"):
        proc = subprocess.run([sys.executable, str(code / test)], capture_output=True, text=True)
        check("offline regression: " + test, proc.returncode == 0)
        report[test] = proc.stdout + proc.stderr
    db = sqlite3.connect((data / "map.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    source_nodes, source_edges = {}, {}
    for layer in ("ipv4", "ipv6"):
        source_nodes[layer] = {r["asn"]: dict(r) for r in db.execute("SELECT * FROM nodes WHERE layer=?", (layer,))}
        source_edges[layer] = [normalize_edge(dict(r)) for r in db.execute("SELECT * FROM edges WHERE layer=? ORDER BY u,v", (layer,))]
    design = read_json(samples / "design.json")
    expected_ids = {f"{layer}-{domain}-{size}-s{seed}" for layer in design["layers"] for domain in design["edge_domains"] for size in design["sizes"] for seed in design["seeds"]}
    check("complete design matrix", expected_ids == {r["id"] for r in batch["samples"]} and len(batch["samples"]) == len(expected_ids))
    for entry in batch["samples"]:
        name = entry["id"]
        print("Verifying " + name, flush=True)
        path = samples / name
        sample, quality = read_json(path / "topology.json"), read_json(path / "quality.json")
        ids = {r["asn"] for r in sample["nodes"]}
        layer = sample["layer"]
        check(name + ": exact unique size", len(ids) == len(sample["nodes"]) == sample["size"])
        check(name + ": no nonexistent nodes", ids <= source_nodes[layer].keys())
        expected_internal = {r for r in source_edges[layer] if r[0] in ids and r[1] in ids}
        expected_cut = {r for r in source_edges[layer] if (r[0] in ids) != (r[1] in ids)}
        actual_internal = [normalize_edge(r) for r in sample["edges"]]
        actual_cut_rows = read_csv(path / "boundary.csv")
        actual_cut = [normalize_edge(r) for r in actual_cut_rows]
        check(name + ": all induced edges exact", set(actual_internal) == expected_internal and len(actual_internal) == len(expected_internal))
        check(name + ": all boundary edges exact", set(actual_cut) == expected_cut and len(actual_cut) == len(expected_cut))
        check(name + ": boundary orientation", all(int(r["inside"]) in ids and int(r["outside"]) not in ids and {int(r["inside"]), int(r["outside"])} == {int(r["u"]), int(r["v"])} for r in actual_cut_rows))
        csv_edges = read_csv(path / "edges.csv")
        check(name + ": edge CSV parity", [normalize_edge(r) for r in csv_edges] == actual_internal and all(r["active"] == str(e["active"]) for r, e in zip(csv_edges, sample["edges"])))
        adjacency = {n: set() for n in ids}
        providers, customers, peers, unknown = Counter(), Counter(), Counter(), Counter()
        for r in sample["edges"]:
            should_be_active = sample["edge_domain"] == "union" or r["relation"] in ("p2p", "p2c")
            check(name + f": active edge {r['u']}-{r['v']}", r["active"] == should_be_active)
            if not should_be_active:
                continue
            u, v = r["u"], r["v"]
            adjacency[u].add(v)
            adjacency[v].add(u)
            if r["relation"] == "p2c":
                p = r["provider"]
                c = v if p == u else u
                providers[c] += 1
                customers[p] += 1
            else:
                target = peers if r["relation"] == "p2p" else unknown
                target[u] += 1
                target[v] += 1
        seen, queue = {min(ids)}, [min(ids)]
        for current in queue:
            for nxt in adjacency[current] - seen:
                seen.add(nxt)
                queue.append(nxt)
        check(name + ": independent connectivity", seen == ids)
        for row in sample["nodes"]:
            n = row["asn"]
            check(name + f": source and local attributes AS{n}", all(row[k] == source_nodes[layer][n][k] for k in ("degree", "providers", "customers", "peers", "unknown")) and row["sample_degree"] == len(adjacency[n]) and row["sample_providers"] == providers[n] and row["sample_customers"] == customers[n] and row["sample_peers"] == peers[n] and row["sample_unknown"] == unknown[n])
        check(name + ": endpoint conservation", sum(source_nodes[layer][n]["degree"] for n in ids) == 2 * len(expected_internal) + len(expected_cut))
        expected_prefixes = set()
        for n in ids:
            expected_prefixes.update((n, r[0], r[1]) for r in db.execute("SELECT prefix,source FROM prefixes WHERE layer=? AND asn=?", (layer, n)))
        prefix_csv = read_csv(path / "prefixes.csv")
        check(name + ": complete prefix provenance", len(prefix_csv) == len(expected_prefixes) and {(int(r["asn"]), r["prefix"], r["source"]) for r in prefix_csv} == expected_prefixes)
        prefix_sets = defaultdict(set)
        for a, p, _ in expected_prefixes:
            prefix_sets[a].add(p)
        check(name + ": per-AS prefix counts", all(row["observed_prefix_count"] == len(prefix_sets[row["asn"]]) for row in sample["nodes"]))
        observed_hops = Counter()
        for start in sorted(ids):
            dist, todo = {start: 0}, deque([start])
            while todo:
                current = todo.popleft()
                for nxt in adjacency[current]:
                    if nxt not in dist:
                        dist[nxt] = dist[current] + 1
                        todo.append(nxt)
            observed_hops.update(d for dst, d in dist.items() if start < dst)
        active_metrics = quality["active_graph"]
        check(name + ": independent all-pair hops", dict(observed_hops) == {int(k): v for k, v in active_metrics["undirected_adjacency_hops_unordered_pairs"].items()})
        check(name + ": independent degree distribution", dict(Counter(len(v) for v in adjacency.values())) == {int(k): v for k, v in active_metrics["degree_histogram"].items()})
        check(name + ": retained multi-upstream count", sum(providers[n] >= 2 for n in ids) == active_metrics["inferred_multi_upstream_in_this_graph"])
        if "motif_anchors" in sample["sampling"]:
            anchors = sample["sampling"]["motif_anchors"]
            check(name + ": motif coverage target", len(anchors) == sample["size"] // 10 and len({a["asn"] for a in anchors}) == len(anchors))
            for a in anchors:
                check(name + f": motif providers AS{a['asn']}", len(set(a["providers"])) == 2 and all(any(r[0:2] == tuple(sorted((a["asn"], p))) and r[2] == "p2c" and r[3] == p for r in expected_internal) for p in a["providers"]))
        report["samples"].append({"id": name, "nodes": len(ids), "union_induced_edges": len(expected_internal), "cut_edges": len(expected_cut), "prefix_rows": len(expected_prefixes), "status": "passed"})
    db.close()
    check("source unchanged after verification", hash_file(data / "map.sqlite") == source_hash)
    report["status"] = "passed_structural_data_only"
    report["not_proven"] = ["scientific representativeness", "routing policy correctness", "packet filtering", "1000-AS runtime performance"]
    report["verifier_sha256"] = hash_file(Path(__file__))
    report["batch_manifest_sha256"] = hash_file(samples / "manifest.json")
    with out.open("x", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "samples": len(report["samples"])}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    verify(args.data, args.samples, args.out)
