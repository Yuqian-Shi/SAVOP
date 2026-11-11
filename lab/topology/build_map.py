"""Build an attributed AS map from immutable, hashed public inputs.

This is an offline data preparation tool, not the Rust simulation runtime.
Neither graph connectivity nor observed AS_PATHs prove forwarding reachability.
"""
import argparse
import bz2
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
from importlib.metadata import version
import ipaddress
import json
from pathlib import Path
import platform
import re
import sqlite3
import struct
import sys

import networkx as nx
from pybgpkit_parser import RouteParser
from fetch_sources import sha256


SCHEMA = """
CREATE TABLE sources(id TEXT PRIMARY KEY, metadata TEXT NOT NULL);
CREATE TABLE claims(layer TEXT, u INTEGER, v INTEGER, relation TEXT, provider INTEGER,
 source TEXT, line INTEGER, step TEXT, PRIMARY KEY(layer,u,v,relation,provider,source));
CREATE TABLE observations(layer TEXT, u INTEGER, v INTEGER, source TEXT,
 route_count INTEGER, example_path TEXT, example_prefix TEXT,
 PRIMARY KEY(layer,u,v,source));
CREATE TABLE paths(layer TEXT, source TEXT, peer_asn INTEGER, peer_ip TEXT,
 path TEXT, route_count INTEGER, example_prefix TEXT,
 PRIMARY KEY(layer,source,peer_asn,peer_ip,path));
CREATE TABLE prefixes(layer TEXT, asn INTEGER, prefix TEXT, source TEXT,
 PRIMARY KEY(layer,asn,prefix,source));
CREATE TABLE peers(source TEXT, peer_asn INTEGER, peer_ip TEXT, layer TEXT,
 route_count INTEGER, PRIMARY KEY(source,peer_asn,peer_ip,layer));
CREATE TABLE edges(layer TEXT,u INTEGER,v INTEGER,relation TEXT,provider INTEGER,
 inferred_sources TEXT,observed_sources TEXT,PRIMARY KEY(layer,u,v));
CREATE TABLE nodes(layer TEXT,asn INTEGER,degree INTEGER,providers INTEGER,customers INTEGER,
 peers INTEGER,unknown INTEGER,PRIMARY KEY(layer,asn));
CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT);
"""


def dump(path, obj):
    with Path(path).open("x", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)


def public_asn(asn):
    # Do not silently turn private/test/AS_TRANS/zero values into public AS nodes.
    return (0 < asn < 4294967295 and asn not in (23456, 65535)
            and not 64496 <= asn <= 65534
            and not 65536 <= asn <= 65551 and not 4200000000 <= asn)


def normalize_path(text):
    if not text:
        return None, "empty_path"
    # Reject sets/confederations as ambiguous rather than inventing adjacencies.
    if not re.fullmatch(r"\d+(?:\s+\d+)*", text.strip()):
        return None, "set_confederation_or_nonsequence"
    seq = []
    for item in text.split():
        asn = int(item)
        if not public_asn(asn):
            return None, "nonpublic_or_reserved_asn"
        if not seq or seq[-1] != asn:
            seq.append(asn)
    if len(set(seq)) != len(seq):
        return None, "nonconsecutive_as_loop"
    return tuple(seq), None


def parse_rel(path):
    opener = bz2.open if str(path).endswith(".bz2") else open
    counts = Counter()
    records = {}
    rejected = []
    step = "not_recorded"
    headers = []
    with opener(path, "rt", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, 1):
            text = raw.strip()
            if not text:
                counts["blank"] += 1
                continue
            if text.startswith("#"):
                headers.append(text)
                if text.startswith("# step"):
                    step = text
                continue
            counts["rows"] += 1
            fields = text.split("|")
            reason = None
            try:
                if len(fields) != 3:
                    raise ValueError("field_count")
                a, b, rel = map(int, fields)
                if rel not in (-1, 0):
                    raise ValueError("unsupported_relation")
                if not public_asn(a) or not public_asn(b):
                    raise ValueError("nonpublic_or_reserved_asn")
                if a == b:
                    raise ValueError("self_loop")
            except ValueError as e:
                reason = str(e)
            if reason:
                counts["rejected"] += 1
                rejected.append({"line": lineno, "text": text, "reason": reason})
                continue
            u, v = sorted((a, b))
            key = (u, v, "p2c" if rel == -1 else "p2p", a if rel == -1 else 0)
            if key in records:
                counts["duplicate_claims"] += 1
            else:
                records[key] = (lineno, step)
            counts["p2c_rows" if rel == -1 else "p2p_rows"] += 1
    counts["unique_claims"] = len(records)
    return records, {"counts": dict(counts), "rejected": rejected, "headers": headers}


def inspect_mrt(path):
    """Check full gzip CRC and MRT framing, independently count RIB entries."""
    types = Counter()
    entries = 0
    with gzip.open(path, "rb") as f:
        while True:
            header = f.read(12)
            if not header:
                break
            if len(header) != 12:
                raise ValueError("Truncated MRT header")
            timestamp, typ, subtype, size = struct.unpack("!IHHI", header)
            if size > 64 * 1024 * 1024:
                raise ValueError("Implausible MRT record length")
            payload = f.read(size)
            if len(payload) != size:
                raise ValueError("Truncated MRT payload")
            types[f"{typ}/{subtype}"] += 1
            if typ == 13 and subtype == 1:  # PEER_INDEX_TABLE
                continue
            if typ != 13 or subtype not in (2, 4):
                raise ValueError(f"Unvalidated MRT subtype {typ}/{subtype}")
            if size < 7:
                raise ValueError("Short RIB record")
            prefixlen = payload[4]
            if prefixlen > (32 if subtype == 2 else 128):
                raise ValueError("Invalid RIB prefix length")
            pos = 5 + (prefixlen + 7) // 8
            if pos + 2 > size:
                raise ValueError("Missing RIB entry count")
            num = struct.unpack_from("!H", payload, pos)[0]
            pos += 2
            # Each standard TABLE_DUMP_V2 entry: peer index, time, attr length.
            for _ in range(num):
                if pos + 8 > size:
                    raise ValueError("Truncated RIB entry")
                attrlen = struct.unpack_from("!H", payload, pos + 6)[0]
                pos += 8 + attrlen
                if pos > size:
                    raise ValueError("Truncated RIB attributes")
            if pos != size:
                raise ValueError("Trailing RIB payload bytes")
            entries += num
    return {"record_types": dict(types), "expected_rib_entries": entries,
            "gzip_crc_and_mrt_framing": "passed"}


def ingest_mrt(db, path, source):
    integrity = inspect_mrt(path)
    routes, peers, paths = Counter(), Counter(), Counter()
    examples, origins, normalize_cache, reject_examples = {}, set(), {}, []
    fields = ["peer_asn", "peer_ip", "prefix", "as_path"]
    for batch in RouteParser(str(path)).iter_tuple_batches(fields, batch_size=10000):
        for peer, peer_ip, prefix, raw_path in batch:
            routes["parsed"] += 1
            layer = "ipv6" if ":" in prefix else "ipv4"
            peers[(peer, peer_ip, layer)] += 1
            if raw_path not in normalize_cache:
                normalize_cache[raw_path] = normalize_path(raw_path)
            seq, reason = normalize_cache[raw_path]
            if reason:
                routes["excluded_" + reason] += 1
                if len(reject_examples) < 50:
                    reject_examples.append({"prefix": prefix, "path": raw_path, "reason": reason})
                continue
            ipaddress.ip_network(prefix, strict=True)
            routes["accepted"] += 1
            p = " ".join(map(str, seq))
            key = (layer, source, peer, peer_ip, p)
            paths[key] += 1
            examples.setdefault(key, prefix)
            origins.add((layer, seq[-1], prefix, source))
        if routes["parsed"] % 1000000 == 0:
            print(f"{source}: parsed {routes['parsed']:,} RIB entries", flush=True)
    if routes["parsed"] != integrity["expected_rib_entries"]:
        raise ValueError(f"MRT parser lost entries: {routes['parsed']} != {integrity}")
    if not routes["accepted"]:
        raise ValueError("No usable RIB paths")
    obs, obs_examples = Counter(), {}
    for key, count in paths.items():
        layer, _, peer, peer_ip, p = key
        seq = list(map(int, p.split()))
        for a, b in zip(seq, seq[1:]):
            u, v = sorted((a, b))
            ekey = (layer, u, v, source)
            obs[ekey] += count
            obs_examples.setdefault(ekey, (p, examples[key]))
    db.executemany("INSERT INTO paths VALUES(?,?,?,?,?,?,?)", ((*key, count, examples[key]) for key, count in sorted(paths.items())))
    db.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?,?)", ((*key, count, *obs_examples[key]) for key, count in sorted(obs.items())))
    db.executemany("INSERT INTO prefixes VALUES(?,?,?,?)", sorted(origins))
    db.executemany("INSERT INTO peers VALUES(?,?,?,?,?)", ((source, *key, count) for key, count in sorted(peers.items())))
    db.commit()
    return {"integrity": integrity, "routes": dict(routes), "unique_peer_path_rows": len(paths),
            "prefix_origin_rows": len(origins), "edge_source_rows": len(obs),
            "peer_af_rows": len(peers), "exclusion_examples": reject_examples,
            "note": "RIB route multiplicity is not independent evidence; collectors/peers have visibility bias."}


def materialize(db, layer):
    g = nx.Graph()
    rels, inferred, observed = defaultdict(set), defaultdict(set), defaultdict(set)
    for u, v, relation, provider, source in db.execute("SELECT u,v,relation,provider,source FROM claims WHERE layer=?", (layer,)):
        g.add_edge(u, v)
        rels[(u, v)].add((relation, provider))
        inferred[(u, v)].add(source)
    for u, v, source in db.execute("SELECT u,v,source FROM observations WHERE layer=?", (layer,)):
        g.add_edge(u, v)
        observed[(u, v)].add(source)
    # Single-AS paths still contribute nodes; do not drop isolates.
    g.add_nodes_from(row[0] for row in db.execute("SELECT DISTINCT asn FROM prefixes WHERE layer=?", (layer,)))
    degree = dict(g.degree())
    roles = defaultdict(Counter)
    counts = Counter()
    for u, v in sorted(tuple(sorted(e)) for e in g.edges):
        claims = rels.get((u, v), set())
        if len(claims) == 1:
            relation, provider = next(iter(claims))
        else:
            relation, provider = ("conflict" if claims else "unknown"), 0
        counts[relation] += 1
        if relation == "p2c":
            customer = v if provider == u else u
            roles[provider]["customers"] += 1
            roles[customer]["providers"] += 1
        else:
            for asn in (u, v):
                roles[asn]["peers" if relation == "p2p" else "unknown"] += 1
        ins, obs = sorted(inferred[(u, v)]), sorted(observed[(u, v)])
        counts["inferred_and_observed" if ins and obs else "inferred_only" if ins else "observed_only"] += 1
        db.execute("INSERT INTO edges VALUES(?,?,?,?,?,?,?)", (layer, u, v, relation, provider, json.dumps(ins), json.dumps(obs)))
    db.executemany("INSERT INTO nodes VALUES(?,?,?,?,?,?,?)", ((layer, asn, degree[asn], roles[asn]["providers"], roles[asn]["customers"], roles[asn]["peers"], roles[asn]["unknown"]) for asn in sorted(g)))
    components = sorted((len(c) for c in nx.connected_components(g)), reverse=True)
    hist = dict(sorted(Counter(degree.values()).items()))
    db.commit()
    return {"nodes": len(g), "edges": g.number_of_edges(), "relations_and_evidence": dict(counts),
            "connected_components": len(components), "component_sizes": components,
            "isolates": sum(d == 0 for d in degree.values()), "degree_histogram": hist,
            "as_with_two_or_more_inferred_providers": sum(roles[n]["providers"] >= 2 for n in g),
            "highest_degree": sorted(degree.items(), key=lambda x: (-x[1], x[0]))[:20],
            "meaning": "Undirected adjacency connectivity, not BGP-policy or data-plane reachability."}


def build(args):
    # An incomplete run is preserved. Use a new output path instead of replacing it.
    if args.out.exists():
        raise FileExistsError(f"Output already exists: {args.out}")
    sources = []
    config = json.loads(args.config.read_text(encoding="utf-8"))
    for item in config["sources"]:
        source_dir = args.raw / item["id"]
        record = json.loads((source_dir / "source.json").read_text(encoding="utf-8"))
        path = source_dir / record["file"]
        if record["url"] != item["url"] or sha256(path) != record["sha256"]:
            raise ValueError(f"Source mismatch: {item['id']}")
        sources.append((record, path))
    old_hash = sha256(args.historical)
    args.out.mkdir(parents=True)
    db = sqlite3.connect(args.out / "map.sqlite")
    db.executescript(SCHEMA)
    report = {"schema_version": 1, "built_utc": datetime.now(timezone.utc).isoformat(),
              "snapshot_date": config["snapshot_date"], "source_checks": {}, "layers": {},
              "limitations": ["公开观测与关系推断的组合，不是完整互联网真值或物理地图。",
              "CAIDA也使用RIS/RouteViews；来源吻合不是完全独立验证。",
              "两台RIS采集器的多个对等体仍存在观测偏差；未见连接不等于不存在。",
              "p2c方向表示提供商到客户关系，不表示只能单向转发。",
              "不包含完整路由策略、真实带宽/时延、SAV部署或Anycast站点。",
              "查询邻域和最短连接路径不是BGP路由推演；未生成实验子图或实验配置。"],
              "environment": {"python": sys.version, "platform": platform.platform(),
              "networkx": nx.__version__, "pybgpkit-parser": version("pybgpkit-parser")}}
    old_records, old_stats = parse_rel(args.historical)
    historical_source = {"id": "local-20230801", "kind": "as_rel", "date": "2023-08-01",
                         "date_basis": "filename until upstream comparison", "path": str(args.historical.resolve()),
                         "sha256": old_hash, "semantics": "historical_unverified_relationship"}
    db.execute("INSERT INTO sources VALUES(?,?)", (historical_source["id"], json.dumps(historical_source)))
    db.executemany("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?)", (("historical", *key, "local-20230801", *value) for key, value in sorted(old_records.items())))
    report["source_checks"]["local-20230801"] = old_stats
    for record, path in sources:
        source = record["id"]
        print(f"Importing {source}", flush=True)
        db.execute("INSERT INTO sources VALUES(?,?)", (source, json.dumps(record, ensure_ascii=False)))
        if record["kind"] in ("as_rel", "historical_reference"):
            records, stats = parse_rel(path)
            report["source_checks"][source] = stats
            if record["kind"] == "historical_reference":
                upstream, local = set(records), set(old_records)
                report["historical_comparison"] = {"same_normalized_claims": upstream == local,
                    "upstream_only": len(upstream - local), "local_only": len(local - upstream),
                    "note": "Canonical relation equality does not prove how the old file was originally obtained."}
            else:
                if not records:
                    raise ValueError("Empty CAIDA graph")
                db.executemany("INSERT INTO claims VALUES(?,?,?,?,?,?,?,?)", ((record["af"], *key, source, *value) for key, value in sorted(records.items())))
        elif record["kind"] == "mrt":
            report["source_checks"][source] = ingest_mrt(db, path, source)
        db.commit()
    for layer in ("historical", "ipv4", "ipv6"):
        print(f"Computing {layer} graph quality", flush=True)
        report["layers"][layer] = materialize(db, layer)
    db.executescript("""
    CREATE INDEX edges_v ON edges(layer,v);
    CREATE INDEX claims_v ON claims(layer,v);
    CREATE INDEX obs_v ON observations(layer,v);
    CREATE INDEX prefixes_asn ON prefixes(layer,asn);
    CREATE INDEX nodes_degree ON nodes(layer,degree DESC,asn);
    """)
    if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("SQLite integrity check failed")
    if sha256(args.historical) != old_hash:
        raise ValueError("Historical source changed during build")
    db.execute("INSERT INTO metadata VALUES(?,?)", ("quality", json.dumps(report, ensure_ascii=False)))
    db.commit()
    db.close()
    dump(args.out / "quality.json", report)
    code_dir = Path(__file__).parent
    manifest = {"schema_version": 1, "status": "complete", "built_utc": report["built_utc"],
                "sources": [r for r, _ in sources] + [historical_source],
                "artifacts": {p.name: sha256(p) for p in args.out.iterdir() if p.is_file()},
                "code_sha256": {p.name: sha256(p) for p in code_dir.iterdir() if p.suffix in (".py", ".json", ".txt", ".html", ".js", ".css")},
                "command": sys.argv}
    dump(args.out / "manifest.json", manifest)
    print(json.dumps({"status": "complete", "out": str(args.out), "layers": {k: {f: v[f] for f in ("nodes", "edges", "connected_components")} for k, v in report["layers"].items()}}, ensure_ascii=False), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", type=Path, default=Path(__file__).with_name("sources.json"))
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--historical", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    build(ap.parse_args())


if __name__ == "__main__":
    main()
