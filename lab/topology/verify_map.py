"""Read-only independent audits of inputs, graph materialization and HTTP exports."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
import csv
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from build_map import parse_rel, dump
from fetch_sources import sha256
from serve_map import connect, neighborhood


def verify(args):
    start = time.monotonic()
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    quality = json.loads((args.data / "quality.json").read_text(encoding="utf-8"))
    checks = []
    def check(name, condition, detail=None):
        if not condition:
            raise AssertionError(f"{name}: {detail}")
        checks.append({"name": name, "passed": True, "detail": detail})

    check("complete_manifest", manifest["status"] == "complete")
    for name, expected in manifest["artifacts"].items():
        check("artifact_hash:" + name, sha256(args.data / name) == expected)
    for s in manifest["sources"]:
        path = Path(s["path"]) if s["id"] == "local-20230801" else args.raw / s["id"] / s["file"]
        check("source_hash:" + s["id"], sha256(path) == s["sha256"])
    result = subprocess.run([sys.executable, str(Path(__file__).with_name("test_topology.py"))], capture_output=True, text=True)
    check("offline_regressions", result.returncode == 0, result.stdout + result.stderr)
    with closing(connect(args.data / "map.sqlite")) as db:
        check("sqlite_integrity", db.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
        for layer, source in (("ipv4","caida-20261001-v4"),("ipv6","caida-20261001-v6"),("historical","local-20230801")):
            src = next(s for s in manifest["sources"] if s["id"] == source)
            path = Path(src["path"]) if layer == "historical" else args.raw/source/src["file"]
            records, stats = parse_rel(path)
            stored = {tuple(r) for r in db.execute("SELECT u,v,relation,provider FROM claims WHERE layer=? AND source=?",(layer,source))}
            check("all_source_claims:" + layer, set(records) == stored, len(stored))
        for layer in ("historical","ipv4","ipv6"):
            expected = quality["layers"][layer]
            adjacency, roles = defaultdict(set), defaultdict(Counter)
            relation_count, evidence_count = Counter(), Counter()
            for row in db.execute("SELECT * FROM edges WHERE layer=?",(layer,)):
                u,v,r,p = row["u"],row["v"],row["relation"],row["provider"]
                assert u < v
                adjacency[u].add(v); adjacency[v].add(u)
                relation_count[r] += 1
                ins,obs=json.loads(row["inferred_sources"]),json.loads(row["observed_sources"])
                assert ins or obs
                evidence_count["inferred_and_observed" if ins and obs else "inferred_only" if ins else "observed_only"] += 1
                if r=="p2c":
                    assert p in (u,v)
                    roles[p]["customers"] += 1
                    roles[v if p==u else u]["providers"] += 1
                else:
                    for asn in (u,v): roles[asn]["peers" if r=="p2p" else "unknown"] += 1
            nodes=list(db.execute("SELECT * FROM nodes WHERE layer=?",(layer,)))
            for n in nodes:
                adjacency[n["asn"]]  # retain isolates
                assert n["degree"] == len(adjacency[n["asn"]])
                for key in ("providers","customers","peers","unknown"):
                    assert n[key] == roles[n["asn"]][key]
            remaining=set(adjacency); components=[]
            while remaining:
                root=min(remaining); remaining.remove(root); stack=[root]; size=0
                while stack:
                    n=stack.pop(); size+=1
                    new=adjacency[n]&remaining; remaining-=new; stack.extend(new)
                components.append(size)
            check("independent_nodes_degrees_roles_components:"+layer,
                  len(nodes)==expected["nodes"] and sum(map(len,adjacency.values()))//2==expected["edges"]
                  and sorted(components,reverse=True)==expected["component_sizes"],
                  {"nodes":len(nodes),"edges":expected["edges"],"components":len(components)})
            check("evidence_counts:"+layer, dict(relation_count+evidence_count)==expected["relations_and_evidence"])
            check("prefix_origin_nodes_present:"+layer, db.execute("SELECT COUNT(*) FROM prefixes p LEFT JOIN nodes n ON p.layer=n.layer AND p.asn=n.asn WHERE p.layer=? AND n.asn IS NULL",(layer,)).fetchone()[0]==0)
        # Reconstruct every observed edge count from stored peer-specific paths,
        # rather than trusting the precomputed observations table.
        for source in ("ris-rrc06-20261001","ris-rrc11-20261001"):
            count=Counter(); accepted=0
            for r in db.execute("SELECT layer,path,route_count FROM paths WHERE source=?",(source,)):
                seq=list(map(int,r["path"].split())); accepted+=r["route_count"]
                assert len(seq)==len(set(seq))
                for a,b in zip(seq,seq[1:]): count[(r["layer"],*sorted((a,b)))]+=r["route_count"]
            actual={tuple(r[:3]):r[3] for r in db.execute("SELECT layer,u,v,route_count FROM observations WHERE source=?",(source,))}
            check("all_path_edges:"+source, dict(count)==actual, len(actual))
            q=quality["source_checks"][source]
            check("route_accounting:"+source, accepted==q["routes"]["accepted"] and q["routes"]["parsed"]==q["integrity"]["expected_rib_entries"]
                  and accepted+sum(v for k,v in q["routes"].items() if k.startswith("excluded_"))==q["routes"]["parsed"],q["routes"])
        # Test live endpoints, including limits, full exports and failure modes.
        timings={}
        for layer in ("historical","ipv4","ipv6"):
            begin=time.monotonic()
            with urlopen(args.url+f"/api/graph?layer={layer}&asn=4134&hops=2&limit=80",timeout=30) as response:
                live=json.load(response)
            timings[layer]=round(time.monotonic()-begin,3)
            check("http_graph:"+layer,live==neighborhood(db,layer,4134,2,80))
            with urlopen(args.url+f"/api/export?layer={layer}",timeout=60) as response:
                reader=csv.reader(io.TextIOWrapper(response,encoding="utf-8-sig",newline=""))
                header=next(reader); count=0
                for row in reader:
                    assert len(row)==7 and row[0]==layer
                    assert int(row[1])<int(row[2])
                    json.loads(row[5]);json.loads(row[6]);count+=1
            check("full_csv_export:"+layer,count==quality["layers"][layer]["edges"],count)
        for suffix,code in (("/api/graph?asn=0",400),("/api/graph?asn=4134&limit=10000",400),("/api/graph?asn=4134&layer=garbage",400),("/../sources.json",404)):
            try:
                urlopen(args.url+suffix,timeout=10)
                check("reject:"+suffix,False)
            except HTTPError as e:
                check("reject:"+suffix,e.code==code)
        try:
            urlopen(Request(args.url+"/api/summary",headers={"Host":"untrusted.example"}),timeout=10)
            check("host_rebinding_rejected",False)
        except HTTPError as e:
            check("host_rebinding_rejected",e.code==403)
    outcome={"status":"passed","time_utc":datetime.now(timezone.utc).isoformat(),"checks":checks,
             "http_graph_roundtrip_seconds":timings,"elapsed_seconds":round(time.monotonic()-start,3),
             "current_code_sha256":{p.name:sha256(p) for p in Path(__file__).parent.iterdir() if p.suffix in (".py",".json",".txt",".html",".js",".css",".ps1")},
             "scope":"Data ingestion, attribution, graph quality and local explorer; not proof of Internet completeness, routing policy or SAV correctness."}
    dump(args.out,outcome)
    print(json.dumps({"status":"passed","checks":len(checks),"http_graph_roundtrip_seconds":timings,"output":str(args.out)}),flush=True)


if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data",type=Path,required=True)
    ap.add_argument("--raw",type=Path,required=True)
    ap.add_argument("--url",default="http://127.0.0.1:18765")
    ap.add_argument("--out",type=Path,required=True)
    verify(ap.parse_args())
