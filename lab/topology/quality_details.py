"""Additional observational diagnostics; do not infer BGP/data-plane reachability."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
import json
from pathlib import Path

from build_map import dump
from fetch_sources import sha256
from serve_map import connect


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data",type=Path,required=True)
    ap.add_argument("--raw",type=Path,required=True)
    args=ap.parse_args()
    result={"database_sha256":sha256(args.data/"map.sqlite"),"layers":{},"policy_documents":[],
            "unmeasured":{"policy_constrained_reachability":"not_computed; requires routing policy and execution model",
                          "actual_forwarding_reachability":"not_measured",
                          "complete_prefix_propagation_scope":"unknown; limited to chosen public observers",
                          "anycast_or_SAV_deployment":"unknown; not inferred from topology or MOAS"}}
    with closing(connect(args.data/"map.sqlite")) as db:
        for layer in ("ipv4","ipv6"):
            weighted,peer_paths=Counter(),Counter()
            for path,count in db.execute("SELECT path,route_count FROM paths WHERE layer=?",(layer,)):
                hops=len(path.split())-1
                weighted[hops]+=count; peer_paths[hops]+=1
            totals=db.execute("SELECT COUNT(DISTINCT prefix),COUNT(DISTINCT asn) FROM prefixes WHERE layer=?",(layer,)).fetchone()
            multiple=db.execute("SELECT COUNT(*) FROM (SELECT prefix FROM prefixes WHERE layer=? GROUP BY prefix HAVING COUNT(DISTINCT asn)>1)",(layer,)).fetchone()[0]
            per_source=[dict(r) for r in db.execute("SELECT source,COUNT(DISTINCT peer_asn) peer_asns,COUNT(DISTINCT peer_ip) peer_ips,SUM(route_count) rib_entries FROM peers WHERE layer=? GROUP BY source",(layer,))]
            result["layers"][layer]={"observed_unique_prefixes":totals[0],"observed_origin_asns":totals[1],
                "multi_origin_prefixes":multiple,"multi_origin_note":"Observed multiple origin ASNs, not proof of Anycast or a hijack.",
                "normalized_path_hops_route_weighted":dict(sorted(weighted.items())),
                "normalized_path_hops_peer_path_rows":dict(sorted(peer_paths.items())),
                "path_length_note":"Hop count = deduplicated AS sequence length - 1; route-weighted distribution repeats routes across observers, not independent samples.",
                "collectors":per_source}
    for source in json.loads(Path(__file__).with_name("policy_sources.json").read_text(encoding="utf-8"))["sources"]:
        folder=args.raw/source["id"]
        record=json.loads((folder/"source.json").read_text(encoding="utf-8"))
        if sha256(folder/record["file"])!=record["sha256"]:
            raise ValueError("Policy document changed")
        result["policy_documents"].append(record)
    dump(args.data/"quality-details.json",result)
    print(json.dumps({"status":"complete","quality_details":str(args.data/"quality-details.json")}))


if __name__=="__main__":
    main()
