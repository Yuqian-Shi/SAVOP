"""Convert an attributed sample into explicit, isolated SAVOP experiment inputs.

Public ASN/prefix observations stay as provenance. Execution uses private ASNs
and separate laboratory prefixes. A compiled scene is NOT a deployment result.
"""
import argparse
from collections import deque
from copy import deepcopy
import ipaddress
import json
from pathlib import Path
import shutil

from fetch_sources import sha256
from sample_topologies import dump, digest


MODEL = "customer-provider-v1"


def compile_sample(sample):
    if sample.get("schema") != "k5-topology-sample-v1" or sample.get("layer") not in ("ipv4", "ipv6"):
        raise ValueError("Unsupported topology schema/layer")
    nodes = sample["nodes"]
    by_asn = {n["asn"]: n for n in nodes}
    if len(by_asn) != len(nodes) or len(nodes) != sample["size"] or not 5 <= len(nodes) <= 4000:
        raise ValueError("Need 5..4000 unique ASes matching declared size")
    if any(type(n) is not int or not 0 < n < 4294967295 for n in by_asn):
        raise ValueError("Invalid source AS number")
    version = 4 if sample["layer"] == "ipv4" else 6
    mapping, devices = {}, {}
    for i, asn in enumerate(sorted(by_asn), 1):
        prefix = str(ipaddress.ip_network((int(ipaddress.ip_address("198.18.0.0")) + i * 16, 28))) if version == 4 else f"fd42:2400:{i:x}::/64"
        mapping[asn] = {"node_id": str(i), "source_asn": asn, "lab_asn": 4200000000 + i,
                        "lab_prefix": prefix, "test_address": str(ipaddress.ip_network(prefix).network_address + 1),
                        "source_role": by_asn[asn]["full_role"], "source_degree": by_asn[asn]["degree"],
                        "sample_degree": by_asn[asn]["sample_degree"]}
        devices[str(i)] = {"as": 4200000000 + i, "prefixes": {prefix: {}}, "source_asn": asn}
    links, relations, inactive = [], [], []
    seen, adjacency, providers = set(), {n: set() for n in by_asn}, {n: set() for n in by_asn}
    for edge in sample["edges"]:
        u, v = edge["u"], edge["v"]
        if u not in by_asn or v not in by_asn or u >= v or (u, v) in seen:
            raise ValueError("Bad, duplicate or noncanonical edge")
        seen.add((u, v))
        if type(edge.get("active")) is not bool:
            raise ValueError("Each edge needs explicit boolean activity")
        if not edge["active"]:
            if edge["relation"] not in ("unknown", "conflict"):
                raise ValueError("Known relationship unexpectedly disabled")
            inactive.append(edge)
            continue
        if edge["relation"] not in ("p2p", "p2c"):
            raise ValueError("Cannot compile unknown/conflicting active relationships")
        if edge["relation"] == "p2c" and edge["provider"] not in (u, v):
            raise ValueError("Provider outside relationship endpoints")
        a, b = mapping[u]["node_id"], mapping[v]["node_id"]
        links.append([a, b, "dsav"])
        relations.append({"a": a, "b": b, "relationship": edge["relation"],
                          "provider": mapping[edge["provider"]]["node_id"] if edge["relation"] == "p2c" else None})
        adjacency[u].add(v)
        adjacency[v].add(u)
        if edge["relation"] == "p2c":
            p = edge["provider"]
            providers[v if p == u else u].add(p)
    reached, queue = {min(by_asn)}, deque([min(by_asn)])
    while queue:
        for n in adjacency[queue.popleft()] - reached:
            reached.add(n)
            queue.append(n)
    if reached != set(by_asn):
        raise ValueError("Active graph is disconnected")
    base = {"devices": devices, "links": links, "auto_ip_version": version,
            "routing_policy": {"model": MODEL, "links": relations},
            "sav_apps": ["strict_urpf", "loose_urpf", "fp_urpf"], "active_sav_app": "strict_urpf",
            "enable_rpki": False, "prefix_method": "blackhole",
            "ignore_nets": ["10.0.0.0/8"] if version == 4 else ["fec::/16"],
            "k5_metadata": {"source_sample_digest": digest(sample), "schema": "k5-scenario-v1",
                            "requires_generator_policy": MODEL, "deployment_status": "not_run",
                            "isolation_required": "No external eBGP or data-plane uplink; deny experiment traffic on management network."}}
    low = min(by_asn, key=lambda n: (len(adjacency[n]), n))
    high = min(by_asn, key=lambda n: (-len(adjacency[n]), n))
    multihomed = sorted(n for n in by_asn if len(providers[n]) >= 2)
    placements = [("low_degree", low), ("high_degree", high)]
    if multihomed:
        placements.append(("multi_upstream", multihomed[0]))

    def deployment_arms(selected, purpose):
        selected = sorted(set(selected))
        targets = [{"node_id": mapping[asn]["node_id"], "lab_asn": mapping[asn]["lab_asn"],
                    "ingress_interfaces": ["eth_" + mapping[peer]["node_id"] for peer in sorted(adjacency[asn])]}
                   for asn in selected]
        arms = [{"id": "no-sav", "mechanism": None, "targets": [], "deployment_fraction": 0,
                 "verification": "Disable SAV on every node and verify no SAV table exists; app selection alone is insufficient."}]
        for mechanism in ("strict_urpf", "loose_urpf"):
            arms.append({"id": purpose + "-" + mechanism, "mechanism": mechanism,
                         "targets": deepcopy(targets), "deployment_fraction": len(selected) / len(nodes),
                         "purpose": purpose, "placement_basis": "explicit synthetic experimental treatment, not inferred Internet deployment",
                         "verification": "Install on targets only; inspect family rules, actual nft state and legal/spoof packet counters."})
        return arms

    cases = []
    for position, victim in placements:
        others = sorted(set(by_asn) - {victim})
        attacker, reflector = others[:2]
        cases.append({"id": "placement-" + position, "mode": "unicast", "victim": mapping[victim],
                      "attacker": mapping[attacker], "reflector": mapping[reflector],
                      "selection_basis": "deterministic structural boundary case, not population-random victim",
                      "controlled_factors": {"topology": "fixed", "prefixes_per_as": 1, "deployment": "explicit_per_arm",
                                             "traffic_rate": "not_scheduled", "packet_generation": "not_run"},
                      "deployment_arms": deployment_arms([victim], "victim_ingress")})
    if multihomed:
        anchor = multihomed[0]
        cases.append({"id": "multihoming", "mode": "multihoming", "origin": mapping[anchor],
                      "provider_nodes": [mapping[p] for p in sorted(providers[anchor])],
                      "purpose": "Evaluate legitimate ingress alternatives and selected-route asymmetry, not Anycast.",
                      "deployment_arms": deployment_arms(providers[anchor], "provider_ingress"),
                      "events": "withdrawal/asymmetry variants require separate explicit schedules and runtime verification"})
    # Explicit multiple-origin laboratory Anycast, not inferred from public MOAS.
    first, second = sorted(by_asn)[0], sorted(by_asn)[-1]
    anycast_prefix = "198.19.255.0/28" if version == 4 else "fd42:2400:ffff::/64"
    cases.append({"id": "anycast-two-origins", "mode": "anycast", "origin_nodes": [mapping[first], mapping[second]],
                  "prefix": anycast_prefix, "test_address": str(ipaddress.ip_network(anycast_prefix).network_address + 1),
                  "purpose": "Explicit two-AS advertisement of one lab prefix; actual path/site selection must be measured.",
                  "deployment_arms": deployment_arms([first, second], "anycast_site_ingress"),
                  "configuration_origin": "synthetic scenario, not observation of deployed Anycast"})
    return base, {"schema": "k5-scenario-v1", "mapping": list(mapping.values()), "cases": cases,
                  "deployment_contract": {"default": "no installed SAV anywhere", "data_plane_auto": False,
                                          "control_access": "namespace-local loopback only; no public listener",
                                          "enable": {"method": "POST", "path": "/enable_sav_table", "body": {"active_app": "<arm.mechanism>", "dry_run": False}},
                                          "disable": {"method": "POST", "path": "/disable_sav_table", "body": {}},
                                          "address_family": version, "hook_scope": ["input", "forward"],
                                          "excluded_mechanisms": "FP/EFP and other apps remain unqualified; not included in these treatment arms",
                                          "runtime_status": "planned_not_run_at_100_or_1000_AS"},
                  "inactive_source_edges": inactive,
                  "policy_assumptions": {"local_preference": {"customer": 300, "peer": 200, "provider": 100},
                                         "export_to_customer": "own static and BGP-learned routes",
                                         "export_to_peer_or_provider": "own static and directly customer-learned routes",
                                         "not_inferred": "real operator import/export policies, traffic, bandwidth, latency and SAV deployment",
                                         "scope": "one router per AS, inter-AS links only; no route-server/sibling/complex relationship model"},
                  "runtime_gates": ["BIRD config parse", "route convergence", "policy leak negative cases",
                                    "management/data isolation", "legal/spoof packet counters", "known dataplane P0 fixes"],
                  "runtime_status": "not_executed"}


def run(args):
    if args.out.exists():
        raise FileExistsError(args.out)
    manifest = json.loads((args.sample / "manifest.json").read_text(encoding="utf-8"))
    if sha256(args.sample / "topology.json") != manifest["artifacts"]["topology.json"]:
        raise ValueError("Input sample hash mismatch")
    sample = json.loads((args.sample / "topology.json").read_text(encoding="utf-8"))
    base, matrix = compile_sample(sample)
    args.out.mkdir(parents=True, exist_ok=False)
    code = args.out / "code"
    code.mkdir()
    for name in ("compile_scene.py", "sample_topologies.py", "fetch_sources.py"):
        shutil.copy2(Path(__file__).with_name(name), code / name)
    dump(args.out / "savop-base.json", base)
    dump(args.out / "scenario-matrix.json", matrix)
    anycast = deepcopy(base)
    case = next(c for c in matrix["cases"] if c["mode"] == "anycast")
    for origin in case["origin_nodes"]:
        anycast["devices"][origin["node_id"]]["prefixes"][case["prefix"]] = {}
    dump(args.out / "savop-anycast.json", anycast)
    dump(args.out / "manifest.json", {"schema": "k5-scenario-v1", "status": "compiled_runtime_unverified",
                                     "input_topology_sha256": sha256(args.sample / "topology.json"),
                                     "compiler_sha256": sha256(Path(__file__)),
                                     "code_artifacts": {p.name: sha256(p) for p in sorted(code.iterdir())},
                                     "artifacts": {p.name: sha256(p) for p in sorted(args.out.iterdir()) if p.is_file()}})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args())
