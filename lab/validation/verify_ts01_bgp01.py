#!/usr/bin/env python3
"""Independently audit a completed TS01-BGP-01 evidence directory.

This verifier reads only frozen inputs and saved run artifacts. It does not
import the scenario runner or modify its source evidence; it creates a new
independent-audit.json and refuses to overwrite an existing audit.
"""
import argparse
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def audit(result_path):
    run = result_path.parent
    result = load(result_path)
    spec_path = run / "ts01-bgp-01.json"
    scene_path = run / "scene.json"
    runner_path = run / "run_ts01_bgp01.py"
    spec, scene = load(spec_path), load(scene_path)
    checks = []
    hashes = {"result.json": sha256(result_path.read_bytes()),
              "ts01-bgp-01.json": sha256(spec_path.read_bytes()),
              "scene.json": sha256(scene_path.read_bytes()),
              "run_ts01_bgp01.py": sha256(runner_path.read_bytes())}

    def record(name, ok, detail=None):
        row = {"name": name, "pass": bool(ok)}
        if detail is not None:
            row["detail"] = detail
        checks.append(row)

    record("runner_status", result.get("status") == "passed_ts01_bgp01_functional_smoke",
           result.get("status"))
    record("scope_5_as_50_nodes", result.get("AS_count") == 5
           and result.get("node_count") == 50 and result.get("created_nodes") == 50)
    provenance = result.get("provenance", {})
    record("input_provenance", provenance.get("ts01-bgp-01.json") == hashes["ts01-bgp-01.json"]
           and provenance.get("run_ts01_bgp01.py") == hashes["run_ts01_bgp01.py"],
           {"runner_sha256": hashes["run_ts01_bgp01.py"],
            "scenario_sha256": hashes["ts01-bgp-01.json"]})

    devices = scene.get("devices", {})
    links = scene.get("links", [])
    asns = {device.get("as") for device in devices.values()}
    record("scene_topology", len(devices) == 50 and len(asns) == 5
           and len(links) == 50 and len(spec["topology"]["links"]) == 5,
           {"nodes": len(devices), "unique_asns": len(asns), "router_links": len(links)})

    expected_peers = {node: set() for node in devices}
    for link in links:
        a, b = str(link[0]), str(link[1])
        expected_peers[a].add(f"dsav_{a}_{b}")
        expected_peers[b].add(f"dsav_{b}_{a}")
    role_hubs = {role: 10 * index + 1
                 for index, role in enumerate(spec["topology"]["roles"])}
    peer_edges = [(str(role_hubs[row["a"]]), str(role_hubs[row["b"]]))
                  for row in spec["topology"]["links"] if row["relationship"] == "peer"]

    state_tags = (
        "initial", "before-none", "after-none", "before-strict_urpf",
        "after-strict_urpf", "before-loose_urpf", "after-loose_urpf",
        "pk-withdrawn", "pk-restored", "peer-down", "peer-restored",
    )
    states = {}
    for tag in state_tags:
        path = run / f"state-{tag}.json"
        state = load(path) if path.exists() else {}
        states[tag] = state
        fingerprint = state.get("fingerprint")
        recomputed = sha256(json.dumps(fingerprint, sort_keys=True).encode()) if fingerprint else None
        record(f"state_fingerprint:{tag}", bool(fingerprint)
               and recomputed == state.get("state_sha256"),
               {"stored": state.get("state_sha256"), "recomputed": recomputed})
        routers = (fingerprint or {}).get("routers", {})
        peers_ok = set(routers) == set(devices)
        prefixes_ok = peers_ok
        state_expected_peers = {node: set(peers) for node, peers in expected_peers.items()}
        if state.get("peer_up") is False:
            for a, b in peer_edges:
                state_expected_peers[a].discard(f"dsav_{a}_{b}")
                state_expected_peers[b].discard(f"dsav_{b}_{a}")
        for node, router in routers.items():
            peers_ok &= set(router.get("bgp", [])) == state_expected_peers.get(node, set())
            route_prefixes = {json.loads(row).get("dst") for row in router.get("fib", [])}
            required = {spec["address_plan"]["pS"], spec["address_plan"]["pD"]}
            if state.get("pk_present"):
                required.add(spec["address_plan"]["pK"])
            prefixes_ok &= required.issubset(route_prefixes)
            prefixes_ok &= spec["address_plan"]["pX"] not in route_prefixes
            if not state.get("pk_present"):
                prefixes_ok &= spec["address_plan"]["pK"] not in route_prefixes
        record(f"all_router_bgp_and_fib:{tag}", bool(fingerprint) and peers_ok and prefixes_ok,
               {"routers": len(routers), "peer_sets_match": bool(peers_ok),
                "required_prefixes_match": bool(prefixes_ok)})
        if state:
            peer_up = state.get("peer_up")
            if peer_up is not None:
                wanted_p = "eth_21" if peer_up else "eth_1"
                wanted_q = "eth_11" if peer_up else "eth_1"
                route_paths_ok = (state.get("p_path", {}).get("dev") == wanted_p
                                  and state.get("q_path", {}).get("dev") == wanted_q)
                record(f"selected_paths:{tag}", route_paths_ok,
                       {"P": state.get("p_path", {}).get("dev"),
                        "Q": state.get("q_path", {}).get("dev")})

    baseline = states["initial"].get("state_sha256")
    arm_tags = ("before-none", "after-none", "before-strict_urpf", "after-strict_urpf",
                "before-loose_urpf", "after-loose_urpf")
    record("sav_arm_routes_unchanged", bool(baseline)
           and all(states[tag].get("state_sha256") == baseline for tag in arm_tags),
           {"baseline": baseline, "compared_states": len(arm_tags)})
    reported_fingerprints = result.get("route_arm_fingerprint_checks", [])
    record("runner_fingerprint_assertions", len(reported_fingerprints) == 6
           and all(row.get("pass") and row.get("expected") == baseline
                   and row.get("actual") == baseline for row in reported_fingerprints),
           {"passed": sum(bool(row.get("pass")) for row in reported_fingerprints),
            "total": len(reported_fingerprints)})

    expected = {arm["mode"]: arm["probes"] for arm in spec["arms"]}
    expected["loose_urpf-after-withdrawal"] = {"pK": {"received": 0, "drop_delta": 10}}
    expected["loose_urpf-after-restore"] = {"pK": {"received": 10, "drop_delta": 0}}
    source_addresses = spec["traffic"]["source_addresses"]
    probes = result.get("probe_results", [])
    probe_ok = len(probes) == 11
    observed_received = observed_drops = 0
    for index, probe in enumerate(probes):
        mode, source = probe.get("mode"), probe.get("source")
        expectation = expected.get(mode, {}).get(source, {})
        packets = probe.get("received_packets", [])
        payloads = [packet.get("payload") for packet in packets]
        token = f"{result.get('run_id')}-{mode}-{source}-{index:04d}"
        sent = probe.get("sent")
        expected_received = expectation.get("received", -1)
        expected_drops = expectation.get("drop_delta", -1)
        wanted_payloads = {f"{token}:{i}" for i in range(sent or 0)}
        packet_ok = (sent == 10 and expected_received >= 0
                     and len(packets) == probe.get("received") == expected_received
                     and len(payloads) == len(set(payloads))
                     and (set(payloads) == wanted_payloads if expected_received == sent
                          else not payloads)
                     and all(packet.get("source") == source_addresses.get(source)
                             for packet in packets)
                     and probe.get("drop_counter_after", -1)
                     - probe.get("drop_counter_before", -1) == expected_drops
                     and probe.get("drop_delta") == expected_drops
                     and probe.get("expected_drop_delta") == expected_drops)
        probe_ok &= packet_ok
        observed_received += len(packets)
        observed_drops += probe.get("drop_delta", 0)
    record("raw_packet_matrix", bool(probe_ok),
           {"probe_groups": len(probes), "sent": len(probes) * 10,
            "received": observed_received, "drop_counter_delta": observed_drops})

    events = result.get("events", [])
    withdrawal = next((row for row in events if row.get("kind") == "prefix-withdrawal"), {})
    restoration = next((row for row in events if row.get("kind") == "prefix-readvertisement"), {})
    record("prefix_lifecycle", withdrawal.get("prefix") == spec["address_plan"]["pK"]
           and restoration.get("prefix") == spec["address_plan"]["pK"]
           and states["pk-withdrawn"].get("pk_present") is False
           and states["pk-restored"].get("pk_present") is True,
           {"withdrawal_route_state_seconds": states["pk-withdrawn"].get("elapsed_seconds"),
            "restored_route_state_seconds": states["pk-restored"].get("elapsed_seconds")})

    failover = result.get("live_failover", {})
    sender_packets = failover.get("sender_packets", [])
    receiver_packets = failover.get("received_packets", [])
    sent_sequences = {row.get("seq") for row in sender_packets}
    received_sequences = {int(row.get("payload", "").rsplit(":", 1)[-1])
                          for row in receiver_packets if ":" in row.get("payload", "")}
    expected_sequences = set(range(failover.get("sent", 0)))
    stream_ok = (failover.get("sent") == 600 and failover.get("received") == 600
                 and len(sender_packets) == 600 and len(receiver_packets) == 600
                 and sent_sequences == expected_sequences
                 and received_sequences == expected_sequences
                 and all(row.get("source") == source_addresses["pS"] for row in receiver_packets)
                 and states["peer-down"].get("p_path", {}).get("dev") == "eth_1"
                 and states["peer-restored"].get("p_path", {}).get("dev") == "eth_21"
                 and failover.get("missing_sequences") == [])
    record("peer_failover_stream_and_paths", stream_ok,
           {"sent": failover.get("sent"), "received": failover.get("received"),
            "missing": len(failover.get("missing_sequences", []))})

    resources = result.get("resource_summary", {})
    resource_ok = (resources.get("pass") is True and resources.get("min_available_gib", 0) >= 3
                   and resources.get("max_swap_growth_mib", float("inf")) <= 1)
    record("resource_gate", resource_ok, resources)
    record("cleanup_and_host", result.get("host_unchanged") is True
           and result.get("cleanup_errors") == [],
           {"host_unchanged": result.get("host_unchanged"),
            "cleanup_errors": result.get("cleanup_errors")})

    passed = all(row["pass"] for row in checks)
    return {"schema": "ts01-independent-audit-v1", "run_id": result.get("run_id"),
            "outcome": "passed" if passed else "failed", "checks_passed": sum(row["pass"] for row in checks),
            "checks_total": len(checks), "input_sha256": hashes,
            "verifier_sha256": sha256(Path(__file__).read_bytes()), "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path, help="path to the completed result.json")
    parser.add_argument("--output", type=Path, help="new audit JSON path; defaults beside result.json")
    args = parser.parse_args()
    result_path = args.result.resolve(strict=True)
    output = args.output or result_path.with_name("independent-audit.json")
    if output.exists():
        raise SystemExit(f"Refusing to overwrite existing audit: {output}")
    report = audit(result_path)
    output.parent.mkdir(parents=False, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: report[k] for k in ("outcome", "run_id", "checks_passed", "checks_total")},
                     sort_keys=True))
    return 0 if report["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
