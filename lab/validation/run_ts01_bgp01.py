#!/usr/bin/env python3
"""Run the bounded TS01-BGP-01 IPv4 control/data-plane smoke on Linux.

Builds one isolated 5-AS / 50-router topology, checks customer/peer/provider
route policy, exercises no-SAV/strict/loose uRPF, withdraws/re-advertises a
known source prefix, then flaps the P-Q peer during a bounded UDP stream.
All Docker objects are run-ID labelled and removed by the inherited owner-safe
cleanup. Set SAVOP_EVIDENCE_PARENT to an existing dedicated data-disk directory.
"""
import argparse
import hashlib
import ipaddress
import json
import re
import select
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

from run_capacity import CapacityLab, GIB, MIB, dump, sha
from run_five_as import IMAGE
from evidence_paths import validate_evidence_root


HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "scenarios" / "ts01-bgp-01.json"
SPEC = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
ROLES = ("R", "P", "Q", "S", "V")
BASE = {role: i * 10 + 1 for i, role in enumerate(ROLES)}
ASNS = {role: 4200000001 + i for i, role in enumerate(ROLES)}
PREFIXES = {key: value for key, value in SPEC["address_plan"].items() if key in ("pS", "pD", "pK", "pX")}
HOSTS = {key: str(ipaddress.ip_network(value).network_address + 1) for key, value in PREFIXES.items()}
TEST_SOURCE_NODE = BASE["S"] + 4  # S/r5
SERVICE_NODE = BASE["V"] + 4  # V/r5
PK_ENDPOINT_NODE = BASE["V"] + 5  # V/r6
P_HUB = BASE["P"]
Q_HUB = BASE["Q"]
V_HUB = BASE["V"]
S_HUB = BASE["S"]
R_HUB = BASE["R"]
PEER_EDGE = (P_HUB, Q_HUB)


def make_scene():
    devices, links, edges, policy_links = {}, [], [], []
    for role in ROLES:
        hub = BASE[role]
        for local in range(10):
            node = hub + local
            prefixes = {}
            if role == "S" and local == 0:
                prefixes[PREFIXES["pS"]] = {}
            if role == "V" and local == 0:
                prefixes[PREFIXES["pD"]] = {}
                prefixes[PREFIXES["pK"]] = {}
            devices[str(node)] = {"as": ASNS[role], "prefixes": prefixes}
            if local:
                parent = hub
                links.append([str(parent), str(node), "dsav"])
                edges.append((parent, node))

    for row in SPEC["topology"]["links"]:
        a_role, b_role = row["a"], row["b"]
        a, b = BASE[a_role], BASE[b_role]
        links.append([str(a), str(b), "dsav"])
        edges.append((a, b))
        if row["relationship"] == "peer":
            policy_links.append({"a": str(a), "b": str(b), "relationship": "p2p", "provider": None})
        else:
            provider = row["provider"]
            policy_links.append({"a": str(a), "b": str(b), "relationship": "p2c",
                                 "provider": str(BASE[provider])})

    scene = {
        "devices": devices,
        "links": links,
        "routing_policy": {"model": "customer-provider-v1", "links": policy_links},
        "auto_ip_version": 4,
        "sav_apps": ["strict_urpf", "loose_urpf"],
        "active_sav_app": "",
        "enable_rpki": False,
        "prefix_method": "blackhole",
        "ignore_nets": ["10.0.0.0/8"],
    }
    return scene, edges


class TS01Lab(CapacityLab):
    ROOT_PREFIX = "k5-ts01-bgp01-"

    def __init__(self, args):
        args.as_count = 5
        args.hold = 30
        args.create_workers = 1
        args.evidence_encoding = "compact"
        super().__init__(args)
        self.scene, self.edges = make_scene()
        self.count = 50
        self.endpoint_prefixes = {k: PREFIXES[k] for k in ("pS", "pD", "pK")}
        self.data_plane_auto = False  # Arm transitions and route-change refreshes are explicit.
        self.startup_min_available = 3 * GIB
        self.runtime_min_available = 3 * GIB
        self.runtime_swap_limit = 1 * MIB
        self.deadline_seconds = 90
        self.report.update({
            "scenario_id": SPEC["scenario_id"],
            "fixture_origin": "synthetic 5-AS customer-provider BGP functional baseline",
            "claims_excluded": ["Internet representativeness", "1000-AS performance",
                                "independent hardware replication", "application SLA"],
            "events": [],
            "probe_results": [],
            "states": [],
        })

    def design_metadata(self):
        return {
            "scenario_id": SPEC["scenario_id"],
            "spec_sha256": sha(SPEC_PATH),
            "unit": "one isolated 50-router topology on one VM; one functional smoke, not a population sample",
            "topology": "R>P, R>Q, P-Q peer, P>S, Q>V; five ASes with one RR hub and nine iBGP clients each",
            "router_counts": {"AS": 5, "nodes_per_AS": 10, "routers": 50,
                              "intra_AS_links": 45, "inter_AS_links": 5,
                              "iBGP_sessions": 45, "eBGP_sessions": 5},
            "routing_policy": "customer local-pref 300, peer 200, provider 100; valley-free export; experimental policy only",
            "address_family": "IPv4 only",
            "prefixes": {k: PREFIXES[k] for k in ("pS", "pD", "pK", "pX")},
            "source_truth": SPEC["prefix_truth"],
            "SAV_update_mode": "explicit API install/refresh after observed BGP/FIB state; autonomous polling disabled",
            "filter_scope": "P/r1 ingress from S/r1; only P/r1 receives SAV table changes",
            "service_delivery": "V/r1 has a host-only pD /32 route to V/r5; it is not exported by BGP, while pD /28 remains the originated test prefix",
            "route_gates": "all expected BGP sessions established; pS/pD/pK present as specified; selected peer/provider FIB paths verified; stable 3 seconds; route/FIB fingerprint must match the initial state before and after each SAV arm",
            "state_evidence": "persist the full per-router BGP session and canonical FIB fingerprint for every stable state so its SHA-256 can be independently recomputed",
            "packet_probe": "ordinary UDP, 10 packets per source case, 50 ms interval; persist all received packet records and validate exact sequence set, source address, receiver count, and SAV drop-counter delta",
            "independent_verifier": "verify_ts01_bgp01.py; separate read-only audit of saved artifacts, does not import the scenario runner",
            "live_stream": "bounded ordinary UDP, 5 packets/second maximum, during P-Q down/up event",
            "container_limits": "512 MiB memory, 512 MiB memory+swap, 1 CPU, 128 PIDs, no privileged mode, network=none plus owned veth only",
            "resource_guards": "startup and runtime available memory >=3 GiB; swap growth <=1 MiB; host CPU >=95% for 45 seconds stops run",
            "claims_excluded": self.report["claims_excluded"],
        }

    def configure_generated(self):
        super().configure_generated()
        cfg = self.generated / str(V_HUB) / "bird.conf"
        text = cfg.read_text(encoding="utf-8")
        route_line = f"  route {PREFIXES['pK']} blackhole;\n"
        if text.count(route_line) != 1:
            raise RuntimeError("Expected exactly one pK route in V/r1 generated static block")
        text = text.replace(route_line, "", 1)
        text += ("\nprotocol static k5_test_pK {\n"
                 "  ipv4 { export all; import all; };\n"
                 f"  route {PREFIXES['pK']} blackhole;\n"
                 "};\n")
        cfg.write_text(text, encoding="utf-8")
        self.report["pk_bird_protocol"] = "k5_test_pK"
        # Parse with the pinned runtime image: the host may not have BIRD's
        # shared libraries, while this is the environment used by each lab node.
        parse_script = f'for cfg in /build/{self.generated.name}/[0-9]*/bird.conf; do /build/router/bird -p -c "$cfg"; done'
        self.command(["docker", "run", "--rm", "--network", "none",
                      "--mount", f"type=bind,source={self.root},target=/build,readonly",
                      "--entrypoint", "/bin/sh", IMAGE, "-ec", parse_script], timeout=120)
        self.report["bird_config_parse"] = {"nodes_checked": self.count, "pass": True}

    def prepare(self):
        super().prepare()
        hub_script = (self.generated / "clab_batches" / f"{V_HUB}.sh").read_text(encoding="utf-8")
        service_script = (self.generated / "clab_batches" / f"{SERVICE_NODE}.sh").read_text(encoding="utf-8")
        hub_match = re.findall(rf"(?m)^ip addr add ([0-9.]+/\d+) dev eth_{SERVICE_NODE}$", hub_script)
        service_match = re.findall(rf"(?m)^ip addr add ([0-9.]+/\d+) dev eth_{V_HUB}$", service_script)
        if len(hub_match) != 1 or len(service_match) != 1:
            raise RuntimeError("Could not resolve the V/r1 to V/r5 point-to-point addresses")
        hub_if = ipaddress.ip_interface(hub_match[0])
        service_if = ipaddress.ip_interface(service_match[0])
        if hub_if.network != service_if.network or hub_if.ip == service_if.ip:
            raise RuntimeError("V/r1 and V/r5 service link addressing is inconsistent")
        self.ns(V_HUB, "ip", "route", "replace", f"{HOSTS['pD']}/32",
                "via", str(service_if.ip), "dev", f"eth_{SERVICE_NODE}")
        delivery = json.loads(self.ns(V_HUB, "ip", "-j", "route", "show", f"{HOSTS['pD']}/32").stdout)
        if not delivery or delivery[0].get("gateway") != str(service_if.ip) or delivery[0].get("dev") != f"eth_{SERVICE_NODE}":
            raise RuntimeError("V/r1 service endpoint /32 route did not install as specified")
        self.report["service_delivery_route"] = {
            "prefix": f"{HOSTS['pD']}/32", "via": str(service_if.ip),
            "device": f"eth_{SERVICE_NODE}", "scope": "V/r1 kernel route only; not exported by BGP"}
        for node, keys in ((TEST_SOURCE_NODE, ("pS", "pK", "pX")),
                           (SERVICE_NODE, ("pD",)), (PK_ENDPOINT_NODE, ("pK",))):
            for key in keys:
                self.ns(node, "ip", "addr", "add", f"{HOSTS[key]}/32", "dev", "endpoint", "nodad")
        for path in (Path(__file__), SPEC_PATH):
            target = self.run / ("run_ts01_bgp01.py" if path == Path(__file__) else "ts01-bgp-01.json")
            shutil.copy2(path, target)
            self.report.setdefault("provenance", {})[target.name] = sha(path)
        self.report["prefix_hosts"] = HOSTS
        self.report["endpoint_nodes"] = {"source": TEST_SOURCE_NODE, "service": SERVICE_NODE,
                                          "pK_origin_test_address": PK_ENDPOINT_NODE}

    def api_call(self, node, path, body=None):
        args = ["curl", "--silent", "--show-error", "--max-time", "8"]
        if body is not None:
            args += ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
        raw = self.ns(node, *args, f"http://127.0.0.1:8888/{path}", timeout=10).stdout
        result = json.loads(raw)
        if result.get("code") != "0000":
            raise RuntimeError(f"Agent API {path} failed: {result}")
        return result

    def set_sav_mode(self, mode):
        if mode == "none":
            response = self.api_call(P_HUB, "disable_sav_table", {})
            installed = self.ns(P_HUB, "nft", "-j", "list", "table", "inet", "savop", check=False)
            if installed.returncode == 0:
                raise RuntimeError("No-SAV arm still has the SAV nft table")
            row = {"mode": mode, "api": response, "installed": False}
        else:
            response = self.api_call(P_HUB, "enable_sav_table", {"active_app": mode, "dry_run": False})
            installed = self.ns(P_HUB, "nft", "-j", "list", "table", "inet", "savop", check=False)
            if installed.returncode:
                raise RuntimeError("SAV API succeeded but nft table readback is absent")
            active = self.api_call(P_HUB, "active_sav_table")
            data = active.get("data", {})
            if data.get("active_app") != mode:
                raise RuntimeError(f"Active SAV table mismatch: expected {mode}, got {data.get('active_app')}")
            row = {"mode": mode, "api": response, "active_table": active,
                   "nft_json": json.loads(installed.stdout)}
        self.report.setdefault("events", []).append({"kind": "sav-mode", **row})
        return row

    def route_table(self, node):
        return json.loads(self.ns(node, "ip", "-j", "-4", "route", "show", "table", "main").stdout)

    def route(self, node, prefix):
        matches = [r for r in self.route_table(node) if r.get("dst") == prefix]
        return matches[0] if matches else None

    def wait_state(self, tag, *, peer_up=True, pk_present=True):
        started, same_since, previous, samples = time.monotonic(), None, None, []
        expected_edges = [e for e in self.edges if peer_up or tuple(sorted(e)) != tuple(sorted(PEER_EDGE))]
        required_prefixes = {"pS": PREFIXES["pS"], "pD": PREFIXES["pD"]}
        if pk_present:
            required_prefixes["pK"] = PREFIXES["pK"]
        last_rows = []
        while time.monotonic() - started < self.deadline_seconds:
            self.guard()
            self.verify_ownership()
            rows, ready, snapshots = [], True, {}
            for node in self.nodes:
                protocols = self.bird(node, "show protocols", check=False)
                bgp = {line.split()[0] for line in protocols.splitlines()
                       if re.match(r"dsav_\d+_\d+\s", line) and "Established" in line.split()}
                expected = {f"dsav_{node}_{b if node == a else a}" for a, b in expected_edges if node in (a, b)}
                node_ready = bgp == expected
                routes = self.route_table(node)
                route_map = {r.get("dst"): r for r in routes if r.get("dst")}
                for key, prefix in required_prefixes.items():
                    node_ready &= prefix in route_map
                if not pk_present:
                    node_ready &= PREFIXES["pK"] not in route_map
                node_ready &= PREFIXES["pX"] not in route_map
                canonical = sorted(json.dumps({k: r[k] for k in ("dst", "dev", "gateway", "type", "nexthops") if k in r}, sort_keys=True)
                                   for r in routes)
                snapshots[str(node)] = {"bgp": sorted(bgp), "fib": canonical}
                rows.append({"node": node, "expected_bgp": len(expected), "established_bgp": len(bgp),
                             "routes": {p: route_map.get(p) for p in (PREFIXES["pS"], PREFIXES["pD"], PREFIXES["pK"], PREFIXES["pX"])}})
                ready &= bool(node_ready)

            p_path = self.route(P_HUB, PREFIXES["pD"])
            q_path = self.route(Q_HUB, PREFIXES["pS"])
            expected_p_dev = "eth_21" if peer_up else "eth_1"
            expected_q_dev = "eth_11" if peer_up else "eth_1"
            ready &= bool(p_path and p_path.get("dev") == expected_p_dev)
            ready &= bool(q_path and q_path.get("dev") == expected_q_dev)
            ready &= (self.route(P_HUB, PREFIXES["pK"]) or {}).get("dev") == expected_p_dev if pk_present else True
            current = {"routers": snapshots, "P_pD_dev": (p_path or {}).get("dev"),
                       "Q_pS_dev": (q_path or {}).get("dev"),
                       "P_pK_dev": (self.route(P_HUB, PREFIXES["pK"]) or {}).get("dev")}
            now = time.monotonic()
            same = current == previous
            state_sha256 = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
            samples.append({"elapsed": now - started, "ready": bool(ready),
                            "snapshot_sha256": state_sha256,
                            "failed_nodes": [r["node"] for r in rows if len([p for p in expected_edges if r["node"] in p]) != r["established_bgp"]]})
            last_rows = rows
            if ready and same:
                if same_since is None:
                    same_since = now
                if now - same_since >= 3:
                    evidence = {"tag": tag, "elapsed_seconds": now - started, "peer_up": peer_up,
                                "pk_present": pk_present, "p_path": p_path, "q_path": q_path,
                                "state_sha256": state_sha256, "fingerprint": current,
                                "rows": rows, "samples": samples}
                    dump(self.run / f"state-{tag}.json", evidence)
                    self.report["states"].append({k: evidence[k] for k in ("tag", "elapsed_seconds", "peer_up", "pk_present", "p_path", "q_path", "state_sha256")})
                    return evidence
            else:
                same_since = None
            previous = current
            time.sleep(0.5)
        evidence = {"tag": tag, "peer_up": peer_up, "pk_present": pk_present,
                    "last_state_sha256": samples[-1]["snapshot_sha256"] if samples else None,
                    "last_rows": last_rows, "samples": samples}
        dump(self.run / f"state-{tag}.json", evidence)
        raise RuntimeError(f"BGP/FIB state did not stabilize: {tag}")

    def verify_exports(self):
        checks = []
        for node, peer, expected in (
            (P_HUB, R_HUB, {PREFIXES["pS"]}),
            (P_HUB, Q_HUB, {PREFIXES["pS"]}),
            (Q_HUB, R_HUB, {PREFIXES["pD"], PREFIXES["pK"]}),
        ):
            raw = self.bird(node, f"show route export dsav_{node}_{peer}")
            actual = set(re.findall(r"(?m)^([0-9a-fA-F:.]+/\d+)\s", raw))
            row = {"node": node, "peer": peer, "expected": sorted(expected), "actual": sorted(actual), "raw": raw}
            checks.append(row)
            if actual != expected:
                self.report["export_policy_checks"] = checks
                raise RuntimeError(f"Valley-free route export mismatch on {node}->{peer}")
        self.report["export_policy_checks"] = checks

    def drop_counter(self):
        result = self.ns(P_HUB, "nft", "-j", "list", "table", "inet", "savop", check=False)
        if result.returncode:
            return 0
        data = json.loads(result.stdout)
        total = 0
        for item in data.get("nftables", []):
            rule = item.get("rule", {})
            expressions = rule.get("expr", [])
            if any("drop" in expr for expr in expressions):
                total += sum(expr["counter"]["packets"] for expr in expressions if "counter" in expr)
        return total

    def probe(self, mode, source_key, expected_received, expected_drop_delta):
        helper = self.run / "packet_probe.py"
        token = f"{self.args.run_id}-{mode}-{source_key}-{len(self.report['probe_results']):04d}"
        receiver_cmd = self.namespace_command(SERVICE_NODE, sys.executable, helper, "receive",
                                             "--destination", HOSTS["pD"], "--token", token,
                                             "--duration", "2.5")
        before = self.drop_counter()
        receiver = subprocess.Popen(receiver_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([receiver.stdout], [], [], 8)[0] or receiver.stdout.readline().strip() != "READY":
                raise RuntimeError("UDP service receiver did not become ready")
            tx_raw = self.ns(TEST_SOURCE_NODE, sys.executable, helper, "normal-send",
                             "--source", HOSTS[source_key], "--destination", HOSTS["pD"],
                             "--token", token, "--count", "10", timeout=8).stdout
            tx = json.loads(tx_raw)
            output, error = receiver.communicate(timeout=6)
            if receiver.returncode:
                raise RuntimeError(f"UDP receiver failed: {error}")
            rx = json.loads(output)
            after = self.drop_counter()
            drop_delta = after - before
            payloads = [p["payload"] for p in rx["packets"]]
            expected_payloads = {f"{token}:{i}" for i in range(tx["sent"])}
            sequence_pass = (len(payloads) == len(set(payloads))
                             and set(payloads).issubset(expected_payloads)
                             and (expected_received != tx["sent"] or set(payloads) == expected_payloads))
            receiver_count_matches_packets = rx["received"] == len(rx["packets"])
            source_addresses_match = all(p["source"] == HOSTS[source_key] for p in rx["packets"])
            row = {"mode": mode, "source": source_key, "source_address": HOSTS[source_key],
                   "destination": HOSTS["pD"], "sent": tx["sent"], "received": rx["received"],
                   "expected_received": expected_received, "drop_counter_before": before,
                   "drop_counter_after": after, "expected_drop_delta": expected_drop_delta,
                   "drop_delta": drop_delta,
                   "sequence_payloads": payloads, "sequence_pass": sequence_pass,
                   "received_packets": rx["packets"],
                   "receiver_count_matches_packets": receiver_count_matches_packets,
                   "source_addresses_match": source_addresses_match,
                   "pass": tx["sent"] == 10 and rx["received"] == expected_received
                           and drop_delta == expected_drop_delta and sequence_pass
                           and receiver_count_matches_packets and source_addresses_match}
            self.report["probe_results"].append(row)
            if not row["pass"]:
                raise RuntimeError(f"Probe mismatch: {row}")
            return row
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.communicate()

    def probe_arm(self, mode):
        arm = next((row for row in SPEC["arms"] if row["mode"] == mode), None)
        if arm is None:
            raise RuntimeError(f"No expected probe matrix in scenario spec for SAV mode {mode}")
        self.set_sav_mode(mode)
        before = self.wait_state(f"before-{mode}", peer_up=True, pk_present=True)
        self.check_arm_route_fingerprint(mode, "before-probes", before)
        for source_key, expected in arm["probes"].items():
            if expected["received"] + expected["drop_delta"] != 10:
                raise RuntimeError(f"Invalid 10-packet expectation for {mode}/{source_key}: {expected}")
            self.probe(mode, source_key, expected["received"], expected["drop_delta"])
        after = self.wait_state(f"after-{mode}", peer_up=True, pk_present=True)
        self.check_arm_route_fingerprint(mode, "after-probes", after)

    def check_arm_route_fingerprint(self, mode, phase, state):
        baseline = self.report["route_arm_baseline_sha256"]
        actual = state["state_sha256"]
        row = {"mode": mode, "phase": phase, "expected": baseline,
               "actual": actual, "pass": actual == baseline}
        self.report.setdefault("route_arm_fingerprint_checks", []).append(row)
        if not row["pass"]:
            raise RuntimeError(f"Route/FIB state changed during {mode} {phase}: {row}")

    def pk_lifecycle(self):
        self.set_sav_mode("loose_urpf")
        before = self.drop_counter()
        command_start = time.monotonic()
        self.bird(V_HUB, "disable k5_test_pK")
        withdrawn = self.wait_state("pk-withdrawn", peer_up=True, pk_present=False)
        refresh = self.set_sav_mode("loose_urpf")
        table = refresh.get("active_table", {}).get("data", {}).get("rules", {})
        if PREFIXES["pK"] in json.dumps(table):
            raise RuntimeError("loose-uRPF readback still contains withdrawn pK")
        self.probe("loose_urpf-after-withdrawal", "pK", 0, 10)
        self.report["events"].append({"kind": "prefix-withdrawal", "prefix": PREFIXES["pK"],
                                      "route_state_seconds": withdrawn["elapsed_seconds"],
                                      "command_to_refresh_seconds": time.monotonic() - command_start,
                                      "rule_hash": refresh.get("active_table", {}).get("data", {}).get("rules")})

        command_start = time.monotonic()
        self.bird(V_HUB, "enable k5_test_pK")
        restored = self.wait_state("pk-restored", peer_up=True, pk_present=True)
        refresh = self.set_sav_mode("loose_urpf")
        table = refresh.get("active_table", {}).get("data", {}).get("rules", {})
        if PREFIXES["pK"] not in json.dumps(table):
            raise RuntimeError("loose-uRPF readback lacks restored pK")
        self.probe("loose_urpf-after-restore", "pK", 10, 0)
        self.report["events"].append({"kind": "prefix-readvertisement", "prefix": PREFIXES["pK"],
                                      "route_state_seconds": restored["elapsed_seconds"],
                                      "command_to_refresh_seconds": time.monotonic() - command_start})
        self.report["pk_drop_counter_baseline"] = before

    def live_failover(self):
        self.set_sav_mode("loose_urpf")
        helper = self.run / "packet_probe.py"
        token = f"{self.args.run_id}-peer-flap"
        receiver_cmd = self.namespace_command(SERVICE_NODE, sys.executable, helper, "receive",
                                             "--destination", HOSTS["pD"], "--token", token,
                                             "--duration", "125")
        receiver = subprocess.Popen(receiver_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        streamer = None
        down_at = down_stable = up_at = up_stable = None
        try:
            if not select.select([receiver.stdout], [], [], 8)[0] or receiver.stdout.readline().strip() != "READY":
                raise RuntimeError("Live-stream receiver did not become ready")
            stream_cmd = self.namespace_command(TEST_SOURCE_NODE, sys.executable, helper, "normal-stream",
                                                "--source", HOSTS["pS"], "--destination", HOSTS["pD"],
                                                "--token", token, "--duration", "120", "--interval-ms", "200")
            streamer = subprocess.Popen(stream_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(2)
            self.verify_ownership()
            down_at = time.monotonic()
            self.ns(P_HUB, "ip", "link", "set", "dev", f"eth_{Q_HUB}", "down")
            self.ns(Q_HUB, "ip", "link", "set", "dev", f"eth_{P_HUB}", "down")
            down = self.wait_state("peer-down", peer_up=False, pk_present=True)
            down_stable = time.monotonic()
            time.sleep(3)
            up_at = time.monotonic()
            self.ns(P_HUB, "ip", "link", "set", "dev", f"eth_{Q_HUB}", "up")
            self.ns(Q_HUB, "ip", "link", "set", "dev", f"eth_{P_HUB}", "up")
            up = self.wait_state("peer-restored", peer_up=True, pk_present=True)
            up_stable = time.monotonic()
            output, error = streamer.communicate(timeout=125)
            if streamer.returncode:
                raise RuntimeError(f"UDP stream sender failed: {error}")
            sender = json.loads(output)
            rx_output, rx_error = receiver.communicate(timeout=15)
            if receiver.returncode:
                raise RuntimeError(f"UDP stream receiver failed: {rx_error}")
            received = json.loads(rx_output)
            by_sequence = {}
            for packet in received["packets"]:
                try:
                    seq = int(packet["payload"].rsplit(":", 1)[1])
                    by_sequence[seq] = packet["monotonic"]
                except (KeyError, ValueError, IndexError):
                    continue
            missing = sorted(set(range(sender["sent"])) - set(by_sequence))
            event_times = {"peer_down_command": down_at, "peer_down_stable": down_stable,
                           "peer_up_command": up_at, "peer_up_stable": up_stable}
            received_after_restore = [t for t in by_sequence.values() if t >= up_stable]
            row = {"sent": sender["sent"], "received": len(by_sequence), "missing_sequences": missing,
                   "sender_started_monotonic": sender["start_monotonic"], "sender_stopped_monotonic": sender["stop_monotonic"],
                   "events_monotonic": event_times,
                   "event_seconds_from_sender_start": {k: v - sender["start_monotonic"] for k, v in event_times.items()},
                   "first_received_after_restoration": min(received_after_restore) if received_after_restore else None,
                   "peer_down_state": {"pD_at_P": down["p_path"], "pS_at_Q": down["q_path"]},
                   "peer_restored_state": {"pD_at_P": up["p_path"], "pS_at_Q": up["q_path"]},
                   "received_packets": received["packets"], "sender_packets": sender["packets"]}
            self.report["live_failover"] = row
            if sender["sent"] < 500 or not received_after_restore:
                raise RuntimeError("Live stream did not span the restored path or yielded too few samples")
            self.report["events"].append({"kind": "peer-link-failover", "edge": [P_HUB, Q_HUB],
                                          "path_after_down": "S-P-R-Q-V", "path_after_up": "S-P-Q-V",
                                          "down_convergence_seconds": down_stable - down_at,
                                          "restore_convergence_seconds": up_stable - up_at,
                                          "sent": sender["sent"], "received": len(by_sequence),
                                          "loss": sender["sent"] - len(by_sequence)})
        finally:
            if streamer is not None and streamer.poll() is None:
                streamer.terminate()
                streamer.wait(timeout=5)
            if receiver.poll() is None:
                receiver.kill()
                receiver.communicate()
            # Restore both isolated interface ends if an earlier assertion failed.
            for node, peer in ((P_HUB, Q_HUB), (Q_HUB, P_HUB)):
                if node in self.nodes:
                    self.ns(node, "ip", "link", "set", "dev", f"eth_{peer}", "up", check=False)

    def summarize_resources(self):
        samples = self.samples
        if not samples:
            self.report["resource_summary"] = {"samples": 0, "pass": False}
            return False
        min_available = min(row["mem_available_gib"] for row in samples)
        max_swap_growth = max(row["swap_used_mib"] - self.initial_swap / MIB for row in samples)
        summary = {"samples": len(samples), "min_available_gib": min_available,
                   "mean_cpu_percent": sum(row["cpu_percent"] for row in samples) / len(samples),
                   "max_swap_growth_mib": max_swap_growth,
                   "startup_min_available_gib": 3,
                   "runtime_min_available_gib": 3,
                   "max_swap_growth_gate_mib": 1}
        summary["pass"] = min_available >= 3 and max_swap_growth <= 1
        self.report["resource_summary"] = summary
        return summary["pass"]

    def run_scenario(self):
        initial = self.wait_state("initial", peer_up=True, pk_present=True)
        self.report["route_arm_baseline_sha256"] = initial["state_sha256"]
        self.report["initial_state"] = {"P_pD": initial["p_path"], "Q_pS": initial["q_path"]}
        self.verify_exports()
        self.probe_arm("none")
        self.probe_arm("strict_urpf")
        self.probe_arm("loose_urpf")
        self.pk_lifecycle()
        self.live_failover()
        if not self.summarize_resources():
            self.report["status"] = "failed_resource_gate"
            return
        self.report["status"] = "passed_ts01_bgp01_functional_smoke"


def main(args):
    args.root = validate_evidence_root(args.root, TS01Lab.ROOT_PREFIX, must_exist=False)
    args.root.mkdir(mode=0o700, parents=False, exist_ok=False)
    lab = None
    try:
        lab = TS01Lab(args)
        lab.prepare()
        lab.run_scenario()
    except Exception:
        if lab is not None:
            lab.report["status"] = "failed"
            lab.report["error"] = traceback.format_exc()
            print(lab.report["error"], flush=True)
    finally:
        if lab is not None:
            lab.report["created_nodes"] = len(lab.nodes)
            lab.cleanup()
            lab.summarize_resources()
            dump(lab.run / "result.json", lab.report)
    if lab is None:
        return 2
    print(json.dumps({"status": lab.report["status"], "scenario_id": SPEC["scenario_id"],
                      "run": str(lab.run), "resources": lab.report.get("resource_summary")}), flush=True)
    return 0 if lab.report["status"] == "passed_ts01_bgp01_functional_smoke" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--family", type=int, choices=(4,), default=4)
    parser.add_argument("--as-count", type=int, choices=(5,), default=5)
    parser.add_argument("--hold", type=int, default=30)
    parser.add_argument("--create-workers", type=int, choices=(1,), default=1)
    parser.add_argument("--evidence-encoding", choices=("compact",), default="compact")
    parsed = parser.parse_args()
    raise SystemExit(main(parsed))
