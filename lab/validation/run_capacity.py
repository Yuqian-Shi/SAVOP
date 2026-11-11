"""Bounded 10 routing-nodes/AS capacity qualification on one Linux VM.

No uplinks or host firewall/route writes. Every node runs BIRD and the current
Rust Agent with automatic strict uRPF. Synthetic tree, not an Internet sample.
Only new /mnt/hdd/k5-capacity-* roots and fresh run IDs are allowed.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import threading
import time
import traceback

import psutil
from run_five_as import Lab, LABEL, IMAGE, dump, sha, validate_namespace
from evidence_io import write_json
from bounded_tasks import run_bounded
from evidence_paths import validate_evidence_root

GIB = 1024 ** 3
MIB = 1024 ** 2


def hub(as_index):
    return 10 * (as_index - 1) + 1


def topology(as_count, family):
    devices, edges = {}, []
    for a in range(1, as_count + 1):
        for node in range(hub(a), hub(a) + 10):
            devices[str(node)] = {"as": 4200000000 + a, "prefixes": {prefix(node, family): {}}}
            if node != hub(a):
                edges.append((hub(a), node))
        if a > 1:
            edges.append((hub(a // 2), hub(a)))
    return {"devices": devices, "links": [[str(a), str(b), "dsav"] for a, b in edges],
            "auto_ip_version": family, "sav_apps": ["strict_urpf", "loose_urpf"],
            "active_sav_app": "strict_urpf", "enable_rpki": False, "prefix_method": "blackhole",
            "ignore_nets": ["10.0.0.0/8"] if family == 4 else ["fec::/16"]}, edges


def prefix(node, family):
    return (str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.18.0.0")) + node * 16)) + "/28"
            if family == 4 else f"fd42:2400:{node:x}::/64")


def address(node, family):
    return str(ipaddress.ip_network(prefix(node, family)).network_address + 1)


def stability_start(ready, hashes, previous_hashes, since, now):
    if not ready:
        return None
    if since is None or hashes != previous_hashes:
        return now
    return since


def installed_and_fresh(state, now):
    # "checking" is the normal periodic readback phase, not a removed/failed table.
    # Require prior verified installation; an initial uninstalled checking state
    # cannot pass. Route-change gates separately require a new committed hash.
    return (state["phase"] in ("applied", "in_sync", "checking") and not state["paused"]
            and state["last_error"] is None and state["last_hash"] is not None
            and state["installed_fingerprint"] is not None and state["refresh_count"] >= 1
            and state["enabled"] and not state["dry_run"]
            and 0 <= now - (state["last_verified"] or 0) <= 10)


class SafetyStop(RuntimeError):
    pass


class CapacityLab(Lab):
    ROOT_PREFIX = "k5-capacity-"

    def __init__(self, args):
        self.args = args
        self.evidence_encoding = getattr(args, "evidence_encoding", "compact")
        if self.evidence_encoding not in ("pretty", "compact"):
            raise ValueError("Invalid evidence encoding")
        self.create_workers = getattr(args, "create_workers", 1)
        if isinstance(self.create_workers, bool) or self.create_workers not in (1, 2, 4, 8):
            raise ValueError("Invalid container creation concurrency")
        self.creation_lock = threading.Lock()
        self.root = validate_evidence_root(args.root, self.ROOT_PREFIX)
        self.baseline = args.build.resolve(strict=True)
        if not re.fullmatch(r"[a-z0-9-]{3,24}", args.run_id) or not 1 <= args.as_count <= 100:
            raise ValueError("Invalid run ID or AS count")
        self.run = self.root / args.run_id
        self.run.mkdir(exist_ok=False)
        self.log = self.run / "commands.jsonl"
        self.generated = self.root / ("savop_run_" + args.run_id)
        self.nodes, self.namespace_fds, self.created_links = {}, {}, []
        self.scene, self.edges = topology(args.as_count, args.family)
        self.count = args.as_count * 10
        self.endpoint_prefixes = {n: prefix(n, args.family) for n in range(1, self.count + 1)}
        self.stop_monitor = threading.Event()
        self.abort = threading.Event()
        self.abort_reason = None
        self.phase = "prepare"
        self.samples = []
        self.initial_swap = psutil.swap_memory().used
        self.report = {"status": "in_progress", "run_id": args.run_id, "family": args.family,
                       "AS_count": args.as_count, "nodes_per_AS": 10, "node_count": self.count,
                       "initial_swap_mib": self.initial_swap / MIB,
                       "build_root": str(self.baseline), "checks": [], "phase_times": {},
                       "evidence_encoding": self.evidence_encoding,
                       "create_workers": self.create_workers,
                       "claims_excluded": ["Internet representativeness", "traffic throughput",
                                           "full Internet FIB", "dual stack", "long duration endurance"]}
        self.monitor = threading.Thread(target=self.watch_resources, daemon=True)

    def design_metadata(self):
        return {
            "unit": "one VM, one clean deployment; technical checks, no population inference",
            "topology": "10 BIRD+Agent nodes per ASN; one RR hub +9 iBGP clients; AS hubs form a binary eBGP tree",
            "routing_policy": "synthetic export-all calibration; not customer-provider or Internet representative",
            "family": self.args.family, "prefixes": "one /28 IPv4 or /64 IPv6 originated per node; link routes also exported",
            "auto_mode": "strict_urpf on all nodes; 1000ms interval; command timeout2000ms",
            "container_limits": "512MiB memory, memory+swap512MiB, 1CPU, 128PIDs; image pinned by digest",
            "route_gate": "all directed BGP sessions established and all remote endpoint prefixes in every FIB",
            "auto_gate": "all nodes have verified installed table <=10seconds old, enabled/non-dry-run/not-paused/no-error; phase applied/in_sync or normal periodic checking; initial checking without installed hash cannot pass",
            "stability": "two identical full routing observations separated by >=3seconds",
            "hold_seconds": self.args.hold, "hold_gate": "all nodes polled every15s, no new reconciliation errors, skip count advances",
            "observation_encoding": self.evidence_encoding,
            "creation_workers": self.create_workers,
            "traffic": "every node sends3 UDP echo requests, source bound to owned endpoint, all3 replies required",
            "change": "add/withdraw blackhole-originated prefix at last node; require FIB change on ALL nodes and automatic rule hash update on every REMOTE node; originating blackhole is not a SAV allow rule",
            "convergence_deadline_seconds": 180,
            "safe_stop": ["startup stops below3GiB available", "runtime stops below2GiB available",
                          "swap increase>64MiB", "CPU>=95% for45seconds"],
            "steady_resource_gate": "meanCPU<70%, p95CPU<85%, min available>=3GiB, swap growth<=1MiB",
            "stage_plan": "1,5,10,20,40,60,80,100AS until first failure/safety stop; refine bracket and fresh repeat",
            "exclusions": self.report["claims_excluded"]}

    def configure_generated(self):
        # The general generator marks both ends of same-AS links as RR clients.
        # Explicitly configure only each AS hub as the route reflector.
        for node in range(1, self.count + 1):
            cfg = self.generated / str(node) / "bird.conf"
            text = cfg.read_text()
            if (node - 1) % 10:
                text = text.replace("  rr client;\n", "")
            cfg.write_text(text)

    def watch_resources(self):
        psutil.cpu_percent()
        high_cpu = 0
        with (self.run / "resources.jsonl").open("x") as out:
            while not self.stop_monitor.wait(1):
                mem, swap = psutil.virtual_memory(), psutil.swap_memory()
                cpu = psutil.cpu_percent()
                row = {"time": time.time(), "phase": self.phase, "cpu_percent": cpu,
                       "mem_available_gib": mem.available / GIB, "mem_used_gib": mem.used / GIB,
                       "swap_used_mib": swap.used / MIB, "swap_in_bytes": swap.sin,
                       "swap_out_bytes": swap.sout, "load": os.getloadavg(),
                       "memory_pressure": Path("/proc/pressure/memory").read_text(),
                       "cpu_pressure": Path("/proc/pressure/cpu").read_text()}
                self.samples.append(row)
                out.write(json.dumps(row) + "\n")
                out.flush()
                high_cpu = high_cpu + 1 if cpu >= 95 else 0
                reason = None
                if mem.available < getattr(self, "runtime_min_available", 2 * GIB):
                    reason = "available memory below runtime reserve"
                elif swap.used - self.initial_swap > getattr(self, "runtime_swap_limit", 64 * MIB):
                    reason = "swap usage grew beyond configured runtime limit"
                elif high_cpu >= 45:
                    reason = "host CPU >=95% for 45 seconds"
                if reason and not self.abort.is_set():
                    self.abort_reason = reason
                    self.abort.set()
                    print(json.dumps({"safety_stop": reason}), flush=True)

    def guard(self, launching=False):
        if self.abort.is_set():
            raise SafetyStop(self.abort_reason)
        if launching and psutil.virtual_memory().available < getattr(self, "startup_min_available", 3 * GIB):
            raise SafetyStop("available memory below 3 GiB startup reserve")

    def parallel(self, function, items):
        with ThreadPoolExecutor(max_workers=8) as pool:
            return list(pool.map(function, items))

    def namespace_command(self, node, *argv):
        # Batch ownership is refreshed before every observation/probe. Before each
        # command additionally check live init PID + pinned namespace identity.
        info = self.nodes[node]
        fd = self.namespace_fds[node]
        inode = os.stat(f"/proc/{info['pid']}/ns/net").st_ino
        if inode != info["netns_inode"] or os.fstat(fd).st_ino != inode or inode == os.stat("/proc/self/ns/net").st_ino:
            raise RuntimeError("Owned namespace identity changed")
        return ["nsenter", f"--net=/proc/{os.getpid()}/fd/{fd}", *map(str, argv)]

    def verify_ownership(self):
        states = json.loads(self.command(["docker", "inspect", *[x["id"] for x in self.nodes.values()]], timeout=60).stdout)
        by_id = {x["Id"]: x for x in states}
        for node, info in self.nodes.items():
            state = by_id[info["id"]]
            if state["Config"]["Labels"].get(LABEL) != self.args.run_id:
                raise RuntimeError("Ownership label mismatch")
            validate_namespace(state, info["pid"], info["netns_inode"],
                               os.fstat(self.namespace_fds[node]).st_ino, os.stat("/proc/self/ns/net").st_ino)

    def ns(self, node, *argv, **kwargs):
        return self.command(self.namespace_command(node, *argv), **kwargs)

    def bird(self, node, query, check=True):
        return self.command([self.root / "router/birdc", "-s", self.generated / str(node) / "bird.ctl", query],
                            timeout=8, check=check).stdout

    def api(self, node):
        raw = self.ns(node, "curl", "--silent", "--show-error", "--max-time", "5",
                      "http://127.0.0.1:8888/data_plane", timeout=8).stdout
        response = json.loads(raw)
        if response.get("code") != "0000":
            raise RuntimeError("Agent status error")
        return response["data"]["data_plane"]

    def prepare(self):
        self.report["host_before"] = self.host_snapshot()
        self.monitor.start()
        for directory in ("router", "target/release", "lab/base_configs"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.report["provenance"] = {}
        for rel in ("Cargo.toml", "savop.toml", "router/bird", "router/birdc", "router/birdcl",
                    "target/release/sav_agent", "target/release/sav_lab_gen"):
            source, target = self.baseline / rel, self.root / rel
            if target.exists():
                if sha(source) != sha(target):
                    raise RuntimeError("Build root changed")
            else:
                shutil.copy2(source, target)
            self.report["provenance"][rel] = sha(source)
        for name in ("run_capacity.py", "capacity_probe.py", "run_five_as.py", "packet_probe.py", "evidence_io.py", "bounded_tasks.py", "evidence_paths.py"):
            source = Path(__file__).with_name(name)
            shutil.copy2(source, self.run / name)
            self.report["provenance"][name] = sha(source)
        source = self.run / "scene.json"
        dump(source, self.scene)
        self.design = self.design_metadata()
        dump(self.run / "design.json", self.design)
        env = dict(os.environ, SAVOP_ROOT=str(self.root))
        self.command([self.root / "target/release/sav_lab_gen", "--config", source, "--out", self.generated],
                     env=env, cwd=self.root, timeout=60)
        self.configure_generated()
        image_info = json.loads(self.command(["docker", "image", "inspect", IMAGE]).stdout)[0]
        self.report["image"] = image_info["Id"]
        started = time.monotonic()
        self.phase = "create_containers"
        # Bounded scheduler joins all running creates before an exception can
        # reach finally-cleanup. Wiring stays serial and starts only afterwards.
        run_bounded(self.create_node, range(1, self.count + 1), self.create_workers)
        self.nodes = dict(sorted(self.nodes.items()))
        self.namespace_fds = dict(sorted(self.namespace_fds.items()))
        dump(self.run / "ownership.json", self.nodes)
        self.phase = "wire"
        short = hashlib.sha256(self.args.run_id.encode()).hexdigest()[:6]
        for i, (a, b) in enumerate(self.edges):
            self.guard()
            left, right = f"k{short}{i}a", f"k{short}{i}b"
            self.command(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            self.created_links.append((left, right))
            for name, node, peer in ((left, a, b), (right, b, a)):
                self.command(["ip", "link", "set", name, "netns", self.nodes[node]["pid"]])
                self.ns(node, "ip", "link", "set", name, "name", f"eth_{peer}")
        self.phase = "start_agents"
        self.parallel(self.start_node, list(self.nodes))
        self.report["phase_times"]["deployment_seconds"] = time.monotonic() - started
        print(json.dumps({"started_nodes": len(self.nodes), "deployment_seconds": time.monotonic() - started}), flush=True)

    def create_node(self, node):
        self.guard(launching=True)
        name = f"k5-{self.args.run_id}-n{node}"
        if self.inspect(name):
            raise RuntimeError("Container name already exists")
        cfg = self.generated / str(node)
        command = ["docker", "run", "-d", "--name", name, "--label", f"{LABEL}={self.args.run_id}",
                   "--network", "none", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                   "--security-opt", "no-new-privileges", "--memory", "512m", "--memory-swap", "512m",
                   "--cpus", "1", "--pids-limit", "128",
                   "--mount", f"type=bind,source={self.root},target=/build,readonly",
                   "--mount", f"type=bind,source={cfg},target=/node",
                   "--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv4.conf.all.rp_filter=0",
                   "--sysctl", "net.ipv4.conf.default.rp_filter=0", "--sysctl", "net.ipv6.conf.all.forwarding=1",
                   "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--sysctl", "net.ipv6.conf.default.disable_ipv6=0",
                   "--sysctl", "net.ipv6.conf.default.keep_addr_on_down=1",
                   "--entrypoint", "/bin/sleep", self.report["image"], "infinity"]
        try:
            cid = self.command(command, timeout=45).stdout.strip()
        except Exception:
            # Preserve the existing exact-name/label recovery for CLI timeouts
            # after creation. Never claim or delete another run's container.
            partial = self.inspect(name)
            if partial and partial["Config"]["Labels"].get(LABEL) == self.args.run_id:
                with self.creation_lock:
                    self.nodes[node] = {"id": partial["Id"], "name": name}
            raise
        with self.creation_lock:
            self.nodes[node] = {"id": cid, "name": name}
        state = self.owned(node)
        pid = state["State"]["Pid"]
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        with self.creation_lock:
            self.namespace_fds[node] = fd
            self.nodes[node].update(pid=pid, netns_inode=os.fstat(fd).st_ino)
            count = len(self.nodes)
        validate_namespace(state, pid, os.fstat(fd).st_ino, os.fstat(fd).st_ino, os.stat("/proc/self/ns/net").st_ino)
        if node % 50 == 0:
            print(json.dumps({"created_nodes": count, "available_gib": psutil.virtual_memory().available / GIB}), flush=True)

    def start_node(self, node):
        self.guard(launching=True)
        self.execute(node, "/build/router/bird", "-p", "-c", "/node/bird.conf", timeout=10)
        self.ns(node, "sh", str(self.generated / "clab_batches" / f"{node}.sh"))
        self.ns(node, "ip", "link", "add", "endpoint", "type", "dummy")
        self.ns(node, "ip", "link", "set", "endpoint", "up")
        length = 32 if self.args.family == 4 else 128
        self.ns(node, "ip", "addr", "add", f"{address(node, self.args.family)}/{length}", "dev", "endpoint", "nodad")
        cfg = self.generated / str(node)
        dump(cfg / "signal.json", {"command": "start"})
        environment = {"SAVOP_DATA_PATH": "/node", "SAVOP_CONFIG_PATH": "/node/sa.json", "SAVOP_SIGNAL_PATH": "/node/signal.json",
                       "SAVOP_LOG_DIR": "/node/log", "SAVOP_BIRD_BIN": "/build/router/bird", "SAVOP_BIRD_CONFIG": "/node/bird.conf",
                       "SAVOP_BIRD_SOCKET": "/node/bird.ctl", "SAVOP_BIRD_PID_FILE": "/node/bird.pid",
                       "SAVOP_AGENT_ADDR": "127.0.0.1:8888",
                       "SAVOP_DATA_PLANE_INTERVAL_MS": "1000", "SAVOP_DATA_PLANE_COMMAND_TIMEOUT_MS": "2000",
                       "SAVOP_DATA_PLANE_AUTO": str(getattr(self, "data_plane_auto", True)).lower(),
                       "PATH": "/build/router:/usr/sbin:/usr/bin:/sbin:/bin"}
        command = ["docker", "exec", "-d"]
        for key, value in environment.items():
            command += ["-e", key + "=" + value]
        self.command(command + [self.nodes[node]["id"], "/build/target/release/sav_agent"], timeout=30)

    def observe_node(self, node):
        self.guard()
        try:
            protocols = self.bird(node, "show protocols", check=False)
            bgp = [line.split() for line in protocols.splitlines() if re.match(r"dsav_\d+_\d+\s", line)]
            expected = sum(node in pair for pair in self.edges)
            routes = json.loads(self.ns(node, "ip", "-j", f"-{self.args.family}", "route", "show", "table", "main").stdout)
            reachable = {r.get("dst") for r in routes if r.get("type", "unicast") == "unicast"}
            missing = [p for other, p in self.endpoint_prefixes.items() if other != node and p not in reachable]
            canonical = sorted(json.dumps({k: r[k] for k in ("dst", "dev", "gateway", "type", "nexthops") if k in r}, sort_keys=True)
                               for r in routes)
            state = self.api(node)
            age = time.time() - (state.get("last_verified") or 0)
            auto_ok = installed_and_fresh(state, time.time())
            ready = len(bgp) == expected and all("Established" in row for row in bgp) and not missing and auto_ok
            return {"node": node, "ready": ready, "bgp_count": len(bgp), "expected_bgp": expected,
                    "protocols": protocols, "missing_prefixes": missing, "fib": routes,
                    "fib_hash": hashlib.sha256(json.dumps(canonical).encode()).hexdigest(),
                    "auto": state, "auto_age_seconds": age, "at": time.time()}
        except SafetyStop:
            raise
        except Exception as exc:
            return {"node": node, "ready": False, "error": str(exc), "at": time.time()}

    def observe(self, tag):
        self.guard()
        self.verify_ownership()
        rows = self.parallel(self.observe_node, list(self.nodes))
        self.write_observation(tag, rows)
        return rows

    def write_observation(self, tag, rows):
        write_json(self.run / f"observation-{tag}.json", rows, encoding=self.evidence_encoding)

    def wait_ready(self, tag, extra=None, previous=None):
        started, last_hash, same_since, attempt = time.monotonic(), None, None, 0
        while time.monotonic() - started < 180:
            rows = self.observe(f"{tag}-{attempt:03d}")
            attempt += 1
            if time.monotonic() - started >= 180:
                break
            ready = all(row["ready"] for row in rows)
            if ready and extra is not None:
                for row in rows:
                    match = [r for r in row["fib"] if r.get("dst") == extra[0]]
                    ready &= bool(match) == extra[1]
                    # At the origin the static route is deliberately blackhole:
                    # it is advertised, but is not an allow entry in uRPF.
                    if row["node"] != self.count:
                        ready &= row["auto"]["last_hash"] != previous[row["node"]]["auto"]["last_hash"]
                        ready &= row["auto"]["refresh_count"] > previous[row["node"]]["auto"]["refresh_count"]
            hashes = [(row["node"], row.get("fib_hash")) for row in rows]
            same_since = stability_start(ready, hashes, last_hash, same_since, time.monotonic())
            if same_since is not None and time.monotonic() - same_since >= 3:
                self.report["phase_times"][tag + "_seconds"] = time.monotonic() - started
                self.report["checks"].append({"tag": tag, "pass": True, "observations": attempt})
                return {row["node"]: row for row in rows}
            last_hash = hashes
            time.sleep(1)
        bad = [row for row in rows if not row["ready"]]
        raise RuntimeError(f"Readiness deadline: {tag}; bad nodes={[r['node'] for r in bad]}")

    def traffic(self, tag):
        self.guard()
        self.verify_ownership()
        token = self.args.run_id + "-" + tag
        ready_file = self.run / ("echo-ready-" + tag)
        probe = self.run / "capacity_probe.py"
        destination = address(1, self.args.family)
        with (self.run / f"echo-{tag}.log").open("x") as out:
            server = subprocess.Popen(self.namespace_command(1, "python3", probe, "server", "--address", destination,
                                      "--token", token, "--ready", ready_file), stdout=out, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 8
                while not ready_file.exists():
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("Echo server failed")
                    time.sleep(0.05)

                def client(node):
                    self.guard()
                    return json.loads(self.ns(node, "python3", probe, "client", "--address", destination, "--token", token,
                                              "--source", address(node, self.args.family), timeout=10).stdout)

                rows = self.parallel(client, list(self.nodes))
                dump(self.run / f"packets-{tag}.json", rows)
                passed = all(len(row["sent"]) == len(row["received"]) == 3 for row in rows)
                self.report["checks"].append({"tag": "traffic-" + tag, "pass": passed,
                                             "sent": 3 * len(rows), "replies": sum(len(row["received"]) for row in rows)})
                if not passed:
                    raise RuntimeError("UDP echo loss")
            finally:
                self.ns(1, "python3", probe, "stop", "--address", destination, "--token", token, check=False)
                try:
                    server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    server.terminate()
                    server.wait(timeout=5)

    def changes(self, baseline):
        self.phase = "route_changes"
        extra = "198.19.240.0/24" if self.args.family == 4 else "fd42:2400:ffff::/64"
        cfg = self.generated / str(self.count) / "bird.conf"
        original = cfg.read_text()
        needle = f"  route {prefix(self.count, self.args.family)} blackhole;"
        if original.count(needle) != 1:
            raise RuntimeError("Unexpected generated configuration")
        changed = original.replace(needle, needle + f"\n  route {extra} blackhole;")
        (self.run / "churn-before.conf").write_text(original)
        (self.run / "churn-added.conf").write_text(changed)
        cfg.write_text(changed)
        self.bird(self.count, "configure")
        added = self.wait_ready("prefix-added", (extra, True), baseline)
        self.traffic("added")
        cfg.write_text(original)
        self.bird(self.count, "configure")
        restored = self.wait_ready("prefix-withdrawn", (extra, False), added)
        self.traffic("withdrawn")
        return restored

    def qualify(self):
        self.phase = "converge"
        initial = self.wait_ready("initial")
        self.traffic("initial")
        baseline = self.changes(initial)
        self.phase = "steady"
        started, attempt = time.monotonic(), 0
        while time.monotonic() - started < self.args.hold:
            self.guard()
            time.sleep(1)
            if time.monotonic() - started >= attempt * 15:
                rows = self.observe(f"steady-{attempt:03d}")
                attempt += 1
                for row in rows:
                    if not row["ready"] or row["auto"]["error_count"] != baseline[row["node"]]["auto"]["error_count"]:
                        raise RuntimeError(f"Steady-state error on node{row['node']}")
        final = self.observe("steady-final")
        if not all(row["ready"] and row["auto"]["skip_count"] > baseline[row["node"]]["auto"]["skip_count"]
                   and row["auto"]["error_count"] == baseline[row["node"]]["auto"]["error_count"] for row in final):
            raise RuntimeError("Reconciliation did not advance cleanly during steady state")
        self.phase = "final_traffic"
        self.traffic("final")
        rows = [s for s in self.samples if s["phase"] == "steady"]
        cpu = sorted(s["cpu_percent"] for s in rows)
        resource = {"samples": len(rows), "cpu_mean_percent": statistics.mean(cpu),
                    "cpu_p95_percent": cpu[min(len(cpu) - 1, int(len(cpu) * .95))],
                    "available_min_gib": min(s["mem_available_gib"] for s in rows),
                    "available_mean_gib": statistics.mean(s["mem_available_gib"] for s in rows),
                    "swap_max_mib": max(s["swap_used_mib"] for s in rows),
                    "hold_elapsed_seconds": time.monotonic() - started}
        self.report["steady_resources"] = resource
        resource["swap_growth_mib"] = resource["swap_max_mib"] - self.initial_swap / MIB
        passed = (resource["cpu_mean_percent"] < 70 and resource["cpu_p95_percent"] < 85
                  and resource["available_min_gib"] >= 3 and resource["swap_max_mib"] - self.initial_swap / MIB <= 1)
        self.report["checks"].append({"tag": "steady-resource-margin", "pass": passed})
        self.report["status"] = "passed_capacity_tier" if passed else "failed_resource_margin"

    def cleanup(self):
        self.phase = "cleanup"
        errors = []

        def remove(node):
            try:
                state = self.owned(node)
                self.command(["docker", "rm", "-f", state["Id"]], timeout=60)
                if self.inspect(state["Id"]):
                    raise RuntimeError("Container remains")
            except Exception as exc:
                errors.append(f"{node}: {exc}")

        self.parallel(remove, list(self.nodes))
        for fd in self.namespace_fds.values():
            os.close(fd)
        self.namespace_fds.clear()
        self.stop_monitor.set()
        if self.monitor.is_alive():
            self.monitor.join(timeout=3)
        self.report["cleanup_errors"] = errors
        self.report["host_after"] = self.host_snapshot()
        before, after = self.report.get("host_before"), self.report["host_after"]
        if before:
            normalize = lambda text: re.sub(r"counter packets \d+ bytes \d+", "counter", text)
            self.report["host_unchanged"] = (before["routes4"] == after["routes4"] and before["routes6"] == after["routes6"]
                and normalize(before["nft"]) == normalize(after["nft"])
                and {x["ifname"] for x in before["links"]} == {x["ifname"] for x in after["links"]})
        if errors or self.report.get("host_unchanged") is False:
            self.report["status"] = "failed_cleanup_or_host_invariant"


def main(args):
    if os.geteuid() != 0:
        raise SystemExit("Linux root required")
    lab = CapacityLab(args)
    try:
        lab.prepare()
        lab.qualify()
    except SafetyStop as exc:
        lab.report.update(status="stopped_safety_reserve", error=str(exc))
        print(json.dumps({"safety_stop": str(exc)}), flush=True)
    except KeyboardInterrupt:
        lab.report.update(status="operator_interrupted", error="SIGINT or keyboard interruption; owned cleanup requested")
    except Exception:
        lab.report.update(status="failed", error=traceback.format_exc())
        print(lab.report["error"], flush=True)
    finally:
        lab.report["created_nodes"] = len(lab.nodes)
        lab.cleanup()
        dump(lab.run / "result.json", lab.report)
    print(json.dumps({"status": lab.report["status"], "AS": args.as_count,
                      "resources": lab.report.get("steady_resources"), "report": str(lab.run / "result.json")}), flush=True)
    return int(lab.report["status"] != "passed_capacity_tier")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--family", type=int, choices=(4, 6), default=4)
    parser.add_argument("--as-count", type=int, required=True)
    parser.add_argument("--hold", type=int, default=60)
    parser.add_argument("--evidence-encoding", choices=("pretty", "compact"), default="compact",
                        help="Lossless node-wise compact JSON; pretty retained for A/B and compatibility")
    parser.add_argument("--create-workers", type=int, choices=(1, 2, 4, 8), default=1,
                        help="Bounded container creation only; wiring remains serial")
    options = parser.parse_args()
    if options.hold < 30:
        parser.error("Use >=30seconds steady observation")
    raise SystemExit(main(options))
