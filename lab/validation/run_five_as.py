"""Reproducible five-AS runtime calibration, never host-wide lab cleanup.

Requires root on a dedicated Linux development VM, Docker and existing SAVOP
build artifacts. Containers have no management/uplink interfaces or published
ports. Created veth endpoints both enter owned namespaces. All evidence is
written to a fresh run directory; cleanup checks full container IDs and labels.
This is a synthetic calibration fixture, not a representative Internet sample.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import time
import traceback
from evidence_paths import validate_evidence_root


EDGES = [(1, 2, 1), (1, 3, 1), (2, 3, None), (2, 4, 2), (3, 4, 3), (3, 5, 3)]
IMAGE = "savop_runtime_clab:latest"
LABEL = "org.savop.k5-validation"


def validate_namespace(state, expected_pid, expected_inode, actual_inode, host_inode):
    if not state["State"]["Running"] or state["State"]["Pid"] != expected_pid or expected_pid <= 0:
        raise RuntimeError("Container stopped or PID changed")
    if state["HostConfig"]["NetworkMode"] != "none" or state["HostConfig"]["Privileged"]:
        raise RuntimeError("Unsafe container namespace")
    if actual_inode != expected_inode or actual_inode == host_inode:
        raise RuntimeError("Network namespace changed or points to the host")


def dump(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prefix(node, version):
    return f"198.18.0.{node * 16}/28" if version == 4 else f"fd42:2400:{node:x}::/64"


def address(node, version):
    return str(ipaddress.ip_network(prefix(node, version)).network_address + 1)


def fixture(version):
    return {"devices": {str(n): {"as": 4200000000 + n, "prefixes": {prefix(n, version): {}}} for n in range(1, 6)},
            "links": [[str(a), str(b), "dsav"] for a, b, _ in EDGES],
            "routing_policy": {"model": "customer-provider-v1", "links": [
                {"a": str(a), "b": str(b), "relationship": "p2c" if p else "p2p", "provider": str(p) if p else None}
                for a, b, p in EDGES]},
            "auto_ip_version": version, "sav_apps": ["strict_urpf", "loose_urpf", "fp_urpf"],
            "active_sav_app": "strict_urpf", "enable_rpki": False, "prefix_method": "blackhole",
            "ignore_nets": ["10.0.0.0/8"] if version == 4 else ["fec::/16"]}


class Lab:
    def __init__(self, args):
        self.args = args
        self.root = validate_evidence_root(args.root, "k5-five-as-")
        self.baseline = args.build.resolve(strict=True)
        if not re.fullmatch(r"[a-z0-9-]{3,24}", args.run_id):
            raise ValueError("run-id must be 3..24 lowercase letters/digits/dashes")
        self.run = self.root / args.run_id
        self.run.mkdir(exist_ok=False)
        self.log = self.run / "commands.jsonl"
        self.nodes, self.created_links = {}, []
        self.namespace_fds, self.probe_sequence = {}, 0
        self.generated = self.root / ("savop_run_" + args.run_id)
        self.report = {"status": "in_progress", "run_id": args.run_id, "family": args.family,
                       "fixture_origin": "synthetic manually specified policy calibration",
                       "claims_excluded": ["Internet representativeness", "1000-AS performance", "FP/EFP qualification", "independent hardware replication"]}

    def command(self, argv, *, check=True, timeout=30, input=None, env=None, cwd=None):
        started = time.time()
        result = subprocess.run([str(x) for x in argv], input=input, text=True, capture_output=True,
                                timeout=timeout, env=env, cwd=cwd)
        with self.log.open("a") as handle:
            handle.write(json.dumps({"argv": [str(x) for x in argv], "started": started,
                                     "elapsed": time.time() - started, "rc": result.returncode,
                                     "stdout": result.stdout, "stderr": result.stderr}) + "\n")
        if check and result.returncode:
            raise RuntimeError(f"Command failed: {argv}\n{result.stdout}\n{result.stderr}")
        return result

    def inspect(self, identifier):
        result = self.command(["docker", "inspect", identifier], check=False)
        return json.loads(result.stdout)[0] if result.returncode == 0 else None

    def owned(self, node):
        state = self.inspect(self.nodes[node]["id"])
        if not state or state["Config"]["Labels"].get(LABEL) != self.args.run_id:
            raise RuntimeError("Container missing or ownership changed")
        return state

    def execute(self, node, *argv, **kwargs):
        return self.command(["docker", "exec", self.nodes[node]["id"], *argv], **kwargs)

    def namespace_command(self, node, *argv):
        state = self.owned(node)
        fd = self.namespace_fds[node]
        validate_namespace(state, self.nodes[node]["pid"], self.nodes[node]["netns_inode"],
                           os.fstat(fd).st_ino, os.stat("/proc/self/ns/net").st_ino)
        # Pin the namespace object, not a cached PID that could be recycled.
        return ["nsenter", f"--net=/proc/{os.getpid()}/fd/{fd}", *map(str, argv)]

    def next_token(self, label):
        self.probe_sequence += 1
        return f"{self.args.run_id}-{self.probe_sequence:04d}-{label}"

    def bird(self, node, query, check=True):
        return self.execute(node, "/build/router/birdc", "-s", "/node/bird.ctl", query, check=check).stdout

    def api(self, node, path, data=None):
        argv = ["curl", "--silent", "--show-error", "--max-time", "5"]
        if data is not None:
            argv += ["-H", "Content-Type: application/json", "-d", json.dumps(data)]
        result = json.loads(self.execute(node, *argv, "http://127.0.0.1:8888" + path).stdout)
        if not isinstance(result, dict) or result.get("code") != "0000":
            raise RuntimeError(f"API rejected {path}: {result}")
        return result

    def agent_environment(self, node, environment):
        """Subclass hook; baseline remains automatic-update-disabled."""
        return environment

    def prepare(self):
        for tool in (Path(__file__), Path(__file__).with_name("packet_probe.py"),
                     Path(__file__).with_name("evidence_paths.py")):
            shutil.copy2(tool, self.run / tool.name)
        # Run root is separate from the baseline; only copy generator prerequisites.
        for directory in ("router", "target/release", "lab/base_configs"):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        for rel in ("Cargo.toml", "savop.toml", "router/bird", "router/birdc", "router/birdcl",
                    "target/release/sav_agent", "target/release/sav_lab_gen"):
            source, target = self.baseline / rel, self.root / rel
            if target.exists():
                if sha(source) != sha(target):
                    raise RuntimeError(f"Root build differs: {rel}; use a fresh root")
            else:
                shutil.copy2(source, target)
        source = self.run / "scene.json"
        dump(source, fixture(self.args.family))
        dump(self.run / "design.json", {
            "unique_AS": 5, "edges": EDGES, "seed": 240005,
            "order": ["no-SAV routing and all-pairs ping", "policy export negatives", "UDP no-SAV/strict/loose"],
            "unit": "one isolated five-AS run on one VM; packets are technical probes, not independent replicates",
            "route_gate": "all 12 directed BGP sessions established; all remote prefixes in every main FIB; stable for >=3 seconds",
            "packet_gate": "10 valid checksummed UDP datagrams per case; unique sequence numbers; post-filter UDP reception",
            "controls": "same fixture and deterministic packet list; no-SAV before/after each filter; shuffled cases seed240005",
            "UDP_cases": {"legal": "AS4 prefix at AS3 eth_4: pass", "wrong_interface": "AS2 prefix at AS3 eth_4: strict drop, loose pass",
                          "unknown": "unadvertised lab prefix: strict/loose drop"},
            "filter_scope": "install at AS3 only, traffic AS4 -> AS3 -> AS5 plus AS3 local input",
            "discovery": "current binaries are tested as-is; failures are retained, never silently redefined as pass"})
        self.report["provenance"] = {rel: sha(self.root / rel) for rel in (
            "target/release/sav_agent", "target/release/sav_lab_gen", "router/bird")}
        self.report["provenance"].update({"runner": sha(__file__), "packet_probe": sha(Path(__file__).with_name("packet_probe.py"))})
        self.report["provenance"]["evidence_paths.py"] = sha(Path(__file__).with_name("evidence_paths.py"))
        self.report["image"] = json.loads(self.command(["docker", "image", "inspect", IMAGE]).stdout)[0]["Id"]
        env = dict(os.environ, SAVOP_ROOT=str(self.root))
        self.command([self.root / "target/release/sav_lab_gen", "--config", source, "--out", self.generated], env=env, cwd=self.root)
        self.report["host_before"] = self.host_snapshot()
        for node in range(1, 6):
            name = f"k5-{self.args.run_id}-n{node}"
            if self.inspect(name):
                raise RuntimeError(f"Existing container, refusing reuse: {name}")
            cmd = ["docker", "run", "-d", "--name", name, "--label", f"{LABEL}={self.args.run_id}",
                   "--network", "none", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                   "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
                   "--mount", f"type=bind,source={self.root},target=/build,readonly",
                   "--mount", f"type=bind,source={self.generated / str(node)},target=/node",
                   "--sysctl", "net.ipv4.ip_forward=1", "--sysctl", "net.ipv4.conf.all.rp_filter=0",
                   "--sysctl", "net.ipv4.conf.default.rp_filter=0", "--sysctl", "net.ipv6.conf.all.forwarding=1",
                   "--sysctl", "net.ipv6.conf.all.disable_ipv6=0", "--sysctl", "net.ipv6.conf.default.disable_ipv6=0",
                   "--sysctl", "net.ipv6.conf.default.keep_addr_on_down=1",
                   "--entrypoint", "/bin/sleep", IMAGE, "infinity"]
            cid = self.command(cmd).stdout.strip()
            self.nodes[node] = {"id": cid, "name": name}
            state = self.owned(node)
            self.nodes[node]["pid"] = state["State"]["Pid"]
            if state["HostConfig"]["NetworkMode"] != "none" or state["HostConfig"]["Privileged"]:
                raise RuntimeError("Network isolation failed")
            pid = state["State"]["Pid"]
            fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
            self.namespace_fds[node] = fd
            self.nodes[node]["netns_inode"] = os.fstat(fd).st_ino
            self.namespace_command(node, "true")  # Validate the pinned object before use.
        dump(self.run / "ownership.json", self.nodes)
        short = hashlib.sha256(self.args.run_id.encode()).hexdigest()[:6]
        for i, (a, b, _) in enumerate(EDGES):
            left, right = f"k{short}{i}a", f"k{short}{i}b"
            self.command(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            self.created_links.append((left, right))
            for name, node, peer in ((left, a, b), (right, b, a)):
                self.command(["ip", "link", "set", name, "netns", self.nodes[node]["pid"]])
                self.execute(node, "ip", "link", "set", name, "name", f"eth_{peer}")
        for node in self.nodes:
            self.execute(node, "sh", f"/build/{self.generated.name}/clab_batches/{node}.sh")
            self.execute(node, "ip", "link", "add", "endpoint", "type", "dummy")
            self.execute(node, "ip", "link", "set", "endpoint", "up")
            length = 32 if self.args.family == 4 else 128
            self.execute(node, "ip", "addr", "add", f"{address(node, self.args.family)}/{length}", "dev", "endpoint", "nodad")
            cfg = self.generated / str(node)
            dump(cfg / "signal.json", {"command": "start"})
            environment = {"SAVOP_DATA_PATH": "/node", "SAVOP_CONFIG_PATH": "/node/sa.json", "SAVOP_SIGNAL_PATH": "/node/signal.json",
                           "SAVOP_LOG_DIR": "/node/log", "SAVOP_BIRD_BIN": "/build/router/bird", "SAVOP_BIRD_CONFIG": "/node/bird.conf",
                           "SAVOP_BIRD_SOCKET": "/node/bird.ctl", "SAVOP_BIRD_PID_FILE": "/node/bird.pid",
                           "SAVOP_AGENT_ADDR": "127.0.0.1:8888", "SAVOP_DATA_PLANE_AUTO": "false", "PATH": "/build/router:/usr/sbin:/usr/bin:/sbin:/bin"}
            environment = self.agent_environment(node, environment)
            argv = ["docker", "exec", "-d"]
            for k, v in environment.items():
                argv += ["-e", f"{k}={v}"]
            self.command(argv + [self.nodes[node]["id"], "/build/target/release/sav_agent"])

    def host_snapshot(self):
        return {"links": json.loads(self.command(["ip", "-j", "link"]).stdout),
                "routes4": json.loads(self.command(["ip", "-j", "-4", "route"]).stdout),
                "routes6": json.loads(self.command(["ip", "-j", "-6", "route"]).stdout),
                "nft": self.command(["nft", "list", "ruleset"]).stdout}

    def wait_routes(self, tag):
        start, same_since, previous, observations = time.monotonic(), None, None, []
        while time.monotonic() - start < 90:
            snapshot, ready = {}, True
            for node in self.nodes:
                protocols = self.bird(node, "show protocols", check=False)
                bgp = [line.split() for line in protocols.splitlines() if re.match(r"dsav_\d+_\d+\s", line)]
                neighbors = sum(node in (a, b) for a, b, _ in EDGES)
                ready &= len(bgp) == neighbors and all("Established" in row for row in bgp)
                routes = json.loads(self.execute(node, "ip", "-j", f"-{self.args.family}", "route", "show", "table", "main").stdout)
                reachable = {r.get("dst") for r in routes if r.get("type", "unicast") == "unicast"}
                ready &= all(prefix(other, self.args.family) in reachable for other in self.nodes if other != node)
                # Exclude timer/cache/age data; retain the actual forwarding choices.
                canonical = sorted((json.dumps({k: r[k] for k in ("dst", "dev", "gateway", "type", "nexthops") if k in r}, sort_keys=True) for r in routes))
                snapshot[str(node)] = {"bgp": sorted(row[0] for row in bgp if "Established" in row), "fib": canonical}
            now = time.monotonic()
            observations.append({"elapsed": now - start, "ready": bool(ready), "snapshot": snapshot})
            if ready and previous == snapshot:
                if same_since is not None and now - same_since >= 3:
                    dump(self.run / f"routes-{tag}.json", observations)
                    return
            else:
                same_since = now if ready else None
            previous = snapshot
            time.sleep(0.4)
        dump(self.run / f"routes-{tag}.json", observations)
        raise RuntimeError("BGP/FIB readiness or stability gate timed out")

    def route_tests(self):
        self.wait_routes("initial")
        isolation = {}
        for node in self.nodes:
            links = json.loads(self.execute(node, "ip", "-j", "link").stdout)
            expected = {"lo", "endpoint"} | {f"eth_{b if a == node else a}" for a, b, _ in EDGES if node in (a, b)}
            if {x["ifname"] for x in links} != expected:
                raise RuntimeError("Unexpected network interface in lab namespace")
            nft = self.execute(node, "nft", "list", "ruleset").stdout
            if nft.strip():
                raise RuntimeError("No-SAV control already has nft rules")
            isolation[str(node)] = {"interfaces": sorted(expected), "nft": nft,
                                    "rp_filter": self.execute(node, "sysctl", "net.ipv4.conf.all.rp_filter").stdout}
        self.report["isolation"] = isolation
        tests = []
        for a in self.nodes:
            for b in self.nodes:
                if a != b:
                    result = self.execute(a, "ping", f"-{self.args.family}", "-n", "-c", "2", "-W", "1", "-I", address(a, self.args.family), address(b, self.args.family), check=False)
                    tests.append({"from": a, "to": b, "rc": result.returncode, "stdout": result.stdout})
        self.report["all_pairs_ping"] = tests
        if any(t["rc"] for t in tests):
            raise RuntimeError("No-SAV all-pairs ping failed")
        # Independent fixture oracle: leaf AS4 must never offer provider routes
        # to its other provider. AS2->AS3 peer export includes its AS4 customer,
        # but excludes its provider AS1 and AS5 learned through the peer.
        exports = []
        for node, peer, allowed in ((4, 2, {4}), (4, 3, {4}), (5, 3, {5}), (2, 3, {2, 4})):
            output = self.bird(node, f"show route export dsav_{node}_{peer}")
            actual = set(re.findall(r"(?m)^([0-9a-fA-F:.]+/\d+)\s", output))
            expected = {prefix(n, self.args.family) for n in allowed}
            exports.append({"from": node, "to": peer, "expected": sorted(expected), "actual": sorted(actual), "stdout": output})
            if actual != expected:
                self.report["policy_exports"] = exports
                raise RuntimeError("Export policy differs from independent fixture expectation")
        self.report["policy_exports"] = exports

    def probe(self, mode, case, destination):
        sources = {"legal": address(4, self.args.family), "wrong_interface": address(2, self.args.family),
                   "unknown": "198.19.200.1" if self.args.family == 4 else "fd42:2400:ee::1"}
        token = self.next_token(f"{mode}-{case}-{destination}")
        helper = Path(__file__).with_name("packet_probe.py")
        recv_cmd = self.namespace_command(destination, sys.executable, helper, "receive",
                                          "--destination", address(destination, self.args.family), "--token", token)
        receiver = subprocess.Popen(recv_cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            # stdout readiness is bounded independently of datagram collection.
            import select
            if not select.select([receiver.stdout], [], [], 5)[0] or receiver.stdout.readline().strip() != "READY":
                raise RuntimeError("UDP receiver failed readiness")
            mac = json.loads(self.execute(3, "ip", "-j", "link", "show", "dev", "eth_4").stdout)[0]["address"]
            tx = self.command(self.namespace_command(4, sys.executable, helper, "send", "--interface", "eth_3",
                               "--peer-mac", mac, "--source", sources[case], "--destination", address(destination, self.args.family), "--token", token))
            output, error = receiver.communicate(timeout=8)
            if receiver.returncode:
                raise RuntimeError("Receiver failed: " + error)
            rx, tx = json.loads(output), json.loads(tx.stdout)
            sequences = [p["payload"] for p in rx["packets"]]
            expected = 10 if mode.startswith("none") or case == "legal" or (mode == "loose_urpf" and case == "wrong_interface") else 0
            return {"mode": mode, "case": case, "destination_node": destination, "token": token,
                    "tx": tx, "rx": rx, "raw_receiver_stdout": output, "expected_received": expected,
                    "pass": tx["sent"] == 10 and rx["received"] == expected and len(set(sequences)) == len(sequences)}
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.communicate()

    def packet_tests(self):
        cases = [(case, dest) for case in ("legal", "wrong_interface", "unknown") for dest in (3, 5)]
        random.Random(240005).shuffle(cases)
        records, rules = [], []
        self.report["packet_tests"], self.report["installed_rules"] = records, rules
        for mode in ("none-before", "strict_urpf", "none-between", "loose_urpf", "none-after"):
            disabled = self.api(3, "/disable_sav_table", {})
            if self.execute(3, "nft", "list", "ruleset").stdout.strip():
                raise RuntimeError("SAV rules remained after disable")
            if not mode.startswith("none"):
                applied = self.api(3, "/enable_sav_table", {"active_app": mode, "dry_run": False})
            else:
                applied = disabled
            rules.append({"mode": mode, "api": applied, "nft": self.execute(3, "nft", "list", "ruleset").stdout,
                          "active_rules": self.api(3, "/active_sav_table")})
            for case, dest in cases:
                row = self.probe(mode, case, dest)
                records.append(row)
                print(json.dumps({k: row[k] for k in ("mode", "case", "destination_node", "pass")}), flush=True)
            if not mode.startswith("none"):
                # Keep BGP/route health separate from successful filter installation.
                self.report.setdefault("post_filter_protocols", {})[mode] = self.bird(3, "show protocols")
        return all(r["pass"] for r in records)

    def regression_tests(self):
        """Extra post-fix checks: specific route wins; failed transaction retains rules."""
        broad = "198.18.0.0/24" if self.args.family == 4 else "fd42:2400::/32"
        records = []
        self.execute(3, "ip", f"-{self.args.family}", "route", "add", broad, "dev", "eth_4")
        try:
            self.api(3, "/enable_sav_table", {"active_app": "strict_urpf"})
            for case in ("legal", "wrong_interface"):
                for dest in (3, 5):
                    records.append(self.probe("strict_urpf", case, dest))
            self.report["longest_prefix_regression"] = records
            self.report["overlap_rules"] = self.execute(3, "nft", "list", "ruleset").stdout
        finally:
            self.execute(3, "ip", f"-{self.args.family}", "route", "del", broad, "dev", "eth_4")
        self.api(3, "/enable_sav_table", {"active_app": "strict_urpf"})
        before = self.execute(3, "nft", "-s", "list", "table", "inet", "savop").stdout
        candidate = (self.generated / "3/log/savagent_nftables.rules").read_text()
        # An invalid chain reaches nft validation after the old-table deletion
        # in the same batch. It must not commit any deletion or partial update.
        candidate += "add rule inet savop chain_that_does_not_exist counter drop\n"
        failure = self.command(["docker", "exec", "-i", self.nodes[3]["id"], "nft", "-f", "-"], input=candidate, check=False)
        after = self.execute(3, "nft", "-s", "list", "table", "inet", "savop").stdout
        preserved = failure.returncode != 0 and before == after
        unknown = self.probe("strict_urpf", "unknown", 5)
        self.report["atomic_failure_regression"] = {"rejected": failure.returncode != 0, "stderr": failure.stderr,
                                                   "rules_unchanged": preserved, "unknown_probe": unknown}
        self.api(3, "/disable_sav_table", {})
        self.wait_routes("post-filter")
        return all(r["pass"] for r in records) and preserved and unknown["pass"]

    def cleanup(self):
        errors = []
        for node in self.nodes:
            try:
                state = self.owned(node)
                self.report.setdefault("container_logs", {})[str(node)] = self.command(["docker", "logs", state["Id"]], check=False).stdout
                self.command(["docker", "rm", "-f", state["Id"]])
                if self.inspect(state["Id"]):
                    raise RuntimeError("Container remains after cleanup")
            except Exception as exc:
                errors.append(str(exc))
        for fd in self.namespace_fds.values():
            os.close(fd)
        self.namespace_fds.clear()
        # Never delete a host interface just by name. Interfaces stranded before
        # namespace transfer remain explicit cleanup errors requiring inspection.
        host_links = json.loads(self.command(["ip", "-j", "link"]).stdout)
        remaining = {x["ifname"] for x in host_links} & {x for pair in self.created_links for x in pair}
        if remaining:
            errors.append("Stranded interfaces: " + repr(sorted(remaining)))
        self.report["cleanup_errors"] = errors
        self.report["host_after"] = self.host_snapshot()
        before, after = self.report.get("host_before"), self.report["host_after"]
        if before:
            # nft counters may move independently, so freeze rule structure only.
            normalize = lambda x: re.sub(r"counter packets \d+ bytes \d+", "counter", x)
            self.report["host_unchanged"] = (before["routes4"] == after["routes4"] and before["routes6"] == after["routes6"]
                and normalize(before["nft"]) == normalize(after["nft"])
                and {x["ifname"] for x in before["links"]} == {x["ifname"] for x in after["links"]})
        if errors or self.report.get("host_unchanged") is False:
            self.report["status"] = "failed_cleanup_or_host_invariant"


def main(args):
    if os.geteuid() != 0:
        raise SystemExit("Root required on the dedicated development VM")
    lab = Lab(args)
    try:
        lab.prepare()
        lab.route_tests()
        passed = lab.packet_tests()
        if args.regressions:
            passed = lab.regression_tests() and passed
        lab.report["status"] = "passed_five_as_udp_calibration" if passed else "reproduced_dataplane_failures"
    except Exception:
        lab.report["status"] = "failed"
        lab.report["error"] = traceback.format_exc()
        print(lab.report["error"], flush=True)
    finally:
        lab.cleanup()
        dump(lab.run / "result.json", lab.report)
    print(json.dumps({"status": lab.report["status"], "report": str(lab.run / "result.json")}), flush=True)
    return 0 if lab.report["status"] == "passed_five_as_udp_calibration" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--family", type=int, choices=(4, 6), required=True)
    parser.add_argument("--regressions", action="store_true")
    raise SystemExit(main(parser.parse_args()))
