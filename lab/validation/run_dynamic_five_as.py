"""Dynamic five-AS calibration on isolated, owned Docker network namespaces."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import time
import traceback

from run_five_as import Lab, EDGES, address, prefix, dump, sha


class StableWindow:
    def __init__(self, seconds=3):
        self.seconds, self.since, self.previous, self.last_time = seconds, None, None, None

    def update(self, now, ready, snapshot):
        if self.last_time is not None and now < self.last_time:
            raise ValueError("Monotonic clock moved backwards")
        self.last_time = now
        if not ready:
            self.since, self.previous = None, None
            return False
        if self.previous != snapshot or self.since is None:
            self.since, self.previous = now, snapshot
        return now - self.since >= self.seconds


def selected_origin(text):
    # Command requests primary only; reject missing/ambiguous origin evidence.
    paths = re.findall(r"BGP\.as_path:\s*([0-9 ]+)\s*$", text, flags=re.M)
    if len(paths) != 1 or not paths[0].split():
        raise ValueError("Need one selected AS_PATH, not a guessed anycast origin")
    return int(paths[0].split()[-1])


class DynamicLab(Lab):
    def __init__(self, args):
        super().__init__(args)
        self.report.update({"dynamic_events": [], "bursts": [], "states": [], "pilot": args.pilot,
                            "update_mode": "explicit-controller-refresh", "repeat": args.repeat})
        self.anycast_prefix = "198.19.255.0/28" if args.family == 4 else "fd42:2400:ffff::/64"
        self.anycast_address = str(ipaddress.ip_network(self.anycast_prefix).network_address + 1)

    def prepare(self):
        super().prepare()
        for name in ("run_dynamic_five_as.py", "dynamic_design.json"):
            src = Path(__file__).with_name(name)
            shutil.copy2(src, self.run / name)
            self.report["provenance"][name] = sha(src)
        self.design = json.loads((self.run / "dynamic_design.json").read_text())

    def state(self, disabled=(), expected_dev=None, anycast_origin=None):
        snapshots, ready = {}, True
        disabled = {tuple(sorted(pair)) for pair in disabled}
        for node in self.nodes:
            text = self.bird(node, "show protocols", check=False)
            expected = {f"dsav_{node}_{b if node == a else a}" for a, b, _ in EDGES
                        if node in (a, b) and tuple(sorted((a, b))) not in disabled}
            bgp = {line.split()[0] for line in text.splitlines() if re.match(r"dsav_\d+_\d+\s", line) and "Established" in line.split()}
            ready &= expected == bgp
            routes = json.loads(self.execute(node, "ip", "-j", f"-{self.args.family}", "route", "show", "table", "main").stdout)
            unicast = {r.get("dst"): r for r in routes if r.get("type", "unicast") == "unicast"}
            ready &= all(prefix(n, self.args.family) in unicast for n in self.nodes if n != node)
            if expected_dev and node == 3:
                ready &= unicast.get(prefix(4, self.args.family), {}).get("dev") == expected_dev
            canonical = sorted(json.dumps({k: r[k] for k in ("dst", "dev", "gateway", "type", "nexthops") if k in r}, sort_keys=True) for r in routes)
            snapshots[str(node)] = {"bgp": sorted(bgp), "fib": canonical}
        if anycast_origin is not None:
            route_text = self.bird(1, f"show route {self.anycast_prefix} primary all")
            try:
                origin = selected_origin(route_text)
            except ValueError:
                origin = None
            allowed = {4200000004, 4200000005} if anycast_origin == "either" else {4200000000 + anycast_origin}
            ready &= origin in allowed
            snapshots["anycast_origin"] = origin
        return bool(ready), snapshots

    def wait_state(self, tag, **kwargs):
        start, window, samples = time.monotonic(), StableWindow(self.design["stable_window_seconds"]), []
        while time.monotonic() - start < self.design["deadline_seconds"]:
            ready, snapshot = self.state(**kwargs)
            elapsed = time.monotonic() - start
            samples.append({"elapsed": elapsed, "ready": ready, "snapshot": snapshot})
            if window.update(elapsed, ready, snapshot):
                dump(self.run / f"dynamic-state-{tag}.json", samples)
                self.report["states"].append({"tag": tag, "elapsed": elapsed, "constraints": kwargs,
                                               "file": f"dynamic-state-{tag}.json"})
                return snapshot
            time.sleep(0.25)
        dump(self.run / f"dynamic-state-{tag}.json", samples)
        raise RuntimeError(f"Dynamic state failed to stabilize: {tag}")

    def switch_filter(self, mode):
        if mode == "none":
            response = self.api(3, "/disable_sav_table", {})
            if self.execute(3, "nft", "list", "ruleset").stdout.strip():
                raise RuntimeError("No-SAV control is contaminated")
        else:
            response = self.api(3, "/enable_sav_table", {"active_app": mode, "dry_run": False})
            if response.get("data", {}).get(f"ipv{self.args.family}_commands", 0) <= 0:
                raise RuntimeError("Filter installation returned no family commands")
        self.report["dynamic_events"].append({"kind": "filter-refresh", "mode": mode, "response": response,
                                                "nft": self.execute(3, "nft", "list", "ruleset").stdout,
                                                "rules": self.api(3, "/active_sav_table")})

    def drop_snapshot(self):
        output = self.execute(3, "nft", "-j", "list", "chain", "inet", "savop", f"sav_urpf{self.args.family}", check=False)
        if output.returncode:
            if self.execute(3, "nft", "list", "ruleset").stdout.strip():
                raise RuntimeError("SAV table present but drop counter read failed")
            return {"packets": 0, "rules": []}
        data = json.loads(output.stdout)
        total = 0
        for item in data["nftables"]:
            expressions = item.get("rule", {}).get("expr", [])
            if any("drop" in e for e in expressions):
                total += sum(e["counter"]["packets"] for e in expressions if "counter" in e)
        return {"packets": total, "rules": data}

    def normal_burst(self, tag, source_node=4, destinations=(5,), service=None, expected=10):
        """Each actual server listens concurrently; never infer site from route alone."""
        token, processes = self.next_token(tag), {}
        destination = service or address(destinations[0], self.args.family)
        helper = Path(__file__).with_name("packet_probe.py")
        source = address(source_node, self.args.family)
        before = self.drop_snapshot()
        route = json.loads(self.execute(source_node, "ip", "-j", f"-{self.args.family}", "route", "get", destination, "from", source).stdout)
        try:
            for node in destinations:
                command = self.namespace_command(node, sys.executable, helper, "receive", "--destination", destination, "--token", token)
                child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes[node] = child
                if not select.select([child.stdout], [], [], 5)[0] or child.stdout.readline().strip() != "READY":
                    raise RuntimeError("Receiver not ready")
            tx = self.command(self.namespace_command(source_node, sys.executable, helper, "normal-send", "--source", source,
                                                     "--destination", destination, "--token", token))
            received, raw = {}, {}
            for node, child in processes.items():
                output, err = child.communicate(timeout=8)
                if child.returncode:
                    raise RuntimeError("Receiver failed: " + err)
                raw[str(node)] = output
                received[str(node)] = json.loads(output)
            after = self.drop_snapshot()
            sent = json.loads(tx.stdout)
            count = sum(r["received"] for r in received.values())
            identities = [p["payload"] for r in received.values() for p in r["packets"]]
            row = {"tag": tag, "token": token, "tx": sent, "receivers": received, "raw_receiver_stdout": raw,
                   "source_node": source_node, "source_route_get": route, "drop_before": before, "drop_after": after,
                   "expected_total": expected, "actual_total": count, "drop_delta": after["packets"] - before["packets"]}
            row["pass"] = sent["sent"] == 10 and count == expected and len(identities) == len(set(identities))
            if source_node == 4:
                row["pass"] &= row["drop_delta"] == 10 - expected
            self.report["bursts"].append(row)
            print(json.dumps({k: row[k] for k in ("tag", "actual_total", "drop_delta", "pass")}), flush=True)
            if not row["pass"]:
                raise RuntimeError(f"Packet or drop-counter mismatch in {tag}")
            return row
        finally:
            for child in processes.values():
                if child.poll() is None:
                    child.kill()
                    child.communicate()

    def link_change(self):
        self.record_link_addresses("before-flap")
        self.wait_state("before-link", expected_dev="eth_4")
        self.switch_filter("strict_urpf")
        self.normal_burst("link-initial")
        for state, interface, stale_tag, fresh_tag in (("down", "eth_2", "link-down-stale", "link-down-refreshed"),
                                                       ("up", "eth_4", "link-up-stale", "link-up-refreshed")):
            started = time.monotonic()
            self.execute(3, "ip", "link", "set", "eth_4", state)
            self.execute(4, "ip", "link", "set", "eth_3", state)
            self.wait_state(f"link-{state}", disabled=[(3, 4)] if state == "down" else [], expected_dev=interface)
            self.record_link_addresses("after-" + state)
            self.report["dynamic_events"].append({"kind": "link", "state": state, "edge": [3, 4],
                                                  "observed_stable_seconds": time.monotonic() - started})
            self.normal_burst(stale_tag, expected=0)
            self.switch_filter("strict_urpf")
            self.normal_burst(fresh_tag)
        self.switch_filter("none")

    def record_link_addresses(self, tag):
        snapshots = {}
        for node, peer in ((3, 4), (4, 3)):
            config = json.loads((self.generated / str(node) / "sa.json").read_text())
            expected = config["link_map"][f"dsav_{node}_{peer}"]["local_ip"]
            snapshot = json.loads(self.execute(node, "ip", "-j", "addr", "show", "dev", f"eth_{peer}").stdout)
            addresses = [a["local"] for interface in snapshot for a in interface["addr_info"]]
            if expected not in addresses:
                raise RuntimeError(f"Configured address disappeared on node {node}")
            snapshots[str(node)] = {"expected_local_ip": expected, "interfaces": snapshot}
        self.report.setdefault("address_retention", []).append({"tag": tag, "snapshots": snapshots})

    def asymmetry(self):
        source_cfg = json.loads((self.generated / "4/sa.json").read_text())
        upstream = source_cfg["link_map"]["dsav_4_2"]["remote_ip"]
        host = address(5, self.args.family) + ("/32" if self.args.family == 4 else "/128")
        self.execute(4, "ip", f"-{self.args.family}", "route", "add", host, "via", upstream, "dev", "eth_2")
        try:
            self.wait_state("asymmetric", expected_dev="eth_4")
            for mode, expected, tag in (("none", 10, "asym-none-before"), ("strict_urpf", 0, "asym-strict"),
                                         ("loose_urpf", 10, "asym-loose"), ("none", 10, "asym-none-after")):
                self.switch_filter(mode)
                self.normal_burst(tag, expected=expected)
        finally:
            self.execute(4, "ip", f"-{self.args.family}", "route", "del", host, "via", upstream, "dev", "eth_2")
        self.wait_state("post-asymmetric", expected_dev="eth_4")

    def anycast(self):
        self.switch_filter("none")
        for node in (4, 5):
            config = self.generated / str(node) / "bird.conf"
            original = config.read_text()
            shutil.copy2(config, config.with_name("bird.pre-anycast.conf"))
            config.write_text(original + f"\nprotocol static k5_anycast {{ ipv{self.args.family}; route {self.anycast_prefix} blackhole; }};\n")
            self.execute(node, "ip", "addr", "add", self.anycast_address + ("/32" if self.args.family == 4 else "/128"), "dev", "endpoint", "nodad")
            self.bird(node, "configure")
        self.wait_state("anycast-two-sites", anycast_origin="either")
        route = self.bird(1, f"show route {self.anycast_prefix} primary all")
        origin = selected_origin(route) - 4200000000
        initial = self.normal_burst("anycast-initial", source_node=1, destinations=(4, 5), service=self.anycast_address)
        if initial["receivers"][str(origin)]["received"] != 10:
            raise RuntimeError("Selected route origin differs from actual receiving site")
        started = time.monotonic()
        self.bird(origin, "disable k5_anycast")
        remaining = 9 - origin
        self.wait_state("anycast-withdrawn", anycast_origin=remaining)
        self.report["dynamic_events"].append({"kind": "anycast-withdrawal", "withdrawn_site": origin,
                                              "remaining_site": remaining, "initial_selected_route": route,
                                              "observed_stable_seconds": time.monotonic() - started})
        withdrawn = self.normal_burst("anycast-withdrawn", source_node=1, destinations=(4, 5), service=self.anycast_address)
        if withdrawn["receivers"][str(remaining)]["received"] != 10:
            raise RuntimeError("Anycast failed to switch receiving site")
        started = time.monotonic()
        self.bird(origin, "enable k5_anycast")
        self.wait_state("anycast-restored", anycast_origin="either")
        final_route = self.bird(1, f"show route {self.anycast_prefix} primary all")
        final_origin = selected_origin(final_route) - 4200000000
        restored = self.normal_burst("anycast-restored", source_node=1, destinations=(4, 5), service=self.anycast_address)
        if restored["receivers"][str(final_origin)]["received"] != 10:
            raise RuntimeError("Restored selected route differs from actual receiving site")
        self.report["dynamic_events"].append({"kind": "anycast-restore", "selected_site": final_origin,
                                              "selected_route": final_route, "observation_including_probe_seconds": time.monotonic() - started})


def main(args):
    if os.geteuid() != 0:
        raise SystemExit("Root required on the dedicated development VM")
    lab = DynamicLab(args)
    try:
        lab.prepare()
        lab.route_tests()
        lab.link_change()
        lab.asymmetry()
        lab.anycast()
        lab.report["status"] = "passed_dynamic_five_as_calibration"
    except Exception:
        lab.report["status"], lab.report["error"] = "failed", traceback.format_exc()
        print(lab.report["error"], flush=True)
    finally:
        lab.cleanup()
        dump(lab.run / "result.json", lab.report)
    print(json.dumps({"status": lab.report["status"], "report": str(lab.run / "result.json")}), flush=True)
    return 0 if lab.report["status"] == "passed_dynamic_five_as_calibration" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--family", type=int, choices=(4, 6), required=True)
    parser.add_argument("--repeat", type=int, default=0)
    parser.add_argument("--pilot", action="store_true")
    raise SystemExit(main(parser.parse_args()))
