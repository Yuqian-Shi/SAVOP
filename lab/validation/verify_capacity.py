"""Independent capacity evidence check, stdlib only; does not import runner."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import statistics


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def check_run(run):
    result, design, scene = (read(run / name) for name in ("result.json", "design.json", "scene.json"))
    before, after = result["host_before"], result["host_after"]
    normalize = lambda text: re.sub(r"counter packets \d+ bytes \d+", "counter", text)
    assert before["routes4"] == after["routes4"] and before["routes6"] == after["routes6"]
    assert normalize(before["nft"]) == normalize(after["nft"])
    assert {r["ifname"] for r in before["links"]} == {r["ifname"] for r in after["links"]}
    assert not result["cleanup_errors"] and result["host_unchanged"]
    if result["created_nodes"]:
        assert result["image"] == "sha256:919112c855135ffa99720ae7855fc4060e51a400fad3d6fb11fd5c7bd56c472b"
        assert result["provenance"]["target/release/sav_agent"] == "fd0754383770facba20fee275144167970cf73746aa06921177044d78e9baf79"
    if result["status"] not in ("passed_capacity_tier", "failed_resource_margin"):
        observed_failures = []
        paths = sorted(run.glob("observation-steady-*.json"))
        if paths:
            for row in read(paths[-1]):
                state = row.get("auto", {})
                if row.get("error") or state.get("last_error"):
                    observed_failures.append({"node": row["node"], "observation": paths[-1].name,
                                              "command_error": row.get("error"), "phase": state.get("phase"),
                                              "last_error": state.get("last_error"), "error_count": state.get("error_count")})
        return {"run": run.name, "qualified": False, "status": result["status"],
                "excluded": True, "cleanup_verified": True, "observed_failures": observed_failures}
    n, family = result["node_count"], result["family"]
    assert result["AS_count"] * 10 == n == len(scene["devices"])
    counts = Counter(row["as"] for row in scene["devices"].values())
    assert len(counts) == result["AS_count"] and set(counts.values()) == {10}
    prefixes = {int(k): next(iter(v["prefixes"])) for k, v in scene["devices"].items()}
    assert len(set(prefixes.values())) == n
    edges = [(int(a), int(b)) for a, b, _ in scene["links"]]
    assert len(edges) == n - 1 and len(set(tuple(sorted(edge)) for edge in edges)) == n - 1
    seen, todo = {1}, [1]
    while todo:
        current = todo.pop()
        for a, b in edges:
            if current in (a, b):
                other = a if b == current else b
                if other not in seen:
                    seen.add(other)
                    todo.append(other)
    assert seen == set(prefixes)
    ownership = read(run / "ownership.json")
    assert len(ownership) == n and len({r["id"] for r in ownership.values()}) == n
    assert len({r["netns_inode"] for r in ownership.values()}) == n
    assert all(re.fullmatch("[0-9a-f]{64}", r["id"]) for r in ownership.values())
    for name in ("run_capacity.py", "capacity_probe.py", "run_five_as.py", "packet_probe.py"):
        assert hashlib.sha256((run / name).read_bytes()).hexdigest() == result["provenance"][name]

    def check_rows(rows):
        assert len(rows) == n and {r["node"] for r in rows} == set(prefixes)
        for row in rows:
            node = row["node"]
            bgp = [line.split() for line in row["protocols"].splitlines() if re.match(r"dsav_\d+_\d+\s", line)]
            assert len(bgp) == sum(node in pair for pair in edges) and all("Established" in x for x in bgp)
            reachable = {r.get("dst") for r in row["fib"] if r.get("type", "unicast") == "unicast"}
            assert set(prefixes.values()) - {prefixes[node]} <= reachable
            state = row["auto"]
            assert state["phase"] in ("applied", "in_sync", "checking") and not state["paused"]
            assert state["enabled"] and not state["dry_run"] and state["last_error"] is None
            assert state["active_app"] == "strict_urpf" and state["interval_ms"] == 1000
            assert state["refresh_count"] >= 1 and state["installed_fingerprint"] is not None
            assert 0 <= row["at"] - state["last_verified"] <= 10.1
        return {r["node"]: r for r in rows}

    groups = {}
    for tag in ("initial", "prefix-added", "prefix-withdrawn"):
        paths = sorted(run.glob(f"observation-{tag}-*.json"))
        assert len(paths) >= 2
        end = check_rows(read(paths[-1]))
        start = None
        for path in reversed(paths[:-1]):
            candidate = read(path)
            if all(r.get("fib_hash") == end[r["node"]]["fib_hash"] and r.get("ready") for r in candidate):
                start = check_rows(candidate)
            else:
                break
        assert start is not None
        assert min(end[i]["at"] - start[i]["at"] for i in end) >= 2.9
        groups[tag] = end
    extra = "198.19.240.0/24" if family == 4 else "fd42:2400:ffff::/64"
    for node in prefixes:
        initial, added, withdrawn = (groups[tag][node] for tag in ("initial", "prefix-added", "prefix-withdrawn"))
        assert not any(r.get("dst") == extra for r in initial["fib"])
        assert any(r.get("dst") == extra for r in added["fib"])
        assert not any(r.get("dst") == extra for r in withdrawn["fib"])
        if node != n:
            assert added["auto"]["last_hash"] != initial["auto"]["last_hash"]
            assert withdrawn["auto"]["last_hash"] != added["auto"]["last_hash"]
            assert withdrawn["auto"]["refresh_count"] > added["auto"]["refresh_count"] > initial["auto"]["refresh_count"]
    for path in sorted(run.glob("observation-steady-*.json")):
        for node, row in check_rows(read(path)).items():
            assert row["auto"]["error_count"] == groups["prefix-withdrawn"][node]["auto"]["error_count"]
    final = check_rows(read(run / "observation-steady-final.json"))
    assert all(final[n]["auto"]["skip_count"] > groups["prefix-withdrawn"][n]["auto"]["skip_count"] for n in final)
    sent, replies = 0, 0
    for tag in ("initial", "added", "withdrawn", "final"):
        packets = read(run / f"packets-{tag}.json")
        assert len(packets) == n
        sources = {str(ipaddress.ip_network(p).network_address + 1) for p in prefixes.values()}
        assert {r["source"] for r in packets} == sources
        for packet in packets:
            assert packet["sent"] == [0, 1, 2] and sorted(r["seq"] for r in packet["received"]) == [0, 1, 2]
            sent += len(packet["sent"])
            replies += len(packet["received"])
        server = json.loads((run / f"echo-{tag}.log").read_text().strip())
        assert server["received"] == n * 3
    samples = [json.loads(line) for line in (run / "resources.jsonl").read_text().splitlines()]
    steady = [r for r in samples if r["phase"] == "steady"]
    assert len(steady) >= 2 and steady[-1]["time"] - steady[0]["time"] >= design["hold_seconds"] - 2
    assert all(0 < value < 180 for key, value in result["phase_times"].items() if key != "deployment_seconds")
    cpu = sorted(r["cpu_percent"] for r in steady)
    calculated = {"cpu_mean_percent": statistics.mean(cpu),
                  "cpu_p95_percent": cpu[min(len(cpu) - 1, int(len(cpu) * .95))],
                  "available_min_gib": min(r["mem_available_gib"] for r in steady)}
    for key, value in calculated.items():
        assert abs(value - result["steady_resources"][key]) < 1e-6
    initial_swap = result.get("initial_swap_mib", samples[0]["swap_used_mib"])
    margin_ok = (calculated["cpu_mean_percent"] < 70 and calculated["cpu_p95_percent"] < 85
                 and calculated["available_min_gib"] >= 3
                 and max(r["swap_used_mib"] for r in steady) - initial_swap <= 1)
    assert margin_ok == (result["status"] == "passed_capacity_tier")
    removed = set()
    with (run / "commands.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["argv"][:3] == ["docker", "rm", "-f"] and row["rc"] == 0:
                removed.add(row["argv"][3])
            assert not any("/enable_sav_table" in arg for arg in row["argv"])
    assert removed == {r["id"] for r in ownership.values()}
    return {"run": run.name, "qualified": margin_ok, "functional_checks_passed": True,
            "status": result["status"], "cleanup_verified": True, "AS": result["AS_count"], "nodes": n, "family": family,
            "udp_requests": sent, "udp_echo_replies": replies, "resources": calculated,
            "hold_seconds": design["hold_seconds"], "agent_sha256": result["provenance"]["target/release/sav_agent"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for path in sorted(args.root.glob("cap-*/result.json")):
        rows.append(check_run(path.parent))
    with args.output.open("x", encoding="utf-8") as out:
        json.dump({"runs": rows, "qualified_count": sum(r["qualified"] for r in rows)}, out, indent=2)
    print(json.dumps(rows, indent=2))
