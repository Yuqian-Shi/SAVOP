"""Independent reconstruction of dynamic five-AS evidence; no runner imports."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re


EXPECTED = {"link-initial": 10, "link-down-stale": 0, "link-down-refreshed": 10, "link-up-stale": 0,
            "link-up-refreshed": 10, "asym-none-before": 10, "asym-strict": 0, "asym-loose": 10,
            "asym-none-after": 10, "anycast-initial": 10, "anycast-withdrawn": 10, "anycast-restored": 10}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def drop_count(raw):
    if raw == []:
        return 0
    count = 0
    for entry in raw["nftables"]:
        expressions = entry.get("rule", {}).get("expr", [])
        if any("drop" in expression for expression in expressions):
            count += sum(expr.get("counter", {}).get("packets", 0) for expr in expressions)
    return count


def audit_run(run, report=None):
    report = report or json.loads((run / "result.json").read_text())
    assert report["status"] == "passed_dynamic_five_as_calibration"
    assert report["host_unchanged"] is True and report["cleanup_errors"] == []
    before_host, after_host = report["host_before"], report["host_after"]
    for key in ("links", "routes4", "routes6"):
        assert before_host[key] == after_host[key]
    canonical_nft = lambda text: re.sub(r"counter packets \d+ bytes \d+", "counter", text)
    assert canonical_nft(before_host["nft"]) == canonical_nft(after_host["nft"])
    commands = [json.loads(line) for line in (run / "commands.jsonl").read_text().splitlines()]
    family = report["family"]
    addresses = {n: f"198.18.0.{16*n+1}" if family == 4 else f"fd42:2400:{n}::1" for n in range(1, 6)}
    anycast_address = "198.19.255.1" if family == 4 else "fd42:2400:ffff::1"
    cases = report["bursts"]
    assert len(cases) == 12 and {r["tag"] for r in cases} == set(EXPECTED)
    assert len({r["token"] for r in cases}) == 12
    for r in cases:
        expected, token = EXPECTED[r["tag"]], r["token"]
        anycast = r["tag"].startswith("anycast-")
        source = addresses[1 if anycast else 4]
        destination = anycast_address if anycast else addresses[5]
        assert r["tx"]["sent"] == 10 and len(r["tx"]["payload_lengths"]) == 10
        assert r["tx"]["source"] == source and r["tx"]["destination"] == destination
        tx_commands = [c for c in commands if "normal-send" in c["argv"] and token in c["argv"]]
        assert len(tx_commands) == 1 and tx_commands[0]["rc"] == 0
        assert json.loads(tx_commands[0]["stdout"]) == r["tx"]
        assert any(arg.startswith("--net=/proc/") and "/fd/" in arg for arg in tx_commands[0]["argv"])
        assert set(r["receivers"]) == ({"4", "5"} if anycast else {"5"})
        ids = []
        for site, rx in r["receivers"].items():
            assert json.loads(r["raw_receiver_stdout"][site]) == rx
            assert len(rx["packets"]) == rx["received"]
            assert all(p["source"] == source for p in rx["packets"])
            ids.extend(p["payload"] for p in rx["packets"])
        assert len(ids) == expected and len(ids) == len(set(ids))
        assert set(ids) == ({f"{token}:{i}" for i in range(10)} if expected else set())
        before, after = drop_count(r["drop_before"]["rules"]), drop_count(r["drop_after"]["rules"])
        assert before == r["drop_before"]["packets"] and after == r["drop_after"]["packets"]
        if not anycast:
            assert after - before == 10 - expected
        if r["tag"].startswith("asym-") or r["tag"].startswith("link-down-"):
            assert r["source_route_get"][0]["dev"] == "eth_2"
        elif r["tag"].startswith("link-"):
            assert r["source_route_get"][0]["dev"] == "eth_3"
    state_by_tag = {}
    for state in report["states"]:
        samples = json.loads((run / state["file"]).read_text())
        assert samples[-1]["ready"] is True
        assert 3 <= samples[-1]["elapsed"] < 90
        assert all(a["elapsed"] < b["elapsed"] for a, b in zip(samples, samples[1:]))
        tail = []
        for sample in reversed(samples):
            if not sample["ready"] or sample["snapshot"] != samples[-1]["snapshot"]:
                break
            tail.append(sample)
        assert tail[0]["elapsed"] - tail[-1]["elapsed"] >= 3
        last = samples[-1]["snapshot"]
        expected_sessions = 10 if state["tag"] == "link-down" else 12
        assert sum(len(v["bgp"]) for k, v in last.items() if k.isdigit()) == expected_sessions
        edges = [(1, 2), (1, 3), (2, 3), (2, 4), (3, 4), (3, 5)]
        for node in range(1, 6):
            expected_peers = {f"dsav_{node}_{b if a == node else a}" for a, b in edges
                              if node in (a, b) and not (state["tag"] == "link-down" and (a, b) == (3, 4))}
            assert set(last[str(node)]["bgp"]) == expected_peers
            fib_prefixes = {json.loads(r).get("dst") for r in last[str(node)]["fib"]}
            for other in range(1, 6):
                if other != node:
                    expected_prefix = f"198.18.0.{16*other}/28" if family == 4 else f"fd42:2400:{other}::/64"
                    assert expected_prefix in fib_prefixes
        if state["tag"] in ("link-down", "link-up", "asymmetric"):
            prefix4 = "198.18.0.64/28" if family == 4 else "fd42:2400:4::/64"
            fib = [json.loads(row) for row in last["3"]["fib"]]
            match = [row for row in fib if row.get("dst") == prefix4]
            assert len(match) == 1 and match[0]["dev"] == ("eth_2" if state["tag"] == "link-down" else "eth_4")
        state_by_tag[state["tag"]] = last
    assert len(state_by_tag) == 8
    withdrawal = [e for e in report["dynamic_events"] if e["kind"] == "anycast-withdrawal"]
    assert len(withdrawal) == 1
    withdrawn, remaining = withdrawal[0]["withdrawn_site"], withdrawal[0]["remaining_site"]
    assert {withdrawn, remaining} == {4, 5}
    for tag, state_tag in (("anycast-initial", "anycast-two-sites"), ("anycast-withdrawn", "anycast-withdrawn"), ("anycast-restored", "anycast-restored")):
        row = next(r for r in cases if r["tag"] == tag)
        actual = [int(n) for n, rx in row["receivers"].items() if rx["received"] == 10]
        assert len(actual) == 1 and state_by_tag[state_tag]["anycast_origin"] == actual[0] + 4200000000
        if tag == "anycast-withdrawn":
            assert actual == [remaining]
    assert report["update_mode"] == "explicit-controller-refresh"
    for name, key in (("run_five_as.py", "runner"), ("packet_probe.py", "packet_probe"),
                      ("run_dynamic_five_as.py", "run_dynamic_five_as.py"), ("dynamic_design.json", "dynamic_design.json")):
        assert sha(run / name) == report["provenance"][key]
    ownership = json.loads((run / "ownership.json").read_text())
    assert len(ownership) == 5
    assert len({n["id"] for n in ownership.values()}) == 5
    assert len({n["netns_inode"] for n in ownership.values()}) == 5
    for node in ownership.values():
        inspections = [json.loads(c["stdout"])[0] for c in commands
                       if c["argv"] == ["docker", "inspect", node["id"]] and c["rc"] == 0]
        assert inspections
        for inspected in inspections:
            assert inspected["Id"] == node["id"]
            assert inspected["Config"]["Labels"]["org.savop.k5-validation"] == run.name
            assert inspected["HostConfig"]["NetworkMode"] == "none"
            assert inspected["HostConfig"]["Privileged"] is False
            assert inspected["HostConfig"]["PortBindings"] in ({}, None)
            assert inspected["HostConfig"]["Memory"] == 512 * 1024 * 1024
        assert any(c["argv"] == ["docker", "rm", "-f", node["id"]] and c["rc"] == 0 for c in commands)
    if "address_retention" in report:
        assert {r["tag"] for r in report["address_retention"]} == {"before-flap", "after-down", "after-up"}
        for phase in report["address_retention"]:
            for node, snapshot in phase["snapshots"].items():
                addresses = [a for interface in snapshot["interfaces"] for a in interface["addr_info"]
                             if a["local"] == snapshot["expected_local_ip"]]
                assert len(addresses) == 1
                if phase["tag"] == "after-up":
                    assert not addresses[0].get("tentative", False)
                    assert not addresses[0].get("dadfailed", False)
    return {"run": run.name, "family": family, "repeat": report["repeat"], "bursts": 12, "sent": 120,
            "received": sum(EXPECTED.values()), "expected_drops": 30,
            "anycast_initial_site": withdrawn, "anycast_failover_site": remaining,
            "event_observation_seconds": {e["kind"] + "-" + e.get("state", ""): e["observed_stable_seconds"]
                                          for e in report["dynamic_events"] if "observed_stable_seconds" in e},
            "result_sha256": sha(run / "result.json"), "commands_sha256": sha(run / "commands.jsonl")}


def main(args):
    rows = [audit_run(run) for run in args.run]
    if not args.pilot:
        assert len(rows) == 6 and {(r["family"], r["repeat"]) for r in rows} == {(f, n) for f in (4, 6) for n in (1, 2, 3)}
        assert all(not json.loads((r / "result.json").read_text())["pilot"] for r in args.run)
        assert len({json.loads((r / "result.json").read_text())["image"] for r in args.run}) == 1
        for key in ("target/release/sav_agent", "target/release/sav_lab_gen", "router/bird", "runner", "packet_probe", "run_dynamic_five_as.py", "dynamic_design.json"):
            assert len({json.loads((r / "result.json").read_text())["provenance"][key] for r in args.run}) == 1
    evidence = {str(p.relative_to(args.output.parent)).replace("\\", "/"): sha(p)
                for p in sorted(args.output.parent.rglob("*")) if p.is_file() and p != args.output}
    result = {"status": "passed_independent_dynamic_audit", "scope": "same-VM IPv4/IPv6 technical replay, UDP and explicit controller refresh",
              "records": rows, "verifier_sha256": sha(__file__), "artifacts_sha256": evidence,
              "not_verified": ["autonomous Agent update", "precise outage duration", "TCP/session continuity", "DSR", "100/1000-AS runtime"]}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps({"status": result["status"], "records": rows}, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--pilot", action="store_true")
    main(p.parse_args())
