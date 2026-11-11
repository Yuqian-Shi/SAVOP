"""Reconstruct automatic-loop evidence independently; never import a runner."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def drops(snapshot):
    raw = snapshot["rules"]
    if raw == []:
        assert snapshot["packets"] == 0
        return 0
    count = sum(expr["counter"]["packets"] for item in raw["nftables"]
                if any("drop" in e for e in item.get("rule", {}).get("expr", []))
                for expr in item["rule"]["expr"] if "counter" in expr)
    assert count == snapshot["packets"]
    return count


def audit_run(run, report=None):
    report = report if report is not None else json.loads((run / "result.json").read_text())
    assert report["status"] == "passed_auto_five_as_calibration"
    assert report["update_mode"] == "agent-periodic-reconciliation"
    assert report["cleanup_errors"] == [] and report["host_unchanged"]
    before, after = report["host_before"], report["host_after"]
    for field in ("links", "routes4", "routes6"):
        assert before[field] == after[field]
    scrub = lambda s: re.sub(r"counter packets \d+ bytes \d+", "counter", s)
    assert scrub(before["nft"]) == scrub(after["nft"])
    commands = [json.loads(s) for s in (run / "commands.jsonl").read_text().splitlines()]
    ownership = json.loads((run / "ownership.json").read_text())
    assert len(ownership) == len({r["id"] for r in ownership.values()}) == len({r["netns_inode"] for r in ownership.values()}) == 5
    for node in ownership.values():
        inspected = [json.loads(c["stdout"])[0] for c in commands
                     if c["argv"] == ["docker", "inspect", node["id"]] and c["rc"] == 0]
        assert inspected
        for obj in inspected:
            assert obj["Id"] == node["id"] and obj["Config"]["Labels"]["org.savop.k5-validation"] == run.name
            assert obj["HostConfig"]["NetworkMode"] == "none" and obj["HostConfig"]["Privileged"] is False
            assert obj["HostConfig"]["PortBindings"] in ({}, None)
        assert any(c["argv"] == ["docker", "rm", "-f", node["id"]] and c["rc"] == 0 for c in commands)
    agent_starts = [c for c in commands if c["argv"][-1] == "/build/target/release/sav_agent"]
    assert len(agent_starts) == 5
    for c in agent_starts:
        auto = c["argv"][-2] == ownership["3"]["id"]
        assert ("SAVOP_DATA_PLANE_AUTO=true" if auto else "SAVOP_DATA_PLANE_AUTO=false") in c["argv"]
    for name in ("run_auto_five_as.py", "auto_design.json", "auto_fault_ip.sh", "auto_fault_nft.sh",
                 "run_five_as.py", "run_dynamic_five_as.py"):
        assert sha(run / name) == report["provenance"][name]
    assert sha(run / "packet_probe.py") == report["provenance"]["packet_probe"]
    checks = {r["tag"]: r for r in report["auto_checks"]}
    assert len(checks) == len(report["auto_checks"])
    assert all(r["pass"] for r in checks.values())
    snaps = report["auto_snapshots"]
    # Anchor every status/nft/FIB snapshot to a successful real command, not
    # solely to a runner's "pass" field.
    for snap in snaps:
        recent = [c for c in commands if 0 <= snap["time"] - c["started"] < 12]
        assert any(c["rc"] == 0 and c["argv"][-1] == "http://127.0.0.1:8888/data_plane"
                   and json.loads(c["stdout"])["data"]["data_plane"] == snap["state"] for c in recent)
        assert any(c["argv"][-6:] == ["/usr/sbin/nft", "-s", "list", "table", "inet", "savop"]
                   and c["rc"] == snap["nft_rc"] and c["stdout"] == snap["nft"] for c in recent)
        assert any(c["rc"] == 0 and c["argv"][-6:] == ["-j", f"-{report['family']}", "route", "show", "table", "main"]
                   and 0 <= c["started"] - snap["time"] < 3 and json.loads(c["stdout"]) == snap["fib"] for c in commands)

    by_tag = lambda tag: next(r for r in reversed(snaps) if r["tag"] == tag)
    assert by_tag("boot-install")["state"]["refresh_count"] > 0
    for tag in ("paused-control-before", "paused-control-after", "after-preview"):
        assert by_tag(tag)["state"]["paused"] and by_tag(tag)["nft_rc"] != 0
    a, b = by_tag("enabled-before-probes"), by_tag("unchanged-after-counters")
    assert a["state"]["refresh_count"] == b["state"]["refresh_count"]
    assert b["state"]["skip_count"] > a["state"]["skip_count"]
    assert a["nft"] == b["nft"]
    for direction, dev in (("down", "eth_2"), ("up", "eth_4")):
        a, b = by_tag("before-link-" + direction), by_tag("after-link-" + direction)
        assert b["state"]["refresh_count"] > a["state"]["refresh_count"]
        assert b["state"]["last_hash"] != a["state"]["last_hash"]
        prefix = "198.18.0.64/28" if report["family"] == 4 else "fd42:2400:4::/64"
        assert [r["dev"] for r in b["fib"] if r.get("dst") == prefix] == [dev]
        assert prefix in b["nft"] and dev in b["nft"]
        # No controller install/selection call is allowed across route mutation
        # and the passing post-update packet probe.
        token = next(r["token"] for r in report["bursts"] if r["tag"] == "auto-link-" + direction + "-legal")
        tx = next(c for c in commands if token in c["argv"] and "normal-send" in c["argv"])
        middle = [c for c in commands if a["time"] < c["started"] < tx["started"]]
        assert any(c["argv"][-4:] == ["link", "set", "eth_4", direction] for c in middle)
        assert not any(any(endpoint in arg for endpoint in ("/enable_sav_table", "/install_sav_table", "/switch_sav_app"))
                       for c in middle for arg in c["argv"])
    for kind in ("missing", "edited"):
        a, b = by_tag("before-drift-" + kind), by_tag("repaired-" + kind)
        assert a["nft"] == b["nft"] and a["state"]["last_hash"] == b["state"]["last_hash"]
        assert b["state"]["refresh_count"] > a["state"]["refresh_count"]
    for kind in ("ip-error", "ip-malformed", "ip-timeout", "nft-invalid", "nft-timeout"):
        a, error, retained, b = [by_tag(prefix + kind) for prefix in ("before-", "error-", "still-failed-", "recovered-")]
        for row in (error, retained):
            assert row["nft"] == a["nft"]
            assert row["state"]["refresh_count"] == a["state"]["refresh_count"]
            assert row["state"]["last_hash"] == a["state"]["last_hash"]
        assert error["state"]["last_error"] and error["state"]["error_count"] > a["state"]["error_count"]
        if kind.endswith("timeout"):
            assert "timeout after 800 ms" in error["state"]["last_error"]
        if kind == "nft-invalid":
            assert "missing_fault_chain" in error["state"]["last_error"]
        assert b["state"]["last_error"] is None and b["state"]["consecutive_errors"] == 0
        if kind.startswith("nft-"):
            assert b["state"]["refresh_count"] > a["state"]["refresh_count"]
    assert checks["failed-disable-truthful"]["response"]["code"] == "5004"
    assert by_tag("failed-disable-paused")["state"]["phase"] == "paused_error"
    assert by_tag("after-preview")["state"]["last_hash"] is None
    assert by_tag("after-preview")["state"]["dry_run_count"] > by_tag("before-preview")["state"]["dry_run_count"]
    assert by_tag("after-preview")["state"]["refresh_count"] == by_tag("before-preview")["state"]["refresh_count"]
    assert by_tag("auto-switch-strict")["state"]["last_result"]["active_app"] == "strict_urpf"
    assert by_tag("auto-switch-strict")["state"]["refresh_count"] > by_tag("before-auto-switch")["state"]["refresh_count"]
    a, b, c = [by_tag(tag) for tag in ("before-loose-prefix", "loose-prefix-added", "loose-prefix-removed")]
    assert a["state"]["last_hash"] != b["state"]["last_hash"]
    assert a["state"]["last_hash"] == c["state"]["last_hash"]
    assert a["state"]["refresh_count"] < b["state"]["refresh_count"] < c["state"]["refresh_count"]
    assert a["nft"] == c["nft"]
    if "lifecycle" in report:
        lifecycle = report["lifecycle"]
        assert sha(run / "run_auto_lifecycle.py") == report["provenance"]["run_auto_lifecycle.py"]
        assert lifecycle["stop_result"]["execute_result"] == "ok" and lifecycle["stop_result"]["action"] == "stop"
        assert lifecycle["start_result"]["execute_result"] == "ok" and lifecycle["start_result"]["action"] == "start"
        assert lifecycle["bird_stopped_rc"] != 0
        for key in ("stopped", "retained"):
            assert lifecycle[key]["state"]["paused"] and lifecycle[key]["nft_rc"] != 0
            assert lifecycle[key]["state"]["refresh_count"] == lifecycle["before"]["state"]["refresh_count"]
        assert not lifecycle["resumed"]["state"]["paused"] and lifecycle["resumed"]["nft_rc"] == 0
        assert lifecycle["resumed"]["state"]["refresh_count"] > lifecycle["before"]["state"]["refresh_count"]
        assert any(c["rc"] != 0 and c["argv"][-1] == "show status" for c in commands)
        for key in ("stop_result", "start_result"):
            assert any(c["rc"] == 0 and c["argv"][-1] == "/node/log/exec_results.json"
                       and json.loads(c["stdout"]) == lifecycle[key] for c in commands)

    # Routing stability is reconstructed from the full shared-window samples.
    assert {r["tag"] for r in report["states"]} == {"auto-link-down", "auto-link-up"}
    for record in report["states"]:
        samples = json.loads((run / record["file"]).read_text())
        tail = []
        for sample in reversed(samples):
            if not sample["ready"] or sample["snapshot"] != samples[-1]["snapshot"]:
                break
            tail.append(sample)
        assert tail and tail[0]["elapsed"] - tail[-1]["elapsed"] >= 3
        assert tail[0]["elapsed"] < 90
        assert sum(len(v["bgp"]) for v in tail[0]["snapshot"].values()) == (10 if record["tag"].endswith("down") else 12)

    expected_raw = {"no-sav-unknown": 10, "initial-strict-unknown": 0, "initial-strict-wrong-interface": 0,
                    "auto-link-restored-unknown": 0, "repair-missing-unknown": 0, "repair-edited-unknown": 0,
                    "loose-wrong-interface": 10, "loose-unknown": 0, "auto-switch-strict-wrong-interface": 0,
                    "loose-new-prefix-allowed": 10, "loose-withdrawn-prefix-denied": 0}
    expected_raw.update({kind + "-old-rule-unknown": 0 for kind in ("ip-error", "ip-malformed", "ip-timeout", "nft-invalid", "nft-timeout")})
    normal_tags = {"no-sav-legal", "initial-strict-legal", "auto-link-down-legal", "auto-link-up-legal"}
    normal_tags.update({kind + "-old-rule-legal" for kind in ("ip-error", "ip-malformed", "ip-timeout", "nft-invalid", "nft-timeout")})
    assert {r["tag"] for r in report["packet_tests"]} == set(expected_raw)
    assert {r["tag"] for r in report["bursts"]} == normal_tags
    tokens, total_received = set(), 0
    family = report["family"]
    addresses = {n: f"198.18.0.{n*16+1}" if family == 4 else f"fd42:2400:{n}::1" for n in (2, 4, 5)}
    unknown = "198.19.200.1" if family == 4 else "fd42:2400:ee::1"
    for raw, rows in ((True, report["packet_tests"]), (False, report["bursts"])):
        for row in rows:
            token = row["token"]
            assert token not in tokens
            tokens.add(token)
            expected = expected_raw[row["tag"]] if raw else 10
            if raw:
                case = "wrong_interface" if "wrong-interface" in row["tag"] else "unknown"
                assert row["case"] == case
                source = addresses[2] if case == "wrong_interface" else unknown
            else:
                source = addresses[4]
                assert row["source_route_get"][0]["dev"] == ("eth_2" if row["tag"] == "auto-link-down-legal" else "eth_3")
            assert row["tx"]["source"] == source and row["tx"]["destination"] == addresses[5]
            txs = [c for c in commands if token in c["argv"] and ("send" if raw else "normal-send") in c["argv"]]
            assert len(txs) == 1 and txs[0]["rc"] == 0 and json.loads(txs[0]["stdout"]) == row["tx"]
            assert any(arg.startswith("--net=/proc/") and "/fd/" in arg for arg in txs[0]["argv"])
            rx = row["rx"] if raw else row["receivers"]["5"]
            raw_stdout = row["raw_receiver_stdout"] if raw else row["raw_receiver_stdout"]["5"]
            assert json.loads(raw_stdout) == rx
            lengths = row["tx"]["frame_lengths" if raw else "payload_lengths"]
            assert row["tx"]["sent"] == 10 and len(lengths) == 10
            overhead = (14 + (20 if family == 4 else 40) + 8) if raw else 0
            assert lengths == [len(f"{token}:{i}".encode()) + overhead for i in range(10)]
            assert rx["received"] == len(rx["packets"]) == expected
            assert {p["payload"] for p in rx["packets"]} == {f"{token}:{i}" for i in range(expected)}
            assert all(p["source"] == row["tx"]["source"] for p in rx["packets"])
            assert drops(row["drop_after"]) - drops(row["drop_before"]) == 10 - expected
            total_received += expected
    assert len(tokens) == 25
    return {"run": run.name, "family": report["family"], "repeat": report["repeat"],
            "checks": len(checks), "bursts": len(tokens), "sent": 250,
            "received": total_received, "expected_drops": 250 - total_received,
            "lifecycle_verified": "lifecycle" in report,
            "result_sha256": sha(run / "result.json"), "commands_sha256": sha(run / "commands.jsonl")}


def negative_controls(run):
    original = json.loads((run / "result.json").read_text())
    results = {}
    for label in ("rx-fabricated", "no-generation", "error-hidden", "paused-false", "host-route-changed"):
        report = copy.deepcopy(original)
        if label == "rx-fabricated":
            report["packet_tests"][1]["rx"]["received"] = 10
        elif label == "no-generation":
            for row in report["auto_snapshots"]:
                if row["tag"] == "after-link-down":
                    row["state"]["refresh_count"] = 0
        elif label == "error-hidden":
            for row in report["auto_snapshots"]:
                if row["tag"] == "error-ip-timeout":
                    row["state"]["last_error"] = None
        elif label == "paused-false":
            for row in report["auto_snapshots"]:
                if row["tag"] == "after-preview":
                    row["state"]["paused"] = False
        else:
            report["host_after"]["routes4"].append({"dst": "198.18.0.0/24"})
        try:
            audit_run(run, report)
        except AssertionError:
            results[label] = "rejected"
        else:
            raise AssertionError("Auditor accepted corrupt evidence: " + label)
    return results


def main(args):
    records = [audit_run(run) for run in args.run]
    if not args.pilot:
        assert {(r["family"], r["repeat"]) for r in records} == {(4, 1), (4, 2), (6, 1), (6, 2)}
        assert len(records) == 4
        assert args.plan is not None
        plan = json.loads(args.plan.read_text())
        assert [(r["family"], r["repeat"], r["run"]) for r in records] == [
            (r["family"], r["repeat"], r["run_id"]) for r in plan["schedule"]]
        for run in args.run:
            for name, expected in plan["files"].items():
                if (run / name).is_file():
                    assert sha(run / name) == expected
    reports = [json.loads((run / "result.json").read_text()) for run in args.run]
    assert len({r["image"] for r in reports}) == 1
    for key in reports[0]["provenance"]:
        assert len({r["provenance"][key] for r in reports}) == 1
    for report in reports:
        for rel in ("target/release/sav_agent", "target/release/sav_lab_gen", "router/bird"):
            assert sha(args.build / rel) == report["provenance"][rel]
    result = {"status": "passed_independent_auto_audit", "records": records,
              "negative_controls": negative_controls(args.run[0]), "verifier_sha256": sha(__file__),
              "scope": "same-VM synthetic 5AS uRPF periodic reconciliation and isolated UDP fault/recovery",
              "not_verified": reports[0]["auto_design"]["excluded_claims"]}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, action="append", required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--pilot", action="store_true")
    p.add_argument("--plan", type=Path)
    main(p.parse_args())
