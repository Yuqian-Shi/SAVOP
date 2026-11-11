"""Independent evidence audit of the five-AS calibration, not a traffic runner.

Reconstruct expectations from the fixed experiment definition, check packet
identities and the actual command log, then compare baseline and repaired runs.
Does not import the runner's predicate or trust its `pass` flags as evidence.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(run, unique_tokens=False):
    report = json.loads((run / "result.json").read_text())
    commands = [json.loads(line) for line in (run / "commands.jsonl").read_text().splitlines()]
    version = report["family"]
    is_baseline = run.name.startswith("baseline-")
    assert version in (4, 6)
    scene = json.loads((run / "scene.json").read_text())
    assert len(scene["devices"]) == 5
    assert {d["as"] for d in scene["devices"].values()} == set(range(4200000001, 4200000006))
    assert scene["links"] == [[str(a), str(b), "dsav"] for a, b in ((1, 2), (1, 3), (2, 3), (2, 4), (3, 4), (3, 5))]
    assert report["host_unchanged"] is True and report["cleanup_errors"] == []
    assert len(report["all_pairs_ping"]) == 20
    assert {(t["from"], t["to"]) for t in report["all_pairs_ping"]} == {(a, b) for a in range(1, 6) for b in range(1, 6) if a != b}
    for row in report["all_pairs_ping"]:
        assert row["rc"] == 0 and "2 packets transmitted, 2 received" in row["stdout"]
    for name, key in (("run_five_as.py", "runner"), ("packet_probe.py", "packet_probe")):
        assert sha(run / name) == report["provenance"][key]
    routes = json.loads((run / "routes-initial.json").read_text())
    assert routes[-1]["ready"] and routes[-1]["elapsed"] - routes[0]["elapsed"] >= 3
    stable = []
    for r in reversed(routes):
        if not r["ready"] or r["snapshot"] != routes[-1]["snapshot"]:
            break
        stable.append(r)
    assert stable[0]["elapsed"] - stable[-1]["elapsed"] >= 3
    assert sum(len(n["bgp"]) for n in routes[-1]["snapshot"].values()) == 12
    prefixes = {n: next(iter(scene["devices"][str(n)]["prefixes"])) for n in range(1, 6)}
    for node in range(1, 6):
        fib = [json.loads(s) for s in routes[-1]["snapshot"][str(node)]["fib"]]
        observed = {r.get("dst") for r in fib if r.get("type", "unicast") == "unicast"}
        assert {p for n, p in prefixes.items() if n != node} <= observed
    for item in report["policy_exports"]:
        a, b = item["from"], item["to"]
        allowed = {(4, 2): {4}, (4, 3): {4}, (5, 3): {5}, (2, 3): {2, 4}}[(a, b)]
        observed = set(re.findall(r"(?m)^([0-9a-fA-F:.]+/\d+)\s", item["stdout"]))
        assert observed == {prefixes[n] for n in allowed}
    assert len(report["policy_exports"]) == 4
    records = report["packet_tests"]
    modes = {"none-before", "strict_urpf", "none-between", "loose_urpf", "none-after"}
    assert {(r["mode"], r["case"], r["destination_node"]) for r in records} == {
        (m, c, d) for m in modes for c in ("legal", "wrong_interface", "unknown") for d in (3, 5)}
    assert len(records) == 30
    failures, sent, received = [], 0, 0
    for record in records:
        mode, case = record["mode"], record["case"]
        expected = 10 if mode.startswith("none-") or case == "legal" or (mode == "loose_urpf" and case == "wrong_interface") else 0
        unknown = "198.19.200.1" if version == 4 else "fd42:2400:ee::1"
        source = unknown if case == "unknown" else str(ipaddress.ip_network(prefixes[4 if case == "legal" else 2]).network_address + 1)
        destination = str(ipaddress.ip_network(prefixes[record["destination_node"]]).network_address + 1)
        assert record["tx"]["sent"] == 10 and len(record["tx"]["frame_lengths"]) == 10
        assert record["tx"]["source"] == source and record["tx"]["destination"] == destination
        raw_tx = [cmd for cmd in commands if "send" in cmd["argv"] and record["token"] in cmd["argv"]]
        # Frozen v1 runner reused the case token for the later overlap/atomic
        # regression. Sockets are recreated per case, and the command log is
        # ordered: the first occurrence is the matrix; the second is regression.
        repeated_regression = (not is_baseline and mode == "strict_urpf" and
                               (case in ("legal", "wrong_interface") or
                                (case == "unknown" and record["destination_node"] == 5)))
        assert len(raw_tx) == (2 if repeated_regression and not unique_tokens else 1) and raw_tx[0]["rc"] == 0
        assert json.loads(raw_tx[0]["stdout"]) == record["tx"]
        packets = record["rx"]["packets"]
        assert len(packets) == record["rx"]["received"]
        assert all(p["source"] == source for p in packets)
        identities = {p["payload"] for p in packets}
        assert len(identities) == len(packets)
        assert identities <= {f"{record['token']}:{i}" for i in range(10)}
        if len(packets) != expected:
            failures.append((mode, case, record["destination_node"], len(packets)))
        sent += 10
        received += len(packets)
    if is_baseline:
        assert set(failures) == {(m, "unknown", d, 10) for m in ("strict_urpf", "loose_urpf") for d in (3, 5)}
        assert report["status"] == "reproduced_dataplane_failures"
    else:
        assert not failures
        assert report["status"] == "passed_five_as_udp_calibration"
        assert len(report["longest_prefix_regression"]) == 4
        if unique_tokens:
            all_probes = records + report["longest_prefix_regression"] + [report["atomic_failure_regression"]["unknown_probe"]]
            assert len({r["token"] for r in all_probes}) == 35
        for r in report["longest_prefix_regression"]:
            assert r["tx"]["sent"] == 10 and len(r["rx"]["packets"]) == (10 if r["case"] == "legal" else 0)
            logged = [c for c in commands if "send" in c["argv"] and r["token"] in c["argv"]]
            index = 0 if unique_tokens else 1
            assert len(logged) == index + 1 and logged[index]["rc"] == 0 and json.loads(logged[index]["stdout"]) == r["tx"]
        atomic = report["atomic_failure_regression"]
        assert atomic["rejected"] and atomic["rules_unchanged"]
        assert atomic["unknown_probe"]["tx"]["sent"] == 10 and atomic["unknown_probe"]["rx"]["received"] == 0
        assert "No such file" in atomic["stderr"]
        for mode in ("strict_urpf", "loose_urpf"):
            protocols = report["post_filter_protocols"][mode]
            bgp = [line for line in protocols.splitlines() if re.match(r"dsav_3_\d+\s", line)]
            assert len(bgp) == 4 and all("Established" in x for x in bgp)
    # Full container IDs and labels appear in creation/inspection/removal logs.
    ownership = json.loads((run / "ownership.json").read_text())
    assert len(ownership) == 5
    for node in ownership.values():
        assert any(c["argv"] == ["docker", "rm", "-f", node["id"]] and c["rc"] == 0 for c in commands)
        inspected = [json.loads(c["stdout"])[0] for c in commands if c["argv"] == ["docker", "inspect", node["id"]] and c["rc"] == 0]
        assert inspected and all(i["HostConfig"]["NetworkMode"] == "none" and not i["HostConfig"]["Privileged"] for i in inspected)
    return {"run": run.name, "family": version, "kind": "baseline" if is_baseline else "fixed",
            "matrix_cases": 30, "matrix_sent": sent, "matrix_received": received, "semantic_failures": failures,
            "result_sha256": sha(run / "result.json"), "commands_sha256": sha(run / "commands.jsonl")}


def main(args):
    records = [verify(path) for path in args.run]
    assert len(records) == 4 and {(r["kind"], r["family"]) for r in records} == {(k, v) for k in ("baseline", "fixed") for v in (4, 6)}
    evidence = args.output.parent
    for run in args.run:
        build = evidence / ("baseline-build" if run.name.startswith("baseline-") else "fixed-build")
        report = json.loads((run / "result.json").read_text())
        for rel in ("target/release/sav_agent", "target/release/sav_lab_gen", "router/bird"):
            assert sha(build / Path(rel).name) == report["provenance"][rel]
    artifacts = {str(p.relative_to(evidence)).replace("\\", "/"): sha(p)
                 for p in sorted(evidence.rglob("*")) if p.is_file() and p != args.output}
    result = {"status": "passed_evidence_audit", "scope": "five-AS UDP calibration and two regression classes only",
              "verifier_sha256": sha(__file__), "records": records,
              "artifacts_sha256": artifacts,
              "audit_note": "v1 regression tokens repeat matrix case IDs; ordered command occurrences distinguish phases; packet uniqueness is per receiver lifetime",
              "not_proven": ["independent-hardware replication", "TCP/fragment/extension-header filtering", "link withdrawal/recovery", "Anycast runtime", "100/1000-AS runtime"]}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    main(parser.parse_args())
