"""Summarize completed evidence only, retaining failed and exploratory runs."""
import argparse
import csv
import json
from pathlib import Path


def main(root):
    audit = json.loads((root / "audit-final.json").read_text())
    audited = {r["run"]: r for r in audit["runs"]}
    rows = []
    for path in sorted(root.glob("cap-*/result.json")):
        result = json.loads(path.read_text())
        samples = [json.loads(line) for line in (path.parent / "resources.jsonl").read_text().splitlines()]
        steady = result.get("steady_resources", {})
        initial_swap = result.get("initial_swap_mib", samples[0]["swap_used_mib"] if samples else 0)
        rows.append({
            "run": path.parent.name, "AS": result["AS_count"], "nodes": result["node_count"],
            "family": result["family"], "status": result["status"],
            "image": result.get("image"),
            "agent_sha256": result.get("provenance", {}).get("target/release/sav_agent"),
            "qualified": audited[path.parent.name]["qualified"],
            "functional_checks_passed": audited[path.parent.name].get("functional_checks_passed", False),
            "exploratory": path.parent.name in ("cap-01-v4-pilot", "cap-01-v4-r1", "cap-01-v4-r2", "cap-01-v4-r3", "cap-05-v4-r3"),
            "cpu_mean_percent": steady.get("cpu_mean_percent"),
            "cpu_p95_percent": steady.get("cpu_p95_percent"),
            "available_min_gib": steady.get("available_min_gib"),
            "swap_growth_steady_mib": steady["swap_max_mib"] - initial_swap if steady else None,
            "cpu_peak_all_phases": max((s["cpu_percent"] for s in samples), default=None),
            "available_min_all_phases_gib": min((s["mem_available_gib"] for s in samples), default=None),
            "swap_peak_all_phases_mib": max((s["swap_used_mib"] for s in samples), default=None),
            "deployment_seconds": result["phase_times"].get("deployment_seconds"),
            "initial_convergence_seconds": result["phase_times"].get("initial_seconds"),
            "prefix_added_seconds": result["phase_times"].get("prefix-added_seconds"),
            "prefix_withdrawn_seconds": result["phase_times"].get("prefix-withdrawn_seconds"),
            "hold_requested_seconds": json.loads((path.parent / "design.json").read_text())["hold_seconds"],
            "udp_requests": audited[path.parent.name].get("udp_requests"),
            "udp_echo_replies": audited[path.parent.name].get("udp_echo_replies"),
            "host_unchanged": result["host_unchanged"],
            "cleanup_errors": json.dumps(result["cleanup_errors"]),
            "error": result.get("error"),
        })
    report = {"machine": json.loads((root / ".claude_resources.json").read_text()),
              "unit": "one development VM; controlled synthetic workload; technical runs only",
              "audit": "audit-final.json", "runs": rows}
    with (root / "summary.json").open("x") as out:
        json.dump(report, out, indent=2)
    with (root / "summary.csv").open("x", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps([r for r in rows if not r["exploratory"]], indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    main(parser.parse_args().root)
