"""Export a labelled public subset without modifying the original run evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from verify_ts01_bgp01 import audit


RESULT_FIELDS = (
    "status", "run_id", "AS_count", "node_count", "created_nodes", "provenance",
    "route_arm_fingerprint_checks", "probe_results", "events", "live_failover",
    "resource_summary", "host_unchanged", "cleanup_errors",
)
STATE_FIELDS = ("fingerprint", "state_sha256", "pk_present", "peer_up",
                "p_path", "q_path", "elapsed_seconds")
TAGS = ("initial", "before-none", "after-none", "before-strict_urpf", "after-strict_urpf",
        "before-loose_urpf", "after-loose_urpf", "pk-withdrawn", "pk-restored",
        "peer-down", "peer-restored")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def export(result_path, output):
    source = result_path.resolve(strict=True)
    original_audit = audit(source)
    if original_audit["outcome"] != "passed":
        raise ValueError("Do not export an unverified run as a passing example")
    if output.exists() or output.is_symlink():
        raise ValueError("Public export must be a new directory")
    raw = json.loads(source.read_text())
    result = {key: raw[key] for key in RESULT_FIELDS}
    result["provenance"] = {key: raw["provenance"][key]
                            for key in ("ts01-bgp-01.json", "run_ts01_bgp01.py")}
    # Events expose only their mechanism meaning, not command/path details.
    result["events"] = [{k: row[k] for k in ("kind", "prefix") if k in row}
                        for row in raw["events"]]
    output.mkdir(parents=True, exist_ok=False)
    source_hashes = {"result.json": digest(source)}
    write(output / "result.json", result)
    for name in ("scene.json", "ts01-bgp-01.json", "run_ts01_bgp01.py"):
        path = source.parent / name
        shutil.copyfile(path, output / name)
        source_hashes[name] = digest(path)
    for tag in TAGS:
        name = f"state-{tag}.json"
        path = source.parent / name
        state = json.loads(path.read_text())
        write(output / name, {key: state[key] for key in STATE_FIELDS if key in state})
        source_hashes[name] = digest(path)
    report = audit(output / "result.json")
    write(output / "independent-audit.json", report)
    write(output / "export-manifest.json", {
        "schema": "savop-public-ts01-subset-v1",
        "kind": "transformed public evidence subset, not the untouched raw archive",
        "source_artifact_sha256": source_hashes,
        "omitted": ["commands", "host network inventory", "build paths", "absolute host timestamps",
                    "resource time series", "non-verifier result/state fields"],
        "host_scope": "Host invariance/resource summaries are retained assertions; their omitted raw host inventory cannot be re-audited from this subset.",
        "files": {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()},
    })
    if report["outcome"] != "passed":
        raise ValueError("Export did not retain the verifier's required evidence")
    print(json.dumps({"checks_passed": report["checks_passed"],
                      "checks_total": report["checks_total"], "outcome": report["outcome"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    export(args.result, args.output)
