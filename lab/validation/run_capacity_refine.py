"""Refine the first failed coarse bracket in 5-AS steps, then repeat its safe tier."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def main(args):
    root = args.root.resolve(strict=True)
    batch_path = root / "batch-r4.json"
    batch = json.loads(batch_path.read_text())
    successes = [r["AS"] for r in batch["results"] if r["status"] == "passed_capacity_tier"]
    failures = [r for r in batch["results"] if r["status"] != "passed_capacity_tier"]
    if not successes or not failures:
        raise ValueError("Need a completed passing/failing coarse bracket")
    low = max(successes)
    upper = failures[0]["AS"]
    last = json.loads((root / failures[0]["run_id"] / "result.json").read_text())
    if last["cleanup_errors"] or not last.get("host_unchanged"):
        raise RuntimeError("Unsafe prior cleanup; no further tests")
    plan = {"coarse_batch_sha256": hashlib.sha256(batch_path.read_bytes()).hexdigest(),
            "runner_sha256": hashlib.sha256(Path(__file__).with_name("run_capacity.py").read_bytes()).hexdigest(),
            "starting_bracket": [low, upper], "granularity_AS": 5,
            "refine_hold_seconds": 60, "confirm_AS": low, "confirm_hold_seconds": 180,
            "rule": "midpoint rounded down to a multiple of5 until bracket<=5AS, then fresh repeat of coarse passing tier",
            "harness_bookkeeping_since_r4": "Record initial swap and growth explicitly; enforce180s after a full observation too; classify KeyboardInterrupt. Workload/binary/thresholds unchanged. Independent audit rejects any successful earlier phase over180s.",
            "results": []}
    plan_path = root / "refinement-plan.json"
    with plan_path.open("x") as out:
        json.dump(plan, out, indent=2)

    def run(size, tag, hold):
        run_id = f"cap-{size:02d}-v4-{tag}"
        command = [sys.executable, "-B", str(Path(__file__).with_name("run_capacity.py")),
                   "--root", str(root), "--build", str(args.build), "--run-id", run_id,
                   "--as-count", str(size), "--family", "4", "--hold", str(hold)]
        process = subprocess.run(command)
        result = json.loads((root / run_id / "result.json").read_text())
        plan["results"].append({"AS": size, "run_id": run_id, "rc": process.returncode,
                                "status": result["status"], "resources": result.get("steady_resources")})
        plan_path.write_text(json.dumps(plan, indent=2) + "\n")
        if result["cleanup_errors"] or not result.get("host_unchanged"):
            raise RuntimeError("Cleanup failed; stop refinement")
        return result["status"] == "passed_capacity_tier"

    while upper - low > 5:
        middle = ((low + upper) // 2 // 5) * 5
        if middle <= low:
            break
        if run(middle, "boundary", 60):
            low = middle
        else:
            upper = middle
    plan["final_bracket"] = [low, upper]
    plan_path.write_text(json.dumps(plan, indent=2) + "\n")
    passed = run(plan["confirm_AS"], "confirm", 180)
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    raise SystemExit(main(parser.parse_args()))
