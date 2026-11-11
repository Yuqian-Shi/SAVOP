"""Run independent capacity tiers serially; stop at the first unsuccessful tier."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main(args):
    root = args.root.resolve(strict=True)
    plan = {"tiers": args.tiers, "family": args.family, "hold": args.hold, "suffix": args.suffix,
            "rule": "fresh independent deployments, stop on any nonzero exit", "results": []}
    path = root / ("batch-" + args.suffix + ".json")
    # Reserve the batch name before mutations, refusing overwrite.
    with path.open("x") as out:
        json.dump(plan, out, indent=2)
    for size in args.tiers:
        run_id = f"cap-{size:02d}-v{args.family}-{args.suffix}"
        command = [sys.executable, "-B", str(Path(__file__).with_name("run_capacity.py")),
                   "--root", str(root), "--build", str(args.build), "--run-id", run_id,
                   "--as-count", str(size), "--family", str(args.family), "--hold", str(args.hold)]
        result = subprocess.run(command)
        report_path = root / run_id / "result.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else {}
        plan["results"].append({"run_id": run_id, "rc": result.returncode, "status": report.get("status"),
                                "AS": size, "resources": report.get("steady_resources")})
        path.write_text(json.dumps(plan, indent=2) + "\n")
        if result.returncode:
            return result.returncode
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--tiers", type=int, nargs="+", required=True)
    parser.add_argument("--family", type=int, choices=(4, 6), default=4)
    parser.add_argument("--hold", type=int, default=60)
    parser.add_argument("--suffix", required=True)
    raise SystemExit(main(parser.parse_args()))
