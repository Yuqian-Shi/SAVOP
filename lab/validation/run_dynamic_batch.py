"""Freeze and execute six serial, reproducible dynamic five-AS rebuilds."""
import argparse
import json
from pathlib import Path
import random
import re
import subprocess
import sys
from run_five_as import dump, sha


def main(args):
    root = args.root.resolve(strict=True)
    if root.parent != Path("/mnt/hdd") or not root.name.startswith("k5-five-as-") or not re.fullmatch(r"[a-z0-9-]{3,12}", args.batch):
        raise ValueError("Dedicated data-disk root and short safe batch identifier required")
    schedule = []
    rng = random.Random(240006)
    for repeat in range(1, 4):
        families = [4, 6]
        rng.shuffle(families)
        schedule.extend({"family": af, "repeat": repeat, "run_id": f"{args.batch}-v{af}-r{repeat}"} for af in families)
    bundle = {"schema": "k5-dynamic-batch-v1", "seed": 240006, "schedule": schedule,
              "files": {name: sha(Path(__file__).with_name(name)) for name in (
                  "run_five_as.py", "packet_probe.py", "run_dynamic_five_as.py", "dynamic_design.json", "run_dynamic_batch.py")}}
    dump(root / (args.batch + "-plan.json"), bundle)
    outcomes = []
    for row in schedule:
        print("RUN " + json.dumps(row), flush=True)
        child = subprocess.run([sys.executable, "-u", str(Path(__file__).with_name("run_dynamic_five_as.py")),
                                "--root", str(root), "--build", str(args.build.resolve()),
                                "--run-id", row["run_id"], "--family", str(row["family"]), "--repeat", str(row["repeat"])])
        outcomes.append({**row, "returncode": child.returncode})
        if child.returncode:
            break
    status = "passed_six_rebuilds" if len(outcomes) == 6 and all(x["returncode"] == 0 for x in outcomes) else "incomplete_or_failed"
    dump(root / (args.batch + "-results.json"), {"status": status, "outcomes": outcomes})
    print(status, flush=True)
    return 0 if status == "passed_six_rebuilds" else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--batch", required=True)
    raise SystemExit(main(p.parse_args()))
