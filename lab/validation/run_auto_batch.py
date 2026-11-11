"""Freeze four serial technical replays and their exact sources before launch."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from run_five_as import dump, sha


def main(args):
    root = args.root.resolve(strict=True)
    if root.parent != Path("/mnt/hdd") or not root.name.startswith("k5-five-as-") or not re.fullmatch(r"[a-z0-9-]{3,12}", args.batch):
        raise ValueError("Dedicated data-disk root and short safe batch identifier required")
    design = json.loads(Path(__file__).with_name("auto_design.json").read_text())
    names = ("run_auto_batch.py", "run_auto_five_as.py", "auto_design.json", "auto_fault_ip.sh", "auto_fault_nft.sh",
             "run_five_as.py", "run_dynamic_five_as.py", "dynamic_design.json", "packet_probe.py")
    hashes = {name: sha(Path(__file__).with_name(name)) for name in names}
    schedule = [{"family": af, "repeat": repeat, "run_id": f"{args.batch}-v{af}-r{repeat}"} for af, repeat in design["schedule"]]
    dump(root / (args.batch + "-plan.json"), {"design": design, "files": hashes, "schedule": schedule})
    outcomes = []
    for row in schedule:
        assert hashes == {name: sha(Path(__file__).with_name(name)) for name in names}
        print("RUN " + json.dumps(row), flush=True)
        child = subprocess.run([sys.executable, "-u", str(Path(__file__).with_name("run_auto_five_as.py")),
                                "--root", str(root), "--build", str(args.build.resolve()),
                                "--run-id", row["run_id"], "--family", str(row["family"]), "--repeat", str(row["repeat"])])
        outcomes.append({**row, "returncode": child.returncode})
        if child.returncode:
            break
    passed = len(outcomes) == 4 and all(r["returncode"] == 0 for r in outcomes)
    dump(root / (args.batch + "-results.json"), {"status": "passed_four_rebuilds" if passed else "incomplete_or_failed", "outcomes": outcomes})
    return 0 if passed else 1


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--batch", required=True)
    raise SystemExit(main(p.parse_args()))
