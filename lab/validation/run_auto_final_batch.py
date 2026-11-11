"""Two address-family full-suite regressions after stop-result compatibility fix."""
import argparse
from pathlib import Path
import subprocess
import sys
from run_five_as import dump, sha


def main(root):
    root = root.resolve(strict=True)
    if root.parent != Path("/mnt/hdd") or not root.name.startswith("k5-five-as-auto-final-"):
        raise ValueError("Dedicated final-regression root required")
    names = ("run_auto_final_batch.py", "run_auto_lifecycle.py", "run_auto_five_as.py", "auto_design.json",
             "run_five_as.py", "run_dynamic_five_as.py", "dynamic_design.json", "packet_probe.py",
             "auto_fault_ip.sh", "auto_fault_nft.sh")
    files = {name: sha(root / name) for name in names}
    build = {name: sha(root / name) for name in ("agent/src/main.rs", "agent/src/auto_dataplane.rs", "target/release/sav_agent")}
    schedule = [{"family": family, "repeat": 1, "run_id": f"auto-final-v{family}"} for family in (4, 6)]
    dump(root / "final-plan.json", {"schedule": schedule, "files": files, "build": build,
                                   "scope": "full automatic-loop suite plus signal stop/start; final compatibility patch only"})
    outcomes = []
    for row in schedule:
        assert files == {name: sha(root / name) for name in names}
        assert build == {name: sha(root / name) for name in build}
        print("RUN " + row["run_id"], flush=True)
        result = subprocess.run([sys.executable, str(root / "run_auto_lifecycle.py"), "--root", str(root), "--build", str(root),
                                 "--run-id", row["run_id"], "--family", str(row["family"]), "--repeat", "1"])
        outcomes.append({**row, "returncode": result.returncode})
        if result.returncode:
            break
    passed = len(outcomes) == 2 and all(row["returncode"] == 0 for row in outcomes)
    dump(root / "final-results.json", {"status": "passed_two_final_regressions" if passed else "incomplete_or_failed", "outcomes": outcomes})
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    raise SystemExit(main(parser.parse_args().root))
