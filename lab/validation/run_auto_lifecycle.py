"""Final binary regression: full auto suite plus signal stop/start compatibility."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time
import traceback

from run_auto_five_as import AutoLab
from run_five_as import dump, sha


def lifecycle(lab):
    lab.api(3, "/enable_sav_table", {"active_app": "strict_urpf"})
    before = lab.wait_auto("before-signal-stop", lab.synced)
    signal = lab.generated / "3/signal.json"
    signal.write_text(json.dumps({"command": "stop", "validation": lab.args.run_id}), encoding="utf-8")
    start = time.monotonic()
    outcome = None
    while time.monotonic() - start < 15:
        response = lab.execute(3, "/bin/cat", "/node/log/exec_results.json", check=False)
        if response.returncode == 0:
            outcome = json.loads(response.stdout)
            if outcome["action"] == "stop":
                break
        time.sleep(0.1)
    assert outcome and outcome["action"] == "stop" and outcome["execute_result"] == "ok"
    stopped = lab.snapshot("after-signal-stop")
    time.sleep(1)
    retained = lab.snapshot("signal-stop-stays-paused")
    assert stopped["state"]["paused"] and retained["state"]["paused"]
    assert stopped["nft_rc"] != 0 and retained["nft_rc"] != 0
    assert retained["state"]["refresh_count"] == before["state"]["refresh_count"]
    bird = lab.execute(3, "/build/router/birdc", "-s", "/node/bird.ctl", "show status", check=False)
    assert bird.returncode != 0
    signal.write_text(json.dumps({"command": "start", "validation": lab.args.run_id}), encoding="utf-8")
    lab.wait_routes("signal-restart-routing")
    resumed = lab.wait_auto("signal-restart-auto-installed", lambda r: lab.synced(r)
                            and not r["state"]["paused"]
                            and r["state"]["refresh_count"] > before["state"]["refresh_count"])
    result = lab.execute(3, "/bin/cat", "/node/log/exec_results.json")
    restarted = json.loads(result.stdout)
    assert restarted["action"] == "start" and restarted["execute_result"] == "ok"
    lab.report["lifecycle"] = {"stop_result": outcome, "start_result": restarted,
                               "bird_stopped_rc": bird.returncode, "before": before,
                               "stopped": stopped, "retained": retained, "resumed": resumed}
    print(json.dumps({"check": "signal-stop-start-compatibility", "pass": True}), flush=True)


def main(args):
    if os.geteuid() != 0:
        raise SystemExit("Root required on the dedicated development VM")
    lab = AutoLab(args)
    try:
        lab.prepare()
        shutil.copy2(__file__, lab.run / Path(__file__).name)
        lab.report["provenance"][Path(__file__).name] = sha(__file__)
        lab.initial_checks()
        lab.automatic_link_changes()
        lab.drift_checks()
        lab.fault_checks()
        lab.pause_preview_switch()
        lifecycle(lab)
        lab.report["status"] = "passed_auto_five_as_calibration"
    except Exception:
        lab.report["status"], lab.report["error"] = "failed", traceback.format_exc()
        print(lab.report["error"], flush=True)
    finally:
        lab.cleanup()
        dump(lab.run / "result.json", lab.report)
    print(json.dumps({"status": lab.report["status"], "report": str(lab.run / "result.json")}), flush=True)
    return int(lab.report["status"] != "passed_auto_five_as_calibration")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--family", type=int, choices=(4, 6), required=True)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--pilot", action="store_true")
    raise SystemExit(main(p.parse_args()))
