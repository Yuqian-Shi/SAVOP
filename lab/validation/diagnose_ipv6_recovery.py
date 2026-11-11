"""Isolated paired diagnostic; never counts as a passing dynamic calibration."""
import argparse
import json
from pathlib import Path
import traceback

from run_dynamic_five_as import DynamicLab, dump


def capture(lab, tag):
    evidence = {}
    for node, peer in ((3, 4), (4, 3)):
        evidence[str(node)] = {}
        for name, command in (
            ("addresses", ["ip", "-j", "-6", "addr", "show", "dev", f"eth_{peer}"]),
            ("neighbors", ["ip", "-j", "-6", "neigh", "show", "dev", f"eth_{peer}"]),
            ("nft", ["nft", "-j", "list", "ruleset"]),
        ):
            evidence[str(node)][name] = json.loads(lab.execute(node, *command).stdout)
    dump(lab.run / f"diagnostic-{tag}.json", evidence)


def main(args):
    lab = DynamicLab(args)
    try:
        lab.prepare()
        lab.route_tests()
        try:
            lab.link_change()
            lab.report["status"] = "failure_not_reproduced"
        except RuntimeError as exc:
            lab.report["original_failure"] = str(exc)
            capture(lab, "sav-enabled")
            lab.switch_filter("none")
            lab.wait_state("diagnostic-sav-disabled", expected_dev="eth_4")
            capture(lab, "sav-disabled")
            lab.report["status"] = "recovery_after_removing_sav_observed"
    except Exception:
        lab.report.update(status="diagnostic_failed", error=traceback.format_exc())
    finally:
        lab.cleanup()
        dump(lab.run / "result.json", lab.report)
    print(json.dumps({"status": lab.report["status"]}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--run-id", required=True)
    p.set_defaults(family=6, pilot=True, repeat=0)
    main(p.parse_args())
