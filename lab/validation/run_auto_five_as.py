"""Automatic-rule loop qualification: no manual refresh after route changes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import time
import traceback

from run_dynamic_five_as import DynamicLab
from run_five_as import dump, sha


class AutoLab(DynamicLab):
    def __init__(self, args):
        super().__init__(args)
        self.design = json.loads(Path(__file__).with_name("auto_design.json").read_text())
        self.report.update(update_mode="agent-periodic-reconciliation",
                           auto_checks=[], auto_snapshots=[], packet_tests=[])
        self.extra = "198.19.201.0/24" if args.family == 4 else "fd42:2400:ee01::/64"

    def agent_environment(self, node, environment):
        if node == 3:
            environment.update(SAVOP_DATA_PLANE_AUTO="true",
                               SAVOP_DATA_PLANE_INTERVAL_MS=str(self.design["interval_ms"]),
                               SAVOP_DATA_PLANE_COMMAND_TIMEOUT_MS=str(self.design["command_timeout_ms"]),
                               PATH="/build/fault-bin:" + environment["PATH"])
        return environment

    def prepare(self):
        wrappers = self.root / "fault-bin"
        wrappers.mkdir(exist_ok=True)
        for name in ("ip", "nft"):
            source = Path(__file__).with_name(f"auto_fault_{name}.sh")
            target = wrappers / name
            if target.exists() and sha(target) != sha(source):
                raise RuntimeError("Fault wrapper changed in existing root")
            shutil.copy2(source, target)
            target.chmod(0o755)
        super().prepare()
        self.design = json.loads(Path(__file__).with_name("auto_design.json").read_text())
        for name in ("run_auto_five_as.py", "auto_design.json", "auto_fault_ip.sh", "auto_fault_nft.sh",
                     "run_five_as.py", "run_dynamic_five_as.py"):
            source = Path(__file__).with_name(name)
            target = self.run / name
            if not target.exists():
                shutil.copy2(source, target)
            self.report["provenance"][name] = sha(source)
        self.report["auto_design"] = self.design

    def snapshot(self, tag):
        state = self.api(3, "/data_plane")["data"]["data_plane"]
        table = self.execute(3, "/usr/sbin/nft", "-s", "list", "table", "inet", "savop", check=False)
        row = {"tag": tag, "time": time.time(), "state": state,
               "nft_rc": table.returncode, "nft": table.stdout, "nft_stderr": table.stderr,
               "fib": json.loads(self.execute(3, "/usr/sbin/ip", "-j", f"-{self.args.family}", "route", "show", "table", "main").stdout)}
        self.report["auto_snapshots"].append(row)
        return row

    def check(self, tag, passed, **evidence):
        self.report["auto_checks"].append({"tag": tag, "pass": bool(passed), **evidence})
        print(json.dumps({"check": tag, "pass": bool(passed)}), flush=True)
        if not passed:
            raise RuntimeError("Automatic-loop check failed: " + tag)

    def wait_auto(self, tag, condition):
        start = time.monotonic()
        while time.monotonic() - start < self.design["auto_deadline_seconds"]:
            row = self.snapshot(tag)
            if condition(row):
                row["wait_seconds"] = time.monotonic() - start
                return row
            time.sleep(0.1)
        raise RuntimeError("Auto status deadline exceeded: " + tag)

    @staticmethod
    def synced(row):
        state = row["state"]
        return (state["phase"] in ("applied", "in_sync") and state["last_error"] is None
                and state["last_hash"] is not None and row["nft_rc"] == 0)

    def probe_checked(self, tag, mode="strict_urpf", case="unknown", destination=5, expected=None):
        before = self.drop_snapshot()
        row = self.probe(mode, case, destination)
        if expected is not None:
            row["expected_received"] = expected
            row["pass"] = (row["tx"]["sent"] == 10 and row["rx"]["received"] == expected
                           and len({p["payload"] for p in row["rx"]["packets"]}) == expected)
        row.update(tag=tag, drop_before=before, drop_after=self.drop_snapshot())
        row["drop_delta"] = row["drop_after"]["packets"] - before["packets"]
        row["pass"] &= row["drop_delta"] == 10 - row["expected_received"]
        self.report["packet_tests"].append(row)
        self.check(tag, row["pass"], token=row["token"])
        return row

    def initial_checks(self):
        self.wait_routes("boot-routing")
        initial = self.wait_auto("boot-install", self.synced)
        self.check("boot-install", initial["state"]["refresh_count"] >= 1)
        self.api(3, "/disable_sav_table", {})
        self.route_tests()
        first = self.snapshot("paused-control-before")
        self.normal_burst("no-sav-legal")
        self.probe_checked("no-sav-unknown", "none-before")
        later = self.snapshot("paused-control-after")
        self.check("disable-stays-paused", first["state"]["paused"] and later["state"]["paused"]
                   and later["nft_rc"] != 0 and first["state"]["refresh_count"] == later["state"]["refresh_count"])
        self.api(3, "/enable_sav_table", {"active_app": "strict_urpf"})
        first = self.wait_auto("enabled-before-probes", self.synced)
        self.normal_burst("initial-strict-legal")
        self.probe_checked("initial-strict-unknown")
        self.probe_checked("initial-strict-wrong-interface", case="wrong_interface")
        later = self.snapshot("unchanged-after-counters")
        self.check("no-change-no-install", later["state"]["refresh_count"] == first["state"]["refresh_count"]
                   and later["state"]["skip_count"] > first["state"]["skip_count"]
                   and later["state"]["installed_fingerprint"] == first["state"]["installed_fingerprint"])

    def automatic_link_changes(self):
        for state, interface in (("down", "eth_2"), ("up", "eth_4")):
            before = self.snapshot("before-link-" + state)
            started = time.monotonic()
            self.execute(3, "/usr/sbin/ip", "link", "set", "eth_4", state)
            self.execute(4, "/usr/sbin/ip", "link", "set", "eth_3", state)
            self.wait_state("auto-link-" + state, disabled=[(3, 4)] if state == "down" else [], expected_dev=interface)
            after = self.wait_auto("after-link-" + state, lambda r: self.synced(r)
                                   and r["state"]["refresh_count"] > before["state"]["refresh_count"]
                                   and r["state"]["last_hash"] != before["state"]["last_hash"])
            self.check("auto-link-" + state, True, before=before, after=after,
                       stable_observation_seconds=time.monotonic() - started,
                       timing_scope="command + BGP/FIB stabilization + common 3s window + status check; not packet outage")
            self.normal_burst("auto-link-" + state + "-legal")
            # eth_4 is down in the first case; probe unknowns only after restore.
            if state == "up":
                self.probe_checked("auto-link-restored-unknown")

    def drift_checks(self):
        for kind in ("missing", "edited"):
            before = self.wait_auto("before-drift-" + kind, self.synced)
            if kind == "missing":
                self.execute(3, "/usr/sbin/nft", "delete", "table", "inet", "savop")
            else:
                # A harmless extra rule still represents structural drift.
                self.execute(3, "/usr/sbin/nft", "add", "rule", "inet", "savop", "savagent", "counter")
            after = self.wait_auto("repaired-" + kind, lambda r: self.synced(r)
                                   and r["state"]["refresh_count"] > before["state"]["refresh_count"])
            self.check("repair-" + kind, before["state"]["last_hash"] == after["state"]["last_hash"]
                       and before["nft"] == after["nft"], before=before, after=after)
            self.probe_checked("repair-" + kind + "-unknown")

    def fault(self, name, enabled):
        target = self.generated / "3" / ("fault-" + name)
        if enabled:
            target.touch(exist_ok=False)
        else:
            target.unlink()  # Only this runner's exact per-container fault marker.
        self.report["dynamic_events"].append({"kind": "fault", "name": name, "enabled": enabled, "time": time.time()})

    def fault_checks(self):
        for kind, needs_change in (("ip-error", False), ("ip-malformed", False), ("ip-timeout", False),
                                    ("nft-invalid", True), ("nft-timeout", True)):
            before = self.wait_auto("before-" + kind, self.synced)
            self.fault(kind, True)
            if needs_change:
                self.execute(3, "/usr/sbin/ip", f"-{self.args.family}", "route", "add", self.extra, "dev", "eth_4")
            error = self.wait_auto("error-" + kind, lambda r: r["state"]["error_count"] > before["state"]["error_count"]
                                   and r["state"]["last_error"] is not None)
            self.check("error-visible-" + kind, error["state"]["last_hash"] == before["state"]["last_hash"]
                       and error["state"]["refresh_count"] == before["state"]["refresh_count"]
                       and error["nft"] == before["nft"], before=before, error=error)
            self.normal_burst(kind + "-old-rule-legal")
            self.probe_checked(kind + "-old-rule-unknown")
            still = self.snapshot("still-failed-" + kind)
            self.check("old-rules-retained-" + kind, still["nft"] == before["nft"]
                       and still["state"]["refresh_count"] == before["state"]["refresh_count"])
            self.fault(kind, False)
            after = self.wait_auto("recovered-" + kind, lambda r: self.synced(r)
                                   and (not needs_change or r["state"]["refresh_count"] > before["state"]["refresh_count"]))
            self.check("retry-recovery-" + kind, after["state"]["consecutive_errors"] == 0,
                       before=before, after=after)
            if needs_change:
                self.execute(3, "/usr/sbin/ip", f"-{self.args.family}", "route", "del", self.extra, "dev", "eth_4")
                self.wait_auto("extra-removed-" + kind, lambda r: self.synced(r)
                               and r["state"]["last_hash"] == before["state"]["last_hash"])

    def pause_preview_switch(self):
        before = self.wait_auto("before-failed-disable", self.synced)
        self.fault("nft-delete", True)
        response = json.loads(self.execute(3, "curl", "--silent", "--show-error", "--max-time", "5",
                                           "-d", "{}", "http://127.0.0.1:8888/disable_sav_table").stdout)
        paused = self.snapshot("failed-disable-paused")
        self.check("failed-disable-truthful", response["code"] == "5004" and paused["state"]["paused"]
                   and paused["state"]["phase"] == "paused_error" and paused["nft"] == before["nft"], response=response)
        self.fault("nft-delete", False)
        self.api(3, "/disable_sav_table", {})
        before = self.snapshot("before-preview")
        response = self.api(3, "/enable_sav_table", {"active_app": "loose_urpf", "dry_run": True})
        time.sleep(0.7)
        after = self.snapshot("after-preview")
        self.check("preview-does-not-install-or-resume", response["data"]["dry_run"]
                   and after["nft_rc"] != 0 and after["state"]["paused"]
                   and after["state"]["last_hash"] is None
                   and after["state"]["refresh_count"] == before["state"]["refresh_count"]
                   and after["state"]["dry_run_count"] > before["state"]["dry_run_count"])
        # A dry-run of the SAME plan must not prevent this real installation.
        self.api(3, "/enable_sav_table", {"active_app": "loose_urpf"})
        self.wait_auto("resume-loose", self.synced)
        self.probe_checked("loose-wrong-interface", "loose_urpf", "wrong_interface")
        self.probe_checked("loose-unknown", "loose_urpf")
        # Give the previously unknown probe source a route on a different
        # interface: loose must automatically allow it, then reject withdrawal.
        candidate = "198.19.200.0/24" if self.args.family == 4 else "fd42:2400:ee::/64"
        before = self.snapshot("before-loose-prefix")
        self.execute(3, "/usr/sbin/ip", f"-{self.args.family}", "route", "add", candidate, "dev", "eth_2")
        added = self.wait_auto("loose-prefix-added", lambda r: self.synced(r)
                              and r["state"]["refresh_count"] > before["state"]["refresh_count"])
        self.check("loose-auto-add", added["state"]["last_hash"] != before["state"]["last_hash"])
        self.probe_checked("loose-new-prefix-allowed", "loose_urpf", expected=10)
        self.execute(3, "/usr/sbin/ip", f"-{self.args.family}", "route", "del", candidate, "dev", "eth_2")
        removed = self.wait_auto("loose-prefix-removed", lambda r: self.synced(r)
                                and r["state"]["last_hash"] == before["state"]["last_hash"]
                                and r["state"]["refresh_count"] > added["state"]["refresh_count"])
        self.check("loose-auto-withdraw", candidate not in removed["nft"])
        self.probe_checked("loose-withdrawn-prefix-denied", "loose_urpf")
        before = self.snapshot("before-auto-switch")
        self.api(3, "/switch_sav_app", {"active_app": "strict_urpf", "install": False})
        after = self.wait_auto("auto-switch-strict", lambda r: self.synced(r)
                               and r["state"]["refresh_count"] > before["state"]["refresh_count"]
                               and r["state"]["last_result"]["active_app"] == "strict_urpf")
        self.check("auto-app-switch", after["state"]["last_hash"] != before["state"]["last_hash"])
        self.probe_checked("auto-switch-strict-wrong-interface", case="wrong_interface")
        self.api(3, "/disable_sav_table", {})
        self.wait_routes("post-auto-tests")


def main(args):
    if os.geteuid() != 0:
        raise SystemExit("Root required on the development VM")
    lab = AutoLab(args)
    try:
        lab.prepare()
        lab.initial_checks()
        lab.automatic_link_changes()
        lab.drift_checks()
        lab.fault_checks()
        lab.pause_preview_switch()
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
