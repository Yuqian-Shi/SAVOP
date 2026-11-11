"""Check that the independent auditor rejects deliberately corrupted records."""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from verify_dynamic_five_as import audit_run


def main(run, output):
    original = json.loads((run / "result.json").read_text())
    audit_run(run, original)
    mutations = {}
    changed = deepcopy(original)
    changed["bursts"][0]["receivers"]["5"]["packets"][0]["payload"] = "false-sequence"
    mutations["receiver_identity"] = changed
    changed = deepcopy(original)
    changed["bursts"][0]["drop_after"]["packets"] += 1
    mutations["drop_counter"] = changed
    changed = deepcopy(original)
    changed["bursts"][0]["source_route_get"][0]["dev"] = "eth_999"
    mutations["actual_source_path"] = changed
    changed = deepcopy(original)
    changed["states"] = changed["states"][:-1]
    mutations["missing_state"] = changed
    changed = deepcopy(original)
    event = next(e for e in changed["dynamic_events"] if e["kind"] == "anycast-withdrawal")
    event["remaining_site"] = event["withdrawn_site"]
    mutations["false_anycast_switch"] = changed
    changed = deepcopy(original)
    changed["host_after"]["routes4"] = []
    mutations["host_route_change"] = changed
    rejected = []
    for name, report in mutations.items():
        try:
            audit_run(run, report)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError("Auditor accepted corrupted record: " + name)
    result = {"status": "passed_audit_negative_controls", "run": run.name, "rejected": rejected,
              "scope": "validator checks, not network experiments"}
    with output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    main(a.run, a.output)
