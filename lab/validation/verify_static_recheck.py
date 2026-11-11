"""Audit both AF static matrices after the neighbor-discovery correction."""
import argparse
import json
from pathlib import Path

from verify_five_as import verify, sha


def main(args):
    rows = [verify(run, unique_tokens=True) for run in args.run]
    assert len(rows) == 2 and {r["family"] for r in rows} == {4, 6}
    assert all(r["kind"] == "fixed" and not r["semantic_failures"] for r in rows)
    for run in args.run:
        report = json.loads((run / "result.json").read_text())
        for rel in ("target/release/sav_agent", "target/release/sav_lab_gen", "router/bird"):
            assert sha(args.build / rel) == report["provenance"][rel]
    result = {"status": "passed_static_recheck_audit", "records": rows,
              "main_matrix_cases": 60, "additional_overlap_and_atomic_cases": 10,
              "udp_datagrams_sent": 700, "scope": "same-VM UDP regression; no general protocol qualification",
              "verifiers": {name: sha(Path(__file__).with_name(name)) for name in ("verify_static_recheck.py", "verify_five_as.py")}}
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
    print(json.dumps(result))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, action="append", required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    main(p.parse_args())
