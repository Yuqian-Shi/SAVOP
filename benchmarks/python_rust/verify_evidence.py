"""Independently audit downloaded evidence, source hashes and summary medians."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

evidence, project = map(Path, sys.argv[1:])
results = evidence / "results"

def read(name):
    return json.loads((results / name).read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

manifest, design, analysis = read("manifest.json"), read("design.json"), read("analysis-provenance.json")
checked = []
for original, expected in manifest["files"].items():
    if "/source/" in original:
        local = project / "SAVOP" / original.split("/source/", 1)[1]
    elif "/legacy/" in original:
        local = project / "SAVOP/savop_demo" / original.split("/legacy/", 1)[1]
    elif "/python_rust/" in original:
        local = evidence / "python_rust" / original.split("/python_rust/", 1)[1]
    else:
        raise ValueError(original)
    assert sha(local) == expected, f"source changed: {local}"
    checked.append(str(local))
for name, expected in manifest["inputs"].items():
    assert sha(results / "inputs" / name) == expected
assert sha(results / "design.json") == manifest["design_sha256"] == analysis["design_sha256"]
assert sha(results / "raw.jsonl") == analysis["raw_sha256"]
assert sha(evidence / "analyze_results.py") == analysis["analysis_script_sha256"]
raw = [json.loads(line) for line in (results / "raw.jsonl").read_text().splitlines()]
assert len(raw) == 504
groups = {}
for index, row in enumerate(raw):
    pair_no, within = divmod(index, 2)
    cell = design["schedule"][pair_no]
    assert row["pair_no"] == pair_no and row["language"] == cell["order"][within]
    assert all(row[k] == cell[k] for k in ("app", "family", "mode", "repeat", "iterations"))
    n, loops = cell["count"], cell["iterations"]
    count = n if cell["app"] != "fp_urpf" else 4 * n
    total = n * loops if cell["app"] != "fp_urpf" else n * (4 * loops + (loops // 2 if cell["mode"] == "update" else 0))
    assert loops % 2 == 0 and row["count"] == count and row["count_sum"] == total
    assert row["elapsed_ns"] > 0 and row["process_wall_ns"] >= row["elapsed_ns"]
    key = (cell["app"], cell["family"], n, cell["mode"])
    groups.setdefault(key, {}).setdefault(cell["repeat"], {})[row["language"]] = row
for summary in read("summary.json"):
    key = tuple(summary[k] for k in ("app", "family", "count", "mode"))
    pairs = groups[key]
    assert len(pairs) == 7
    for language in ("python", "rust"):
        values = [p[language]["elapsed_ns"] / p[language]["iterations"] / 1e6 for p in pairs.values()]
        assert math.isclose(statistics.median(values), summary[language + "_core_ms"], rel_tol=1e-12)
    ratios = [p["python"]["elapsed_ns"] / p["rust"]["elapsed_ns"] for p in pairs.values()]
    assert math.isclose(statistics.median(ratios), summary["paired_speedup_median"], rel_tol=1e-12)
verification = read("verification.json")
assert len(verification["checks"]) == 18 and all(r["pass"] for r in verification["checks"])
report = {"pass": True, "source_files_verified": len(checked), "input_files_verified": len(manifest["inputs"]),
          "timed_processes": len(raw), "pairs": len(design["schedule"]), "cells": len(groups),
          "source_files": checked,
          "note": "frozen executed harness verified separately from updated analysis coordinator; production sources unchanged"}
with (results / "local-verification.json").open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2, ensure_ascii=False)
print(json.dumps({k: v for k, v in report.items() if k != "source_files"}, ensure_ascii=False))
