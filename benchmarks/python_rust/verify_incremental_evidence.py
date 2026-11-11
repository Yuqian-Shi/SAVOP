"""Independent local check of frozen three-way measurements and current source."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

evidence, project = map(Path, sys.argv[1:])
out = evidence / "results"
load = lambda name: json.loads((out / name).read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
manifest, design, audit = load("manifest.json"), load("design.json"), load("audit.json")
assert audit["passed"] and sha(out / "raw.jsonl") == audit["raw_sha256"]
assert sha(out / "design.json") == manifest["design_sha256"]
assert sha(evidence / "resources.json") == manifest["resource_sha256"]
for path, digest in manifest["source_files"].items():
    if "/python_rust/" in path:
        local = evidence / "python_rust" / path.split("/python_rust/", 1)[1]
    elif "/legacy/" in path:
        local = project / "SAVOP/savop_demo" / path.split("/legacy/", 1)[1]
    else:
        local = project / "SAVOP" / Path(path).relative_to(design["source"])
    assert sha(local) == digest, str(local)
for name, digest in manifest["inputs"].items():
    assert sha(out / "inputs" / name) == digest
for variant, item in manifest["binaries"].items():
    assert sha(evidence / (variant + ".bin")) == item["sha256"]
raw = [json.loads(s) for s in (out / "raw.jsonl").read_text().splitlines()]
expected_cells = len(design.get("apps", ("strict_urpf", "loose_urpf"))) * 12
assert len(raw) == len(design["schedule"]) * 3 == expected_cells * 7 * 3
groups = {}
for index, row in enumerate(raw):
    triplet, within = divmod(index, 3)
    cell = design["schedule"][triplet]
    assert row["triplet"] == triplet and row["variant"] == cell["order"][within]
    assert all(row[k] == cell[k] for k in ("app", "family", "input_routes", "mode", "repeat", "iterations"))
    # Deliberately derive independently of the runner helper, including FP expansion.
    sizes = [cell["input_routes"] * (4 + ((i + 1) % 2 if cell["mode"] == "update" else 0))
             if cell["app"] == "fp_urpf" else cell["input_routes"] for i in range(cell["iterations"])]
    assert row["count"] == sizes[-1] and row["count_sum"] == sum(sizes)
    key = tuple(cell[k] for k in ("app", "family", "input_routes", "mode"))
    groups.setdefault(key, {}).setdefault(row["repeat"], {})[row["variant"]] = row
summaries = load("summary.json")
assert len(groups) == len(summaries) == expected_cells
verification = load("verification.json")
assert verification["passed"] and len(verification["checks"]) == expected_cells // 2
assert all(check["passed"] for check in verification["checks"])
for summary in summaries:
    key = tuple(summary[k] for k in ("app", "family", "input_routes", "mode"))
    repeats = groups[key]
    assert len(repeats) == 7
    for variant in ("python", "rust_full", "rust_cached"):
        values = [r[variant]["elapsed_ns"] / r[variant]["iterations"] / 1e6 for r in repeats.values()]
        assert math.isclose(statistics.median(values), summary[variant + "_ms"], rel_tol=1e-12)
        for suffix, raw_key, scale in (("_rss_mib", "peak_rss_kib", 1 / 1024),
                                        ("_process_cpu_ms", "process_cpu_seconds", 1000),
                                        ("_process_wall_ms", "process_wall_ns", 1e-6)):
            if variant + suffix in summary:
                actual = statistics.median(r[variant][raw_key] * scale for r in repeats.values())
                assert math.isclose(actual, summary[variant + suffix], rel_tol=1e-12)
    for comparator in ("python", "rust_full"):
        ratios = [r[comparator]["elapsed_ns"] / r["rust_cached"]["elapsed_ns"] for r in repeats.values()]
        assert math.isclose(statistics.median(ratios), summary[comparator + "_over_cached"], rel_tol=1e-12)
        assert math.isclose(min(ratios), summary[comparator + "_over_cached_min"], rel_tol=1e-12)
        assert math.isclose(max(ratios), summary[comparator + "_over_cached_max"], rel_tol=1e-12)
report = dict(passed=True, current_source_and_frozen_harness_files=len(manifest["source_files"]),
              inputs=len(manifest["inputs"]), binaries=2, measured_processes=len(raw), cells=len(groups))
with (out / "local-audit.json").open("x", encoding="utf-8") as stream:
    json.dump(report, stream, indent=2)
print(json.dumps(report))
