"""Paired Python / frozen Rust-full / Rust snapshot-cache regression experiment."""
import argparse
import csv
import itertools
import json
import os
from pathlib import Path
import random
import shutil
import statistics
import time
import run_benchmark as base

VARIANTS = ("python", "rust_full", "rust_cached")
APPS = ("strict_urpf", "loose_urpf")

def expected_counts(cell):
    """Output cardinalities for the frozen four-to-five-interface fixture."""
    n, loops = cell["input_routes"], cell["iterations"]
    if cell["app"] != "fp_urpf":
        return n, n * loops
    if cell["mode"] == "full":
        return 4 * n, 4 * n * loops
    return n * (4 + loops % 2), n * (4 * loops + (loops + 1) // 2)

def prepare(a):
    out = a.root / "results"
    out.mkdir()
    shutil.copytree(a.previous / "results/inputs", out / "inputs")
    cells = [dict(app=app, family=f, input_routes=n, mode=m, iterations=max(4, 100000 // n))
             for app, f, n, m in itertools.product(a.apps, (4, 6), (1000, 10000, 50000), ("full", "update"))]
    rng = random.Random(20261019)
    orders = list(itertools.permutations(VARIANTS))
    order_offsets = [rng.randrange(6) for _ in cells]
    schedule = []
    for repeat in range(7):
        indices = list(range(len(cells)))
        rng.shuffle(indices)
        for i in indices:
            schedule.append(dict(cells[i], repeat=repeat, order=orders[(order_offsets[i] + repeat) % 6]))
    design = dict(seed=20261019, repeats=7, apps=a.apps, cells=len(cells), cpu_affinity=[2], schedule=schedule,
        timing="Same inputs/loop counts as previous; cached Rust includes snapshot scanning and pruning, no precomputed delta",
        full="Cold rule cache construction each iteration (not a warm cache hit)",
        update="1% interface changes, A/B alternating; Python precomputed FIB deltas, cached Rust scans full prepared snapshot",
        fp_output_effect="For FP-uRPF both Rust variants use full generation; 1% input change expands output 4N -> 5N",
        variant_labels={"python": "original Python", "rust_full": "frozen pre-cache Rust", "rust_cached": "current Rust (cache only for strict/loose)"},
        harness_change="Cache consumer black-boxes the entire borrowed rule table before reading length",
        memory="Worker VmHWM includes imports, adapters, both prepared states and warmup; not the whole Agent",
        process_metrics="Fresh worker CPU and wall time include startup, parsing and warmup; core_ms excludes those costs",
        excluded="Kernel polling/parsing, JSON output serialization, BIRD, nft installation, real traffic",
        statistics="Within-VM technical repetitions; median paired ratios and observed range; no population inference",
        acceptance="All canonical rule values equal independent expectation before timing; original full path retained",
        variants=VARIANTS, source=str(a.root), previous=str(a.previous))
    base.dump(out / "design.json", design)
    sources = list((a.root / "agent/src").rglob("*.rs"))
    sources += [a.root / "Cargo.toml", a.root / "Cargo.lock"]
    sources += [p for p in Path(__file__).parent.rglob("*") if p.is_file() and p.suffix in (".py", ".rs", ".toml", ".lock")]
    sources += list((a.legacy / "sav_agent").rglob("*.py")) + list((a.legacy / "utils").rglob("*.py"))
    base.dump(out / "manifest.json", dict(timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        hostname=base.platform.node(), kernel=base.platform.release(), python=base.sys.version,
        rustc=base.command_text(["rustc", "-Vv"]), cargo=base.command_text(["cargo", "-V"]),
        dependencies={name: base.importlib.metadata.version(name) for name in ("netaddr", "pyroute2", "requests")},
        baseline_manifest_sha256=base.sha(a.previous / "results/manifest.json"),
        design_sha256=base.sha(out / "design.json"), resource_sha256=base.sha(a.root / "resources.json"),
        binaries={"rust_full": {"path": str(a.baseline_binary), "sha256": base.sha(a.baseline_binary)},
                  "rust_cached": {"path": str(a.binary), "sha256": base.sha(a.binary)}},
        inputs={p.name: base.sha(p) for p in (out / "inputs").iterdir()},
        source_files={str(p): base.sha(p) for p in sources}))
    print(f"prepared {len(cells)} cells / {len(schedule)} triplets", flush=True)

def worker(a, variant, fixture, app, mode, iterations):
    os.environ["SAVOP_BENCH_RULE_PATH"] = "incremental" if variant == "rust_cached" else "full"
    binary = a.baseline_binary if variant == "rust_full" else a.binary
    return base.worker(a.root, a.legacy, binary, "python" if variant == "python" else "rust", fixture, app, mode, iterations)

def verify(a):
    checks = []
    design = json.loads((a.root / "results/design.json").read_text())
    for app, family, n in itertools.product(design.get("apps", APPS), (4, 6), (1000, 10000, 50000)):
        fixture = a.root / "results/inputs" / f"v{family}-{n}.json"
        expected = base.expected(json.loads(fixture.read_text()), app)
        for variant in VARIANTS:
            observed = worker(a, variant, fixture, app, "verify", 1)
            assert observed == expected, (variant, app, family, n)
        checks.append(dict(app=app, family=family, input_routes=n, passed=True,
                           rule_counts=[len(state) for state in expected],
                           canonical_sha256=base.hashlib.sha256(json.dumps(expected, separators=(",", ":")).encode()).hexdigest()))
        print(f"verified {app} IPv{family} N={n}", flush=True)
    edge = a.root / "results/inputs/edge-loopback.json"
    edge_values = {variant: worker(a, variant, edge, "strict_urpf", "verify", 1) for variant in VARIANTS}
    assert edge_values["rust_full"] == edge_values["rust_cached"]
    base.dump(a.root / "results/verification.json", dict(passed=True, checks=checks,
        edge_probe=dict(name="strict_urpf_lo_interface", values=edge_values,
                        equal=edge_values["python"] == edge_values["rust_cached"],
                        interpretation="Outside equivalent timed workload; upstream filtering not tested")))

def run(a):
    out = a.root / "results"
    assert json.loads((out / "verification.json").read_text())["passed"]
    design = json.loads((out / "design.json").read_text())
    with (out / "raw.jsonl").open("x") as stream:
        for triplet, cell in enumerate(design["schedule"]):
            assert base.available_kib() > 2048 * 1024
            fixture = out / "inputs" / f"v{cell['family']}-{cell['input_routes']}.json"
            for variant in cell["order"]:
                load = os.getloadavg()
                result = worker(a, variant, fixture, cell["app"], cell["mode"], cell["iterations"])
                assert (result["count"], result["count_sum"]) == expected_counts(cell)
                stream.write(json.dumps(dict(cell, triplet=triplet, variant=variant, loadavg_before=load,
                                             timestamp_ns=time.time_ns(), **result)) + "\n")
                stream.flush()
            if (triplet + 1) % 12 == 0:
                print(f"completed {triplet + 1}/{len(design['schedule'])} triplets", flush=True)

def summarize(a):
    out = a.root / "results"
    manifest = json.loads((out / "manifest.json").read_text())
    assert base.sha(out / "design.json") == manifest["design_sha256"]
    for path, checksum in manifest["source_files"].items():
        assert base.sha(Path(path)) == checksum, path
    for name, checksum in manifest["inputs"].items():
        assert base.sha(out / "inputs" / name) == checksum
    for item in manifest["binaries"].values():
        assert base.sha(Path(item["path"])) == item["sha256"]
    design = json.loads((out / "design.json").read_text())
    raw = [json.loads(s) for s in (out / "raw.jsonl").read_text().splitlines()]
    expected_cells = len(design.get("apps", APPS)) * 12
    assert len(raw) == len(design["schedule"]) * 3 == expected_cells * 7 * 3
    groups = {}
    for index, row in enumerate(raw):
        triplet, slot = divmod(index, 3)
        cell = design["schedule"][triplet]
        assert row["triplet"] == triplet and row["variant"] == cell["order"][slot]
        assert all(row[k] == cell[k] for k in ("app", "family", "input_routes", "mode", "iterations", "repeat"))
        assert (row["count"], row["count_sum"]) == expected_counts(cell)
        key = tuple(cell[k] for k in ("app", "family", "input_routes", "mode"))
        groups.setdefault(key, {}).setdefault(row["repeat"], {})[row["variant"]] = row
    summary = []
    for key, repeats in sorted(groups.items()):
        assert len(repeats) == 7
        row = dict(zip(("app", "family", "input_routes", "mode"), key))
        for variant in VARIANTS:
            values = [r[variant]["elapsed_ns"] / r[variant]["iterations"] / 1e6 for r in repeats.values()]
            row[variant + "_ms"] = statistics.median(values)
            row[variant + "_ms_min"] = min(values)
            row[variant + "_ms_max"] = max(values)
            row[variant + "_rss_mib"] = statistics.median(r[variant]["peak_rss_kib"] / 1024 for r in repeats.values())
            row[variant + "_process_cpu_ms"] = statistics.median(r[variant]["process_cpu_seconds"] * 1000 for r in repeats.values())
            row[variant + "_process_wall_ms"] = statistics.median(r[variant]["process_wall_ns"] / 1e6 for r in repeats.values())
        for comparator in ("python", "rust_full"):
            ratios = [r[comparator]["elapsed_ns"] / r["rust_cached"]["elapsed_ns"] for r in repeats.values()]
            row[comparator + "_over_cached"] = statistics.median(ratios)
            row[comparator + "_over_cached_min"] = min(ratios)
            row[comparator + "_over_cached_max"] = max(ratios)
        summary.append(row)
    assert len(summary) == expected_cells
    base.dump(out / "summary.json", summary)
    with (out / "summary.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    base.dump(out / "audit.json", dict(passed=True, raw_sha256=base.sha(out / "raw.jsonl"),
        source_files_checked=len(manifest["source_files"]), raw_rows=len(raw), cells=len(summary)))
    print(f"all source/input/binary hashes, {len(raw)} rows, order and counts verified", flush=True)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("stage", choices=("prepare", "verify", "run", "summarize"))
    p.add_argument("--apps", nargs="+", choices=base.APPS, default=list(APPS))
    for name in ("root", "previous", "legacy", "binary", "baseline-binary"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    assert len(args.apps) == len(set(args.apps)), "duplicate algorithm"
    {"prepare": prepare, "verify": verify, "run": run, "summarize": summarize}[args.stage](args)
