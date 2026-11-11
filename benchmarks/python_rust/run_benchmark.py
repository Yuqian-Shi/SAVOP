"""Linux-only isolated component benchmark. Outputs are evidence, not a whole-system claim."""
import argparse
import csv
import hashlib
import importlib.metadata
import ipaddress
import itertools
import json
import os
from pathlib import Path
import platform
import random
import resource
import statistics
import subprocess
import sys
import time

APPS = ("strict_urpf", "loose_urpf", "fp_urpf")
SIZES = (1000, 10000, 50000)
SEED = 20261019

def dump(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def command_text(args):
    return subprocess.check_output(args, text=True).strip()

def prepare(root, source, legacy, binary):
    results = root / "results"
    results.mkdir()
    inputs = results / "inputs"
    inputs.mkdir()
    for family, count in itertools.product((4, 6), SIZES):
        rows = []
        for i in range(count):
            prefix = (str(ipaddress.IPv4Network((0x0A000000 + (i << 8), 24))) if family == 4 else
                      str(ipaddress.IPv6Network(((0x20010DB8 << 96) + (i << 64), 64))))
            rows.append({"prefix": prefix, "interface": f"eth{i % 4}", "origin": 64520 + i // 100})
        changed = [dict(row, interface="eth4") if i % 100 == 0 else dict(row) for i, row in enumerate(rows)]
        dump(inputs / f"v{family}-{count}.json", {"family": family, "states": [rows, changed]})
    # An explicitly out-of-main-workload boundary probe. Record divergence; never time as equivalent.
    dump(inputs / "edge-loopback.json", {"family": 4, "states": [[
        {"prefix": "192.0.2.0/24", "interface": "lo", "origin": 64520}], [
        {"prefix": "192.0.2.0/24", "interface": "lo", "origin": 64520}]]})
    cells = [{"app": a, "family": f, "count": n, "mode": m,
              "iterations": max(4, 100000 // n)}
             for a, f, n, m in itertools.product(APPS, (4, 6), SIZES, ("full", "update"))]
    rng = random.Random(SEED)
    first = [rng.choice(("python", "rust")) for _ in cells]
    schedule = []
    for repeat in range(7):
        indices = list(range(len(cells)))
        rng.shuffle(indices)
        for index in indices:
            order = [first[index], "rust" if first[index] == "python" else "python"]
            if repeat % 2:
                order.reverse()
            schedule.append(dict(cells[index], repeat=repeat, order=order))
    design = {"seed": SEED, "scope": "original rule-generation functions plus in-memory table replacement/delta apply",
              "excluded": ["FIB polling/parsing/delta detection", "BIRD", "kernel/nft install", "HTTP/RPDP", "logging", "network traffic"],
              "full": "repeated generation of full table from prepared FIB; clear previous externally held table",
              "update": "alternate prepared FIB states: 1% routes switch eth0 to eth4; Python native delta API vs Rust full rebuild",
              "fp_output_effect": "1% input changes add a fifth interface to each 100-prefix origin; 4N -> 5N rules",
              "warmup_calls": 2, "update_initial_table": "generated untimed after warmup",
              "cpu_affinity": [2], "repeats": 7, "schedule": schedule,
              "interpretation": "technical repetitions on one VM, not independent hardware or language-only causal effect",
              "memory": "worker VmHWM includes imports, input adapters, both prepared states and warmup, not whole Agent",
              "cpu": "fresh worker process user+system seconds, not core-loop-only CPU",
              "process_wall": "spawn through exit including imports/input parse/warmup; excludes correctness serialization",
              "core_wall": "perf_counter_ns / Instant over rule generation and in-memory application; per iteration",
              "timeout_seconds": 120, "minimum_available_memory_mib": 2048,
              "validation": "full sorted rule values against each other AND independent expected mapping for A,B,A; count checked every timed process"}
    dump(results / "design.json", design)
    files = list((source / "agent/src").rglob("*.rs")) + [source / "Cargo.toml", source / "Cargo.lock"]
    files += list((legacy / "sav_agent").rglob("*.py")) + list((legacy / "utils").rglob("*.py"))
    files += [p for p in Path(__file__).parent.rglob("*") if p.is_file() and "target" not in p.parts and p.suffix in (".py", ".rs", ".toml", ".lock")]
    manifest = {"timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "hostname": platform.node(),
                "kernel": platform.release(), "python": sys.version, "rustc": command_text(["rustc", "-Vv"]),
                "cargo": command_text(["cargo", "-V"]), "binary": str(binary), "binary_sha256": sha(binary),
                "source": str(source), "legacy": str(legacy), "loadavg": os.getloadavg(),
                "affinity_available": sorted(os.sched_getaffinity(0)),
                "dependencies": {name: importlib.metadata.version(name) for name in ("netaddr", "pyroute2", "requests")},
                "files": {str(p): sha(p) for p in files},
                "inputs": {p.name: sha(p) for p in inputs.iterdir()}, "design_sha256": sha(results / "design.json")}
    dump(results / "manifest.json", manifest)
    print(json.dumps({"prepared": len(cells), "paired_runs": len(schedule), "root": str(root)}), flush=True)

def worker(root, legacy, binary, language, fixture, app, mode, iterations):
    env = dict(os.environ, SAVOP_LEGACY_ROOT=str(legacy), PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1", LC_ALL="C")
    prefix = [sys.executable, str(Path(__file__).with_name("python_worker.py"))] if language == "python" else [str(binary)]
    cmd = ["taskset", "-c", "2", *prefix, str(fixture), app, mode, str(iterations)]
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter_ns()
    completed = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True, timeout=120)
    wall = time.perf_counter_ns() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    if completed.returncode:
        raise RuntimeError(f"worker failed {cmd}: {completed.stderr[-5000:]}")
    result = json.loads(completed.stdout)
    if mode != "verify":
        result.update(process_wall_ns=wall, process_cpu_seconds=(after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime))
    return result

def expected(fixture, app):
    states = []
    for rows in (fixture["states"][0], fixture["states"][1], fixture["states"][0]):
        if app == "fp_urpf":
            origins = {}
            for row in rows:
                prefixes, interfaces = origins.setdefault(row["origin"], (set(), set()))
                prefixes.add(row["prefix"])
                interfaces.add(row["interface"])
            rules = [[p, i, app, -1, True] for prefixes, interfaces in origins.values() for p in prefixes for i in interfaces]
        else:
            rules = [[r["prefix"], "*" if app == "loose_urpf" else r["interface"], app, -1, True] for r in rows]
        states.append(sorted(rules))
    return states

def verify(root, legacy, binary):
    results = root / "results"
    checks = []
    for app, family, count in itertools.product(APPS, (4, 6), SIZES):
        fixture = results / "inputs" / f"v{family}-{count}.json"
        exp = expected(json.loads(fixture.read_text()), app)
        py = worker(root, legacy, binary, "python", fixture, app, "verify", 1)
        rs = worker(root, legacy, binary, "rust", fixture, app, "verify", 1)
        ok = py == rs == exp
        record = {"app": app, "family": family, "count": count, "pass": ok, "rule_counts": [len(x) for x in py],
                  "canonical_sha256": hashlib.sha256(json.dumps(py, separators=(",", ":")).encode()).hexdigest()}
        checks.append(record)
        print(json.dumps(record), flush=True)
        if not ok:
            dump(results / "verification-failure.json", record)
            raise RuntimeError("non-equivalent main workload; timing forbidden")
    edge = results / "inputs/edge-loopback.json"
    py = worker(root, legacy, binary, "python", edge, "strict_urpf", "verify", 1)
    rs = worker(root, legacy, binary, "rust", edge, "strict_urpf", "verify", 1)
    dump(results / "verification.json", {"main_workloads_pass": True, "checks": checks,
        "edge_probe": {"name": "strict_urpf_lo_interface", "equal": py == rs, "python": py, "rust": rs,
                       "interpretation": "component boundary differs; upstream route filtering not covered"}})

def available_kib():
    return int(next(s for s in Path("/proc/meminfo").read_text().splitlines() if s.startswith("MemAvailable:")).split()[1])

def run(root, legacy, binary):
    results = root / "results"
    assert json.loads((results / "verification.json").read_text())["main_workloads_pass"]
    design = json.loads((results / "design.json").read_text())
    with (results / "raw.jsonl").open("x") as stream:
        for pair_no, cell in enumerate(design["schedule"]):
            assert available_kib() >= 2048 * 1024, "resource stop: insufficient available memory"
            fixture = results / "inputs" / f"v{cell['family']}-{cell['count']}.json"
            for language in cell["order"]:
                load = os.getloadavg()
                result = worker(root, legacy, binary, language, fixture, cell["app"], cell["mode"], cell["iterations"])
                n, loops = cell["count"], cell["iterations"]
                expected_count = n if cell["app"] != "fp_urpf" else n * (5 if cell["mode"] == "update" and loops % 2 else 4)
                expected_sum = n * loops if cell["app"] != "fp_urpf" else n * (4 * loops + ((loops + 1) // 2 if cell["mode"] == "update" else 0))
                assert result["count"] == expected_count and result["count_sum"] == expected_sum
                record = dict(cell, input_routes=cell["count"], pair_no=pair_no,
                              loadavg_before=load, timestamp_ns=time.time_ns(), **result)
                stream.write(json.dumps(record) + "\n")
                stream.flush()
            if (pair_no + 1) % 12 == 0:
                print(f"completed {pair_no + 1}/{len(design['schedule'])} pairs", flush=True)

def summarize(root):
    results = root / "results"
    raw = [json.loads(s) for s in (results / "raw.jsonl").read_text().splitlines()]
    design = json.loads((results / "design.json").read_text())
    groups = {}
    for row in raw:
        # Worker count is OUTPUT rules (FP has 4N/5N), not input routes.
        # Recover the immutable input count from the pre-registered schedule.
        cell = design["schedule"][row["pair_no"]]
        assert all(row[k] == cell[k] for k in ("app", "family", "mode", "repeat", "iterations"))
        key = (row["app"], row["family"], cell["count"], row["mode"])
        groups.setdefault(key, {}).setdefault(row["repeat"], {})[row["language"]] = row
    summary = []
    for (app, family, count, mode), pairs in sorted(groups.items()):
        assert len(pairs) == 7 and all(set(p) == {"python", "rust"} for p in pairs.values())
        entry = dict(app=app, family=family, count=count, mode=mode)
        ratios = [p["python"]["elapsed_ns"] / p["rust"]["elapsed_ns"] for p in pairs.values()]
        entry.update(paired_speedup_median=statistics.median(ratios), paired_speedup_min=min(ratios), paired_speedup_max=max(ratios))
        for language in ("python", "rust"):
            rows = [p[language] for p in pairs.values()]
            values = [r["elapsed_ns"] / r["iterations"] / 1e6 for r in rows]
            entry[language + "_core_ms"] = statistics.median(values)
            entry[language + "_core_min_ms"] = min(values)
            entry[language + "_core_max_ms"] = max(values)
            entry[language + "_peak_rss_mib"] = statistics.median(r["peak_rss_kib"] / 1024 for r in rows)
            entry[language + "_process_cpu_ms"] = statistics.median(r["process_cpu_seconds"] * 1000 for r in rows)
            entry[language + "_process_wall_ms"] = statistics.median(r["process_wall_ns"] / 1e6 for r in rows)
        summary.append(entry)
    assert len(summary) == 36 and len(raw) == 504
    dump(results / "analysis-provenance.json", {
        "analysis_script_sha256": sha(Path(__file__)),
        "raw_sha256": sha(results / "raw.jsonl"),
        "design_sha256": sha(results / "design.json"),
        "input_count_source": "design.schedule[pair_no].count; raw worker count is output rules",
        "statistics": "7 paired technical repetitions; medians and observed ranges, no population inference",
        "raw_rows": len(raw), "cells": len(summary)})
    dump(results / "summary.json", summary)
    with (results / "summary.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    print(json.dumps({"rows": len(raw), "cells": len(summary), "summary": str(results / "summary.csv")}), flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "verify", "run", "summarize"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--legacy", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    if args.stage == "prepare": prepare(args.root, args.source, args.legacy, args.binary)
    elif args.stage == "verify": verify(args.root, args.legacy, args.binary)
    elif args.stage == "run": run(args.root, args.legacy, args.binary)
    else: summarize(args.root)
