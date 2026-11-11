# Python and Rust rule-component benchmark

This benchmark measures rule generation and in-memory table application, not
the complete Agent, route convergence, nftables installation or network throughput.
It compares strict uRPF, loose uRPF and FP-uRPF with IPv4/IPv6, 1000/10000/50000
input routes, full generation and a prepared 1% update.

## 🔧 Prepare references and build

The Python reference is fetched from a full upstream commit with per-file
SHA-256 validation. It is not the unversioned historical local demo tree.

```bash
export SAVOP_SOURCE_ROOT="$PWD"
export SAVOP_LEGACY_ROOT="$PWD/.cache/python-reference"
python3 -m venv .venv-bench
.venv-bench/bin/python -m pip install -r benchmarks/python_rust/requirements.txt
.venv-bench/bin/python benchmarks/python_rust/fetch_reference.py "$SAVOP_LEGACY_ROOT"
cargo build --locked --release --manifest-path benchmarks/python_rust/Cargo.toml
```

## 📊 Execute the matrix

Use a fresh existing result root outside the repository. The harness pins CPU 2,
requires that CPU in the allowed affinity set, and uses seven technical repeats.

```bash
export BENCH_ROOT=/data/experiments/savop-rule-benchmark-r1
mkdir "$BENCH_ROOT"
export BENCH_BINARY="$PWD/benchmarks/python_rust/target/release/savop-rule-benchmark"
for stage in prepare verify run summarize; do
  .venv-bench/bin/python benchmarks/python_rust/run_benchmark.py "$stage" \
    --root "$BENCH_ROOT" --source "$SAVOP_SOURCE_ROOT" \
    --legacy "$SAVOP_LEGACY_ROOT" --binary "$BENCH_BINARY"
done
```

Correctness verification precedes timing. Results include input/source/binary
hashes, the frozen schedule, raw measurements and summaries. Do not time a
non-equivalent workload or remove slow observations.

## 🔍 Interpretation and historical tooling

Python uRPF updates consume precomputed deltas; the Rust worker here regenerates
the full rule map. The comparison includes an API/workload difference and is
not a language-only causal estimate. `lo` boundary semantics are recorded
separately rather than forced into the equivalence matrix.

`run_incremental.py` and the older evidence verifiers are retained as historical
analysis tools. They additionally require a frozen previous experiment and old
Rust binary; the preview does not bundle or reconstruct those inputs. Their
presence does not make the three-version historical experiment a one-command
release feature. Fresh results from this pinned upstream reference must not be
presented as a reproduction of numbers obtained from a different legacy snapshot.
