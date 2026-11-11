# SAVOP

Rust-based, router-level experiments for source address validation.

This is an independently maintained engineering derivative of NASP-THU's
SAV Open Playground, not an official upstream release.[^1] The preview scope is
small-scale BGP/SAV experiments, automatic strict/loose uRPF reconciliation,
and independently checkable evidence. The 1000-AS DES/ECS backend is not implemented.

See the [quick start](docs/quickstart.md), [support matrix](docs/support-matrix.md),
[validation guide](docs/validation.md), [benchmark guide](benchmarks/python_rust/README.md),
and [upstream provenance](docs/upstream.md).

SAVOP is a router-level SAV emulator for studying BGP convergence and source address validation mechanisms. The active implementation uses Rust per-router agents, BIRD, and containerlab.

## Repository Layout

- `agent/`: Rust agent, lab generator, route probe, SAV-table probe, and topology slicing tools. SAV mechanisms live under `agent/src/sav_apps/`; see `agent/src/sav_apps/README.md` for adding new SAV apps.
- `lab/`: emulator configs, Dockerfiles, RPKI helpers, benchmarks, and compatibility wrappers.
- `router/`: BIRD-based router source used by the emulator runtime.
- `savop_demo/`: retained historical implementations, experiment data and demo assets. It is not part of the active Cargo workspace or runtime; keep it out of new commits and root Docker build contexts.

Large downloaded topology datasets, generated lab directories, benchmark results, Rust build artifacts, and BIRD build outputs are intentionally ignored by git.

Repository paths are declared in `savop.toml`. The `savop` CLI reads that file and passes the resolved paths to internal tools, so normal workflows do not depend on absolute machine paths or the caller's current subdirectory.

## Quick Start

Use a dedicated Linux VM with Docker, Rust, BIRD build dependencies and Python
test dependencies installed; see the [dependency list](docs/quickstart.md).
The Rust Agent is the runtime; Python is used by topology and test tools.

```sh
export SAVOP_ROOT="$(pwd)"

# Build from source without running the broad legacy host installer.
cargo build --locked --release --workspace --bins
target/release/savop router build
target/release/savop image build runtime
target/release/savop doctor
target/release/savop lab run 5_nodes_v6.json
```

On an already prepared machine:

```sh
export SAVOP_ROOT="$(pwd)"
cargo build --release --workspace --bins
target/release/savop router build
target/release/savop image build runtime
target/release/savop doctor
target/release/savop lab run 5_nodes_v6.json
```

The default path is containerlab + Rust. Legacy non-containerlab lab builders and Python agent paths have been removed from the active workflow.
The default five-node example is one AS, not the [5-AS / 50-node fixture](docs/validation.md).
The latter uses an isolated Docker/network-namespace harness rather than the
containerlab management network. Its explicit-refresh SAV arms and the separate
automatic-update test must not be conflated.

## Main Entrypoint

- `target/release/savop`: primary CLI for router builds, image builds, lab generation, runs, benchmarks, topology slicing, and path inspection.
- `lab/bench_scale.sh` and `lab/bench_fib_window.sh`: compatibility wrappers used by the CLI.

See `lab/README.md` for detailed usage and tuning knobs.


## Release Checks

For source checks without installing system packages, building Docker images or
starting an experimental network, run this on the Linux development machine:

```sh
bash lab/check_source.sh --offline
```

Omit `--offline` only when Cargo needs to download locked dependencies. The check
requires Cargo, rustfmt, Clippy, ShellCheck and jq. To keep build artifacts off the
system disk, set `CARGO_TARGET_DIR` to a dedicated data-disk directory. These checks
cover formatting, shell syntax/lint, JSON syntax, Rust lint/tests and release
binaries; they do not establish SAV correctness or multi-AS deployment readiness.

Run these checks before publishing or tagging a release:

```sh
bash lab/release_check.sh
```

The full release check builds router binaries and a Docker image, then starts a
lab. Run it only in a prepared, isolated environment. Its default
`5_nodes_v6.json` smoke test has five routers in one AS, not five independent ASes.

Use git for publishing so ignored local datasets and build artifacts are not uploaded.

## License

SAVOP is released under multiple licenses. SAVOP-owned Rust/lab code outside
`router/` is MIT-licensed. `router/` contains BIRD-derived GPL-licensed source.
See `LICENSE` and `router/LICENSE`.

Original upstream notices and complete applicable license texts are retained in
[`LICENSES/`](LICENSES/). See [third-party notices](THIRD_PARTY_NOTICES.md).

[^1]: NASP-THU. SAV Open Playground, upstream reference commit `0696df96e482c1ed7e437dd25b589509733bb6b8`. https://github.com/NASP-THU/SAV-Open-Playground/tree/0696df96e482c1ed7e437dd25b589509733bb6b8
