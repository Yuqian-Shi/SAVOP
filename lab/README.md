# SAVOP Emulator

The active emulator path is Rust + containerlab + shell orchestration. Run commands from the repository root, or set `SAVOP_ROOT` explicitly.

```sh
export SAVOP_ROOT="$(pwd)"
```

Primary entrypoint after `cargo build --release --workspace --bins`:

- `target/release/savop`: user-facing CLI.
- Internal binaries are built into `target/release/` and invoked by the CLI or compatibility wrappers.

Python and legacy development paths are not part of the active workflow.

Path layout is owned by the repository-level `savop.toml`. The CLI exports resolved `SAVOP_*` path variables to these shell wrappers; direct wrapper execution remains supported, but the release interface is `target/release/savop`.

## Build

```sh
cd "$SAVOP_ROOT"
cargo build --release --workspace --bins
target/release/savop router build
target/release/savop image build runtime
target/release/savop doctor
```

## 5-Node Smoke Test

```sh
cd "$SAVOP_ROOT"
KEEP_LAST=0 WAIT=60 ROUTE_STABLE_HOLD=5 target/release/savop lab run 5_nodes_v6.json
```

The benchmark checks route-table stability, not only BGP session startup. For network-interactive SAV apps such as `rpdp`, it also checks active SAV-table stability.

## Generate And Control A Lab

Generation is **new-directory-only**. Existing directories (including empty or
previously generated labs) and files are refused without deletion or overwrite.
Use a new output name for each run; do not pre-create the final output directory.

- Allowed locations: repository `savop_run_*` directories, or the dedicated
  `run_dir` / `bench_work_dir` configured in `savop.toml`.
- Repository/ancestor, source, archive and results paths are protected. `..`
  components and output-path symlinks (including dangling links) are rejected.
- JSON, node IDs, ASNs, prefixes, link references and router input files are
  checked before creating output. A later I/O failure may leave a new partial
  directory for inspection; it is not automatically deleted or reused.
- Successful generation writes `.savop-output.json` with the generated file
  list. This records generation only, not deployment success or permission to
  overwrite. Nested generation inside a completed lab is also refused.

This prevents accidental generator data loss, not hostile concurrent filesystem
replacement. Keep output parents under trusted control. Existing benchmark
wrappers have separate cleanup/summary-writing behavior; in particular,
`bench_fib_window.sh` is not made safe by this generator guard and still needs
its own cleanup-scope review before use. No automatic cleanup command is offered.

```sh
cd "$SAVOP_ROOT"
target/release/savop lab generate 5_nodes_v6.json --out savop_run_clab_5
cd savop_run_clab_5
./setup_clab.sh
./start_clab.sh
./status_clab.sh
./destroy_clab.sh
```

The containerlab runtime image is `savop_runtime_clab`, built from `lab/dockerfiles/savop_runtime_clab` with Aliyun Ubuntu mirrors.

To generate again, use another name such as `savop_run_clab_5_trial2`. For a
fresh `lab run` benchmark, select a new `BENCH_ROOT` below the configured
`bench_work_dir`; the generator no longer erases a previous run for the wrapper.

## Performance And Safety Knobs

- `MODE=rust`: Rust is the default and only active agent path.
- `SAVOP_CLAB_MGMT_IPV4_SUBNET`: containerlab management subnet, default `172.30.0.0/16`.
- `CLAB_SETUP_JOBS`: post-deploy interface setup parallelism, default `min(nproc, 32)`.
- `ROUTE_PROBE_JOBS`: route-stability probe parallelism, default `min(nproc, 16)`.
- `SAV_TABLE_STABLE=auto|1|0`: measure active SAV-table stability automatically for network-interactive apps, always, or never.
- `SAV_TABLE_STABLE_APPS`: comma-separated app list used by auto mode, default `rpdp,passport`.
- `SAV_TABLE_PROBE_JOBS`: active SAV-table probe parallelism, default `ROUTE_PROBE_JOBS`.
- `ROUTE_PROBE_HASH_MODE=ordered|sorted`: ordered avoids per-poll sort work and is the default.
- `ROUTE_STABLE_HASH=combo|rib|fib|raw`: digest used for the hold-window check, default `combo`.
- `START_BATCH_SIZE` and `START_BATCH_DELAY_SEC`: stagger agent/BIRD startup for larger topologies.
- `SWAP_GUARD=1`, `MAX_SWAP_USED_MIB=0`: default no-swap benchmark policy.
- `BIRD_DEBUG=1`: opt in to BIRD `debug all`; default generated configs use `debug { states };` to reduce log and CPU/IO overhead.

## Release Gate

Source-only checks are available as `bash lab/check_source.sh --offline`. They
do not install packages, build images, generate keys or start a network. Omit
`--offline` when locked Cargo dependencies need downloading. Build artifacts can
be placed on the data disk with `CARGO_TARGET_DIR`.

Before publishing, run:

```sh
cd "$SAVOP_ROOT"
bash lab/release_check.sh
```

This full gate builds the router and runtime image and deploys the smoke-test
lab. The default five-node topology uses one ASN and does not validate the
five-independent-AS validation scope. Both gates use locked dependencies;
the full gate also respects `CARGO_TARGET_DIR` for its Rust binary entrypoint.

## SAV App Switching

Inside a router container, query the current selection:

```sh
cd "$SAVOP_ROOT/savop_run_clab_5"
CONTAINER_PREFIX="clab-$(cat .clab_name)-r"
docker exec "${CONTAINER_PREFIX}1" curl -s http://127.0.0.1:8888/sav_app/ | jq .
```

Preview a switch:

```sh
docker exec "${CONTAINER_PREFIX}1" curl -s -X POST http://127.0.0.1:8888/switch_sav_app/   -H 'Content-Type: application/json'   --data-binary '{"active_app":"fp_urpf","dry_run":true}' | jq .
```

Switch and install immediately:

```sh
docker exec "${CONTAINER_PREFIX}1" curl -s -X POST http://127.0.0.1:8888/switch_sav_app/   -H 'Content-Type: application/json'   --data-binary '{"active_app":"fp_urpf"}' | jq .
```

Select only, then install later using the runtime selection:

```sh
docker exec "${CONTAINER_PREFIX}1" curl -s -X POST http://127.0.0.1:8888/switch_sav_app/   -H 'Content-Type: application/json'   --data-binary '{"active_app":"loose_urpf","install":false}' | jq .

docker exec "${CONTAINER_PREFIX}1" curl -s -X POST http://127.0.0.1:8888/enable_sav_table/ | jq .
```

Disable the installed data plane:

```sh
docker exec "${CONTAINER_PREFIX}1" curl -s http://127.0.0.1:8888/disable_sav_table/ | jq .
```

The data plane uses nftables table `inet savop` with set-based matching.

## Results And Data

Historical benchmark summaries may exist under `lab/results/`, but that directory is ignored by git. Raw topology downloads under `lab/data/topologies/raw/` and generated ITDK slices under `lab/base_configs/itdk_slices/` are also ignored by default.
