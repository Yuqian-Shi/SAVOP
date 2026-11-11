# Reproduce the 5-AS validation

The TS01 fixture has five ASes, ten BIRD/Rust-Agent routers per AS, customer,
provider and peer policy, three SAV comparison arms, prefix withdrawal/restore,
and a peer-link failover stream. It uses Docker with `--network none` and owned
network namespaces, not containerlab's management network.

## ⚙️ Prerequisites and evidence paths

Build the Rust binaries, BIRD tools and `savop_runtime_clab` image following the
[quick start](quickstart.md). Install the pinned Python harness dependency. The
test requires at least 3 GiB of available memory reserve and checks host resource
use and cleanup. Use a dedicated VM, not a shared production host.

Set `SAVOP_EVIDENCE_PARENT` to an existing directory on the data disk. It must
not be `/`; each run uses a new child directory with the required prefix. The
legacy fallback is `/mnt/hdd`. The harness refuses existing run roots, traversal,
wrong parents and root-directory symlinks.

## 🔧 Execute and audit

Run as root or through a deliberately configured `sudo` invocation. Replace
`/data/experiments` below with your existing data-disk directory.

```bash
export SAVOP_EVIDENCE_PARENT=/data/experiments
export SAVOP_ROOT="$PWD"
.venv/bin/python lab/validation/run_ts01_bgp01.py \
  --root "$SAVOP_EVIDENCE_PARENT/k5-ts01-bgp01-release-r1" \
  --build "$SAVOP_ROOT" --run-id release-r1
.venv/bin/python lab/validation/verify_ts01_bgp01.py \
  "$SAVOP_EVIDENCE_PARENT/k5-ts01-bgp01-release-r1/release-r1/result.json"
```

Expected success includes 44 independent checks, eleven ten-packet probe groups,
precise drop-counter changes, unchanged BGP/FIB across SAV arms, and the 600-packet
low-rate failover stream. The independent verifier recalculates saved evidence;
it does not treat an HTTP success response as packet validation.

The root is never reused. Repeat with `release-r2` and `release-r3` and new roots
when checking repeatability. Preserve failed runs and original observations.
The release's actual test record is in [the release notes](release-notes.md).

## 🔄 Automatic updates are a separate test

TS01 deliberately uses explicit rule refresh after its route changes. To test
the autonomous strict/loose reconciliation path, use the separate runner:

```bash
mkdir "$SAVOP_EVIDENCE_PARENT/k5-five-as-release-auto"
.venv/bin/python lab/validation/run_auto_five_as.py \
  --root "$SAVOP_EVIDENCE_PARENT/k5-five-as-release-auto" \
  --build "$SAVOP_ROOT" --run-id auto-v4-r1 --family 4
.venv/bin/python lab/validation/verify_auto_five_as.py --pilot \
  --run "$SAVOP_EVIDENCE_PARENT/k5-five-as-release-auto/auto-v4-r1" \
  --build "$SAVOP_ROOT" \
  --output "$SAVOP_EVIDENCE_PARENT/auto-v4-r1-audit.json"
```

The automatic path polls FIB snapshots. It is not a Netlink-event incremental
pipeline and does not guarantee zero packet loss during updates.
`--pilot` validates supplied runs without asserting the historical four-run
IPv4/IPv6 confirmatory schedule. Run IPv6 separately with a new run ID and
`--family 6`; retain its result and independent audit as well.

## 📦 What to preserve

Keep the result, frozen scene/specification, executed runner, all state snapshots,
packet records, rule counters, resource records and cleanup evidence. Do not
edit raw logs to remove private paths: export a separate, labelled summary for
public sharing, retaining hashes of its source artifacts. A summary alone is not
the full independently auditable raw bundle.
