# Public validation examples

These are bounded examples from the release qualification, not all historical
experiments or the original private host logs.

The [qualification summary](qualification.json) lists the completed clean-build,
test and network runs, with hashes linking back to the retained source logs.

## 🌐 TS01 packet and route evidence

`evidence/ts01-release-r1/` contains a transformed evidence subset. The exporter
retains packets, counters, route fingerprints and verifier inputs, and records
source-artifact hashes. The unchanged full source evidence remains separate.
Host inventory and command logs are omitted; host-invariance summaries are
retained assertions, not independently re-auditable host snapshots.

```bash
python3 lab/validation/verify_ts01_bgp01.py \
  examples/evidence/ts01-release-r1/result.json \
  --output /tmp/savop-example-audit.json
```

The output must be a new file. This checks the exported inputs without modifying
the bundled example or implying that omitted host logs were inspected.

## 📊 Rule-component measurements

`benchmarks/rule-components/` contains 504 raw measurements, the frozen design,
correctness-check summaries, environment metadata, summaries and file checksums.
Hostnames and absolute source/build paths are omitted. Input generation and the
pinned Python reference are described in the [benchmark guide](../benchmarks/python_rust/README.md).
No whole-system acceleration is inferred from these component timings.

```bash
python3 benchmarks/python_rust/verify_public_result.py examples/benchmarks/rule-components
```

This independently checks the artifact hashes, 504 scheduled records and all
36 summary rows without starting an Agent or rerunning timing measurements.
