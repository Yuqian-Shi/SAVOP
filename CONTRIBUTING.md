# Contributing to SAVOP

Keep changes reproducible and separate the Rust runtime from Python test tools.
Describe the affected mechanism, input assumptions and executed checks.

## 🔧 Local checks

```bash
bash lab/check_source.sh
python3 -m unittest discover -s lab/validation -p 'test_*.py'
python3 -m unittest discover -s lab/topology -p 'test_*.py'
```

Network tests require a dedicated Linux VM and explicit run directories. Do not
run privileged lab deployment as part of an untrusted pull-request workflow.

## 📋 Review expectations

- Retain original copyrights, licenses and source provenance
- Add an independent expected result and negative cases where relevant
- Preserve failed runs; do not relax frozen thresholds after observing a failure
- Separate component timings, full workflow timings and traffic throughput
- Keep credentials, downloaded data, local build artifacts and internal project documents out of commits

## 🤝 Upstream relationship

This fork is independently maintained. Propose small compatible upstream fixes
separately; do not imply upstream endorsement or acceptance of this Rust branch.
