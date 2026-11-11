# SAVOP v0.1.0-alpha

This is a source-only alpha of the independently maintained SAVOP downstream
fork. It retains the history of [NASP-THU/SAV-Open-Playground](https://github.com/NASP-THU/SAV-Open-Playground)
and identifies the imported baseline in [the provenance record](upstream.md).

## 📦 Included

- Rust Agent, CLI, router/configuration generation and existing mechanism modules
- BIRD-derived router source and source-build workflow
- Strict/loose automatic-rule reconciliation and selected failure tests
- TS01 5-AS/50-router functional fixture, independent verifier and public evidence exporter
- AS topology data/sampling tools without downloaded databases
- Pinned-upstream Python/Rust component benchmark and reproducibility instructions

## 🔍 Completed qualification

The following checks completed on 10 November 2026. The machine-readable
[qualification summary](../examples/qualification.json) records run IDs and
source-log hashes; the [public examples](../examples/README.md) provide the
independently verifiable evidence subset and component measurements.

| Check | Result |
| --- | --- |
| Clean source archive | rustfmt, Clippy, 71 Rust tests and release build passed |
| BIRD source build | Passed from a clean archive; runtime image rebuilt from candidate binaries |
| Linux Python suites | 134 passed; 7 explicitly skipped because external historical evidence was not supplied |
| New TS01 5-AS/50-router runs | Three fresh deployments; each passed 44/44 independent checks |
| TS01 traffic per run | 110 probes: 70 received, 40 expected SAV drops; failover stream 600/600 received |
| Automatic rule updates | Separate IPv4/IPv6 release regressions, 43 independent checks each; five tampering controls rejected |
| Fixed-reference component benchmark | 18 A→B→A rule-equivalence checks and 504 timing records completed |
| Public benchmark recomputation | All 36 summary rows and 540 numeric values reproduced from included records |

The automatic-update runs use the pilot schedule, not the historical four-run
confirmatory schedule. Network checks ran on one VM. The TS01 failover stream is
a low-rate functional observation, not a general zero-loss convergence claim.

The fresh build also required explicit generated-directory preparation, current
development dependencies and C declaration/type compatibility repairs. The
original source headers and dated downstream notices remain in the router tree.

## 📋 Scope

The preview does not provide a completed DES/ECS simulator or certify 1000-AS
performance. TS01 uses explicit-refresh SAV arms; automatic updating is tested
separately. Experimental mechanism modules are listed in the
[support matrix](support-matrix.md).
