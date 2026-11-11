# Preview support matrix

This table separates implementation presence from executed validation. The
preview is a research emulator, not a production router or a complete SAV
protocol conformance suite.

## 📋 Mechanisms

| Mechanism | Code | Preview validation |
| --- | --- | --- |
| strict uRPF | Rule generation and nftables path | Small-scale IPv4/IPv6 functional tests; automatic reconciliation tested in a separate fixture |
| loose uRPF | Rule generation and nftables path | Small-scale IPv4/IPv6 functional tests; automatic reconciliation tested in a separate fixture |
| FP-uRPF | Rule-generation module | Component comparison; no general data-plane qualification |
| EFP-uRPF A/B, ROA/ASPA variants | Rule-generation modules | Experimental; not independently qualified by this release |
| BAR, Bicone | Rule-generation modules | Experimental; not independently qualified by this release |
| RPDP | Existing module/runtime interfaces | Experimental; full distributed message/state/revocation semantics not qualified |
| Passport | Existing module/runtime interfaces | Experimental; end-to-end authentication not qualified |

Automatic installation is limited to strict/loose uRPF. ECMP/nhid inputs are
rejected by that path. Registered application IDs are not proof of full protocol
support. The Agent HTTP interface is for an isolated lab, not an Internet-facing API.

## 🌐 Fixtures and tools

| Area | Release meaning |
| --- | --- |
| TS01-BGP-01 | Synthetic IPv4, 5 AS / 50 routers; explicit-refresh SAV arms, prefix lifecycle and peer failover |
| Automatic-update fixture | Separate 5-AS IPv4/IPv6 test; FIB polling, installation/readback, drift and selected failure recovery |
| Capacity tooling | Synthetic 10 routers/AS; resource-qualified results depend on the machine and workload |
| AS map and sampling | Source retrieval, provenance, quality checks and configuration preparation; not a full Internet ground truth |
| Python/Rust benchmark | Rule-component timing, not full experiment or network throughput |
| DES/ECS simulation | Planned, not implemented; no 1000-AS/180-second claim |

## 🔍 Known follow-up work

- Continuous-traffic rule-update latency and packet-loss windows
- Broader restart/crash, TCP/ICMP, ECMP and policy-routing coverage
- Longer-duration and independent-hardware repetitions
- Deterministic DES/ECS core and small-scale model calibration
- Legacy wrapper cleanup-scope review; generator protections do not automatically protect every shell wrapper
