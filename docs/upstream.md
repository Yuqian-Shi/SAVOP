# Upstream relationship and provenance

SAVOP is an independently maintained Rust engineering derivative of NASP-THU's
SAV Open Playground. It is not an official NASP-THU release.[^1]

## 📚 Reference baseline

The publication worktree is based on upstream commit
`0696df96e482c1ed7e437dd25b589509733bb6b8`. Original upstream commits are retained
as Git ancestry. The current development snapshot was imported as a new change;
its incomplete local Git metadata was not treated as recoverable development
history. This publication base is not a claim that all prior local work started
from that exact commit.

The original `sav_agent/`, `sav_control/` and `sav_router/` layout remains
available in upstream history. The Rust branch uses `agent/`, `lab/` and
`router/`. Large legacy demo directories are not duplicated in the current tree.

## 🔧 Downstream changes

- Rust Agent, command-line tools and deterministic rule-generation modules
- Containerlab build/runtime workflow and isolated Docker validation harnesses
- Strict/loose FIB-to-nftables automatic reconciliation and readback
- Explicit AS relationship/policy generation, topology data tools and sampling
- Packet/counter/state evidence, independent verifiers and component benchmarks

The router remains BIRD-derived. Original authorship and third-party licenses
are retained; a Rust rewrite of surrounding tooling does not change the router's
license. See [third-party notices](../THIRD_PARTY_NOTICES.md).

## 🤝 Contributions

Downstream development and issues belong in this repository. Small, compatible
fixes may be proposed upstream separately; the Rust architecture is not assumed
to have been accepted by upstream maintainers. Do not describe an unmerged PR
or this fork as an upstream-endorsed release.

[^1]: NASP-THU. SAV Open Playground. https://github.com/NASP-THU/SAV-Open-Playground
