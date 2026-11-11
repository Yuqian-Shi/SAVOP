# Third-party notices

This is a multi-license source distribution. A repository-wide summary does not
override a file's original license or attribution.

## 📋 Component notices

| Component | Source and scope | Notice |
| --- | --- | --- |
| SAV Open Playground | Original NASP-THU framework and derived portions | Copyright (c) 2024 NASP; MIT text in `LICENSES/MIT.txt`[^1] |
| BIRD-derived router | `router/` | Preserve original headers and `router/distro/pkg/deb/copyright`; GPL v2 or later for most files, with per-file exceptions[^2] |
| BIRD helper exceptions | `router/lib/heap.h`, `printf.c`, `md5.c` and other embedded code | Follow each file and packaging notice, including LGPL, GPL-v2-only and public-domain notices |
| Embedded libraries/build tools | cJSON, BLAKE2, Autoconf helpers, LinuxDoc tooling | Original copyright/license headers and tool notices are retained in their source files |
| Rust dependencies | Locked crates in `Cargo.lock` | Dependency source licenses remain their own; no vendored crate bundle is included |
| Optional Python reference | Downloaded only by the benchmark fetcher | Pinned upstream files and MIT notice; not copied from an unversioned local legacy directory |

Complete GPL v2, LGPL v2 and LGPL v2.1 texts are supplied in `LICENSES/`.
The router is a separate executable from the Rust Agent; this preview ships
source, not prebuilt router binaries or container images.

## 🌐 External datasets

CAIDA and RIPE RIS downloads and generated databases are not bundled. Retrieval
scripts preserve source metadata; users must review the providers' applicable
terms and attribution requirements before redistribution.[^3][^4] Public AS
observations do not establish source-address authorization.

[^1]: NASP-THU. MIT license. https://github.com/NASP-THU/SAV-Open-Playground/blob/main/LICENSE
[^2]: BIRD. Project and source. https://bird.network.cz/
[^3]: CAIDA. Acceptable use agreement. https://www.caida.org/about/legal/aua/
[^4]: RIPE NCC. RIS raw data. https://data.ris.ripe.net/
