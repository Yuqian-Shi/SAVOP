# Build and run SAVOP

The preview runs on a dedicated Linux x86-64 VM. Network experiments require
root, network namespaces and a working Docker daemon. Start with the source
checks; run the 50-router fixture only when the resource reserve is available.

## 🔧 Dependencies

| Component | Preparation |
| --- | --- |
| Rust/Cargo, rustfmt, Clippy | Tested with Rust 1.93.1; use the lockfile |
| Docker and containerlab | Install using their documented distribution procedures[^1][^2] |
| BIRD compilation | C compiler, make, autoconf, bison, flex, pkg-config, readline and SSH development libraries |
| Source checks | Bash, ShellCheck and jq |
| Python test harness | Python 3.10+ with `lab/validation/requirements.txt`; actual release-test versions are recorded separately |
| Optional topology tools | Python 3.11+; `lab/topology/requirements.txt` in a separate virtual environment |

On an existing Debian/Ubuntu development VM, the build packages are typically
`build-essential autoconf bison flex pkg-config libreadline-dev libssh-dev`.
Install packages deliberately for the VM's release. `lab/init_env.sh` is a broad
legacy host installer and is not the preview's recommended entry point.

## ⚙️ Source build

Run from the repository root. Put build artifacts and virtual environments on
your data disk rather than the system disk when space is limited.

```bash
export SAVOP_ROOT="$PWD"
export CARGO_TARGET_DIR="$PWD/target"
python3 -m venv .venv
.venv/bin/python -m pip install -r lab/validation/requirements.txt
bash lab/check_source.sh
target/release/savop router build
target/release/savop image build runtime
target/release/savop doctor
```

`CARGO_TARGET_DIR` is shown at the conventional location because the validation
harness expects `target/release/` under `--build`. An external Cargo target is
also supported by the source check; copy the needed release executables into the
documented build layout before using the network harness.

## 🌐 First experiment

The lightweight containerlab smoke is five routers in one AS:

```bash
target/release/savop lab run 5_nodes_v6.json
```

For five distinct ASes, use the [TS01 validation procedure](validation.md).
That test creates 50 isolated router containers and normally takes several
minutes. A resource stop is a failed or incomplete run, not a result to omit.

## 🔗 References

[^1]: Docker. Install Docker Engine. https://docs.docker.com/engine/install/
[^2]: Containerlab. Installation. https://containerlab.dev/install/
