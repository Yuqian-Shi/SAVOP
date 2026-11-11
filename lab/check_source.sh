#!/usr/bin/env bash
# Source-only checks: no package installation, image builds or lab deployment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAB_DIR="${SAVOP_LAB_DIR:-$ROOT/lab}"
cargo_args=(--locked)

case "${1:-}" in
  --offline) cargo_args+=(--offline); shift ;;
  --help|-h)
    printf 'Usage: bash lab/check_source.sh [--offline]\n'
    printf 'Checks source, JSON, Rust tests and release binaries without starting a lab.\n'
    exit 0
    ;;
esac
if [ "$#" -ne 0 ]; then
  printf 'unexpected argument: %s\n' "$1" >&2
  exit 2
fi

for tool in cargo rustfmt cargo-clippy shellcheck jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'missing required tool: %s\n' "$tool" >&2
    exit 2
  fi
done

cd "$ROOT"
if [ ! -d "$LAB_DIR/base_configs" ]; then
  printf 'missing config directory: %s\n' "$LAB_DIR/base_configs" >&2
  exit 2
fi
shopt -s nullglob
shell_files=("$LAB_DIR"/*.sh "$LAB_DIR"/rpki/*.sh)
if [ "${#shell_files[@]}" -eq 0 ]; then
  printf 'no shell scripts found in %s\n' "$LAB_DIR" >&2
  exit 2
fi
for script in "${shell_files[@]}"; do
  bash -n "$script"
done
shellcheck "${shell_files[@]}"

while IFS= read -r -d '' config; do
  jq empty "$config"
done < <(find "$LAB_DIR/base_configs" -type f -name '*.json' -print0)

cargo fmt --all -- --check
cargo clippy "${cargo_args[@]}" --workspace --all-targets -- -D warnings
cargo test "${cargo_args[@]}" --workspace
cargo build "${cargo_args[@]}" --release --workspace --bins

printf 'Source checks passed; router build and network experiments were not run.\n'
