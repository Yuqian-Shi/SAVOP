#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  printf 'Usage: bash lab/release_check.sh [--offline]\n'
  printf 'Runs source checks, builds router/image artifacts and deploys the smoke-test lab.\n'
  exit 0
fi

cd "$ROOT"

bash "$SCRIPT_DIR/check_source.sh" "$@"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$TARGET_DIR" in
  /*) ;;
  *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
esac
SAVOP_BIN="$TARGET_DIR/release/savop"

"$SAVOP_BIN" router build
"$SAVOP_BIN" image build runtime

"$SAVOP_BIN" doctor
KEEP_LAST=0 WAIT="${WAIT:-90}" ROUTE_STABLE_HOLD="${ROUTE_STABLE_HOLD:-5}" SAV_TABLE_STABLE_HOLD="${SAV_TABLE_STABLE_HOLD:-5}" \
  "$SAVOP_BIN" lab run 5_nodes_v6.json
