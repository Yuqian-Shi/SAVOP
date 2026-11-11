#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
ROUTER_DIR="${SAVOP_ROUTER_DIR:-$ROOT/router}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

need_tool() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "missing required tool: $name" >&2
    return 1
  fi
}

missing=0
for tool in gcc make m4 bison flex; do
  need_tool "$tool" || missing=1
done
if [ ! -x "$ROUTER_DIR/configure" ]; then
  for tool in autoconf autoheader; do
    need_tool "$tool" || missing=1
  done
fi
if [ "$missing" -ne 0 ]; then
  echo "install build dependencies first, for example: bash lab/init_env.sh" >&2
  exit 2
fi

cd "$ROUTER_DIR"

if [ "${FORCE_RECONF:-0}" = "1" ] || [ ! -x ./configure ]; then
  autoconf
  autoheader
fi

if [ "${FORCE_CONFIGURE:-0}" = "1" ] || [ ! -f Makefile ]; then
  # shellcheck disable=SC2086
  ./configure --enable-client --with-protocols=all ${ROUTER_CONFIGURE_ARGS:-}
fi

# A pristine tree needs its output directories before generated source targets
# can run in parallel (not all upstream generators depend on the directory stamp).
make prepare
make -j "$JOBS" all

for bin in bird birdc birdcl; do
  if [ ! -x "$ROUTER_DIR/$bin" ]; then
    echo "router build did not produce $ROUTER_DIR/$bin" >&2
    exit 1
  fi
done

echo "router binaries ready:"
printf '  %s\n' "$ROUTER_DIR/bird" "$ROUTER_DIR/birdc" "$ROUTER_DIR/birdcl"
