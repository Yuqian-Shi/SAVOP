#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAB_DIR="${SAVOP_LAB_DIR:-$ROOT/lab}"
CONFIG_DIR="${SAVOP_CONFIG_DIR:-$LAB_DIR/base_configs}"
RESULTS_DIR="${SAVOP_RESULTS_DIR:-$LAB_DIR/results}"
HOLD="${HOLD:-5}"
WAIT="${WAIT:-240}"
POLL="${POLL:-1}"
BGP_HOLD="${BGP_HOLD:-1}"
POST_FIB_BGP_WAIT="${POST_FIB_BGP_WAIT:-}"
START_BATCH_SIZE="${START_BATCH_SIZE:-}"
START_BATCH_DELAY_SEC="${START_BATCH_DELAY_SEC:-}"
STOP_ON_LIMIT="${STOP_ON_LIMIT:-1}"
SWAP_GUARD="${SWAP_GUARD:-1}"
MAX_SWAP_USED_MIB="${MAX_SWAP_USED_MIB:-0}"
MEM_GUARD_PER_NODE_MIB="${MEM_GUARD_PER_NODE_MIB:-9}"
MEM_GUARD_RESERVE_MIB="${MEM_GUARD_RESERVE_MIB:-2048}"
BENCH_WORK_DIR="${SAVOP_BENCH_WORK_DIR:-$ROOT/fibw_work}"
OUT_DIR="${OUT_DIR:-$RESULTS_DIR/fib_window_$(date +%Y%m%d_%H%M%S)}"
WORK_ROOT="${WORK_ROOT:-$BENCH_WORK_DIR/fib_window_work}"
abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$ROOT/$1" ;;
  esac
}
OUT_DIR="$(abs_path "$OUT_DIR")"
WORK_ROOT="$(abs_path "$WORK_ROOT")"
BENCH_ROOT="$WORK_ROOT/work"
RAW_DIR="$OUT_DIR/raw"
SUMMARY_RAW="$OUT_DIR/summary_raw.csv"
STATS="$OUT_DIR/fib_window_stats.csv"
FAILURES="$OUT_DIR/failures.csv"
STATS_APPEND="${STATS_APPEND:-0}"

mkdir -p "$OUT_DIR" "$RAW_DIR" "$BENCH_ROOT"

CONFIGS=("$@")
if [ "${#CONFIGS[@]}" -eq 0 ]; then
  mapfile -t CONFIGS < <(find "$CONFIG_DIR" -maxdepth 1 -type f \
    -name '246_*_nodes_inter_v4.json' | sort -V)
fi

cat > "$OUT_DIR/README.md" <<EOF
# FIB Sliding-Window Scale Test

Root: \`$ROOT\`
Work root: \`$WORK_ROOT\`
Started: $(date -Is)
Hold window: ${HOLD}s
Poll interval: ${POLL}s
Timeout per slice: ${WAIT}s
BGP hold after FIB: ${BGP_HOLD}s
Startup pacing: batch size ${START_BATCH_SIZE:-auto}, batch delay ${START_BATCH_DELAY_SEC:-auto}${START_BATCH_DELAY_SEC:+s}
Orchestrator: containerlab
Memory policy: no swap; preflight requires MemAvailable >= nodes * ${MEM_GUARD_PER_NODE_MIB}MiB + ${MEM_GUARD_RESERVE_MIB}MiB and SwapUsed <= ${MAX_SWAP_USED_MIB}MiB
Route-stability digest: kernel FIB only (\`ROUTE_STABLE_HASH=fib\`)
SAV-table stability: auto for network-interactive SAV apps
Topology source: real-topology sliced configs \`$CONFIG_DIR/246_*_nodes_inter_v4.json\`

Definitions:

- \`pure_stable_sec\`: elapsed time from agent/BIRD start until every node's FIB digest has stayed unchanged for the hold window.
- \`setup_plus_stable_sec\`: \`setup_sec + pure_stable_sec\`.
- \`end_to_end_sec\`: \`setup_sec + pure_stable_sec + bgp_wait_after_fib_sec\`.
EOF

if [ "$STATS_APPEND" = "1" ] && [ -f "$STATS" ]; then
  :
else
  echo "config,nodes,links,start_batch_size,start_batch_delay_sec,post_fib_bgp_wait_sec,setup_sec,start_sec,pure_stable_sec,bgp_wait_after_fib_sec,setup_plus_stable_sec,end_to_end_sec,stable_nodes,stable_complete,route_poll_count,bgp_stable_complete,established,expected_sessions,bad,agent_count,agent_rss_mib,agent_avg_mib,bird_count,bird_rss_mib,bird_avg_mib,mem_available_mib,active_sav_app,sav_table_required,sav_table_stable_hold_sec,sav_table_stable_sec,sav_table_stable_nodes,sav_table_stable_complete,sav_table_poll_count,result,raw_dir" > "$STATS"
fi
if [ "$STATS_APPEND" = "1" ] && [ -f "$FAILURES" ]; then
  :
else
  echo "config,nodes,links,reason,raw_dir" > "$FAILURES"
fi

auto_start_batch_size() {
  local nodes="$1"
  if [ "$nodes" -ge 200 ]; then
    echo 24
  else
    echo 0
  fi
}

auto_start_batch_delay_sec() {
  local nodes="$1"
  if [ "$nodes" -ge 200 ]; then
    echo 1
  else
    echo 0
  fi
}

auto_post_fib_bgp_wait_sec() {
  local nodes="$1"
  if [ "$nodes" -ge 200 ]; then
    echo 300
  elif [ "$nodes" -ge 150 ]; then
    echo 180
  elif [ "$nodes" -ge 100 ]; then
    echo 120
  else
    echo 60
  fi
}

cleanup_labs() {
  if [ -d "$BENCH_ROOT" ]; then
    find "$BENCH_ROOT" -maxdepth 3 -name destroy_clab.sh -type f -perm -111 -print0 |
      while IFS= read -r -d '' destroy; do
        (
          if cd "$(dirname "$destroy")"; then
            "./$(basename "$destroy")" >/dev/null 2>&1 || true
          fi
        )
      done
  fi
  ip netns list | awk '/^clab-savop/ {print $1}' |
    while read -r ns; do
      ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 || true
      ip netns del "$ns" >/dev/null 2>&1 || true
    done
}

mem_available_mib() {
  awk '/MemAvailable/ { printf "%.0f", $2 / 1024 }' /proc/meminfo
}

swap_used_mib() {
  awk '
    /SwapTotal/ { total = $2 }
    /SwapFree/ { free = $2 }
    END { printf "%.0f", (total - free) / 1024 }
  ' /proc/meminfo
}

memory_preflight_reason() {
  local nodes="$1"
  if [ "$SWAP_GUARD" != "1" ]; then
    echo "ok"
    return 0
  fi

  local mem_avail swap_used required
  mem_avail="$(mem_available_mib)"
  swap_used="$(swap_used_mib)"
  required="$((nodes * MEM_GUARD_PER_NODE_MIB + MEM_GUARD_RESERVE_MIB))"

  if [ "$swap_used" -gt "$MAX_SWAP_USED_MIB" ]; then
    echo "swap_already_used_${swap_used}MiB_gt_${MAX_SWAP_USED_MIB}MiB"
    return 1
  fi
  if [ "$mem_avail" -lt "$required" ]; then
    echo "mem_available_${mem_avail}MiB_lt_required_${required}MiB"
    return 1
  fi

  echo "ok"
  return 0
}

copy_raw() {
  local cfg_name="$1"
  local run_dir="$2"
  local dest="$RAW_DIR/$cfg_name"
  rm -rf "$dest"
  mkdir -p "$dest"
  for path in setup.seconds start.seconds status.txt route_stability.log bgp_wait.log sav_table_stability.log; do
    [ -f "$run_dir/$path" ] && cp -f "$run_dir/$path" "$dest/"
  done
  if [ -d "$run_dir/route_stability" ]; then
    mkdir -p "$dest/route_stability"
    find "$run_dir/route_stability" -maxdepth 1 -type f -print0 |
      while IFS= read -r -d '' file; do cp -f "$file" "$dest/route_stability/"; done
  fi
  if [ -d "$run_dir/sav_table_stability" ]; then
    mkdir -p "$dest/sav_table_stability"
    find "$run_dir/sav_table_stability" -maxdepth 1 -type f -print0 |
      while IFS= read -r -d '' file; do cp -f "$file" "$dest/sav_table_stability/"; done
  fi
  if [ -f "$run_dir/topology.clab.yml" ]; then
    cp -f "$run_dir/.clab_name" "$run_dir/topology.clab.yml" "$dest/" 2>/dev/null || true
    cp -f "$run_dir/"*"_clab.sh" "$dest/" 2>/dev/null || true
  fi
  echo "$dest"
}

append_stats_from_row() {
  local row="$1"
  local raw_dir="$2"
  local result="$3"
  local batch_size="$4"
  local batch_delay="$5"
  local post_wait="$6"
  awk -F, -v raw_dir="$raw_dir" -v result="$result" -v batch_size="$batch_size" -v batch_delay="$batch_delay" -v post_wait="$post_wait" '
    BEGIN { OFS="," }
    {
      expected = $3 * 2
      bgp_wait = ($21 == "" ? 0 : $21)
      bgp_complete = ($22 == "" ? 0 : $22)
      active_sav_app = ($23 == "" ? "none" : $23)
      sav_required = ($24 == "" ? 0 : $24)
      sav_hold = ($25 == "" ? 0 : $25)
      sav_sec = ($26 == "" ? 0 : $26)
      sav_nodes = ($27 == "" ? 0 : $27)
      sav_complete = ($28 == "" ? 1 : $28)
      sav_polls = ($29 == "" ? 0 : $29)
      setup_plus = $5 + $8
      end_to_end = $5 + $8 + bgp_wait
      printf "%s,%s,%s,%s,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.2f,%s,%s,%s,%s,%s\n",
        $1,$2,$3,batch_size,batch_delay,post_wait,$5,$6,$8,bgp_wait,setup_plus,end_to_end,
        $9,$10,$11,bgp_complete,$12,expected,$13,$14,$15,$16,$17,$18,$19,$20,
        active_sav_app,sav_required,sav_hold,sav_sec,sav_nodes,sav_complete,sav_polls,result,raw_dir
    }' <<< "$row" >> "$STATS"
}

limit_reason_from_row() {
  local row="$1"
  awk -F, '
    {
      expected = $3 * 2
      bgp_complete = ($22 == "" ? 0 : $22)
      if ($10 != 1) {
        printf "fib_not_stable_%s_of_%s", $9, $2
      } else if (bgp_complete != 1 || $12 != expected) {
        printf "bgp_established_%s_of_%d", $12, expected
      } else if ($13 != 0) {
        printf "bad_sessions_%s", $13
      } else if ($24 == 1 && $28 != 1) {
        printf "sav_table_not_stable_%s_of_%s", $27, $2
      } else {
        printf "ok"
      }
    }' <<< "$row"
}

cd "$ROOT"
cleanup_labs
rm -rf "$WORK_ROOT"
mkdir -p "$BENCH_ROOT"

for cfg in "${CONFIGS[@]}"; do
  cfg_path="$cfg"
  if [ ! -f "$cfg_path" ]; then
    cfg_path="$CONFIG_DIR/$cfg"
  fi
  cfg_name="$(basename "$cfg_path" .json)"
  run_dir="$BENCH_ROOT/clab_${cfg_name}"
  log="$RAW_DIR/${cfg_name}.run.log"
  node_count="$(jq '.devices | length' "$cfg_path")"
  links="$(jq '.links | length' "$cfg_path")"
  start_batch_size="${START_BATCH_SIZE:-$(auto_start_batch_size "$node_count")}"
  start_batch_delay="${START_BATCH_DELAY_SEC:-$(auto_start_batch_delay_sec "$node_count")}"
  post_wait="${POST_FIB_BGP_WAIT:-$(auto_post_fib_bgp_wait_sec "$node_count")}"
  mkdir -p "$RAW_DIR"

  if ! preflight_reason="$(memory_preflight_reason "$node_count")"; then
    echo "$cfg_name,$node_count,$links,$preflight_reason," >> "$FAILURES"
    echo "LIMIT: $cfg_name $preflight_reason"
    cleanup_labs
    if [ "$STOP_ON_LIMIT" = "1" ]; then
      break
    fi
    continue
  fi

  echo "=== FIB window test: $cfg_name (nodes=$node_count batch_size=${start_batch_size} batch_delay=${start_batch_delay}s post_bgp_wait=${post_wait}s) ===" | tee "$log"
  bench_wait="$WAIT"
  sav_table_stable_mode="${SAV_TABLE_STABLE:-auto}"
  sav_table_timeout="${SAV_TABLE_STABLE_TIMEOUT:-$bench_wait}"
  sav_table_poll="${SAV_TABLE_STABLE_POLL:-$POLL}"
  sav_table_hold="${SAV_TABLE_STABLE_HOLD:-$HOLD}"

  set +e
  MODE=rust \
  KEEP_LAST=1 \
  START_BATCH_SIZE="$start_batch_size" \
  START_BATCH_DELAY_SEC="$start_batch_delay" \
  WAIT="$bench_wait" \
  ROUTE_STABLE_TIMEOUT="$bench_wait" \
  ROUTE_STABLE_HOLD="$HOLD" \
  ROUTE_STABLE_POLL="$POLL" \
  ROUTE_STABLE_HASH=fib \
  ROUTE_PROBE_MODE=rust \
  ROUTE_PROBE_HASH_MODE=ordered \
  SAV_TABLE_STABLE="$sav_table_stable_mode" \
  SAV_TABLE_STABLE_APPS="${SAV_TABLE_STABLE_APPS:-rpdp,passport}" \
  SAV_TABLE_STABLE_TIMEOUT="$sav_table_timeout" \
  SAV_TABLE_STABLE_POLL="$sav_table_poll" \
  SAV_TABLE_STABLE_HOLD="$sav_table_hold" \
  POST_FIB_BGP_WAIT="$post_wait" \
  BGP_STABLE_HOLD="$BGP_HOLD" \
  SWAP_GUARD="$SWAP_GUARD" \
  MAX_SWAP_USED_MIB="$MAX_SWAP_USED_MIB" \
  MEM_GUARD_PER_NODE_MIB="$MEM_GUARD_PER_NODE_MIB" \
  MEM_GUARD_RESERVE_MIB="$MEM_GUARD_RESERVE_MIB" \
  BENCH_ROOT="$BENCH_ROOT" \
  SUMMARY="$SUMMARY_RAW" \
  APPEND=1 \
    "$LAB_DIR/bench_scale.sh" "$cfg_path" >> "$log" 2>&1
  rc=$?
  set -e

  raw_dest="$(copy_raw "$cfg_name" "$run_dir")"
  cp -f "$log" "$raw_dest/run.log"

  if [ "$rc" -ne 0 ]; then
    echo "$cfg_name,$node_count,$links,bench_exit_$rc,$raw_dest" >> "$FAILURES"
    echo "LIMIT: $cfg_name failed with exit $rc"
    cleanup_labs
    if [ "$STOP_ON_LIMIT" = "1" ]; then
      break
    fi
    continue
  fi

  row="$(tail -n 1 "$SUMMARY_RAW")"
  reason="$(limit_reason_from_row "$row")"
  append_stats_from_row "$row" "$raw_dest" "$reason" "$start_batch_size" "$start_batch_delay" "$post_wait"
  if [ "$reason" != "ok" ]; then
    echo "$cfg_name,$node_count,$links,$reason,$raw_dest" >> "$FAILURES"
    echo "LIMIT: $cfg_name $reason"
    cleanup_labs
    [ "$STOP_ON_LIMIT" = "1" ] && break
  else
    echo "OK: $row"
  fi

  cleanup_labs
  rm -rf "$run_dir"
done

rm -rf "$BENCH_ROOT"
rmdir "$WORK_ROOT" 2>/dev/null || true
echo "Finished: $(date -Is)" >> "$OUT_DIR/README.md"
echo "Results: $OUT_DIR"
