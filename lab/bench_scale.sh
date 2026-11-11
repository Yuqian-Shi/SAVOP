#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${SAVOP_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAB_DIR="${SAVOP_LAB_DIR:-$ROOT/lab}"
CONFIG_DIR="${SAVOP_CONFIG_DIR:-$LAB_DIR/base_configs}"
resolve_bin() {
  local name="$1"
  printf '%s\n' "$ROOT/target/release/$name"
}
MODE="${MODE:-rust}"
WAIT="${WAIT:-60}"
KEEP_LAST="${KEEP_LAST:-0}"
BENCH_WORK_DIR="${SAVOP_BENCH_WORK_DIR:-$ROOT/savop_run_bench}"
BENCH_ROOT="${BENCH_ROOT:-$BENCH_WORK_DIR/scale}"
LAB_GEN_BIN="${LAB_GEN_BIN:-$(resolve_bin sav_lab_gen)}"
ROUTE_STABLE_TIMEOUT="${ROUTE_STABLE_TIMEOUT:-$WAIT}"
ROUTE_STABLE_POLL="${ROUTE_STABLE_POLL:-1}"
ROUTE_STABLE_HOLD="${ROUTE_STABLE_HOLD:-5}"
ROUTE_STABLE_ALL_PATHS="${ROUTE_STABLE_ALL_PATHS:-0}"
ROUTE_STABLE_KEEP_SNAPSHOTS="${ROUTE_STABLE_KEEP_SNAPSHOTS:-0}"
ROUTE_STABLE_HASH="${ROUTE_STABLE_HASH:-combo}"
ROUTE_PROBE_BIN="${ROUTE_PROBE_BIN:-$(resolve_bin sav_route_probe)}"
ROUTE_PROBE_MODE="${ROUTE_PROBE_MODE:-rust}"
ROUTE_PROBE_HASH_MODE="${ROUTE_PROBE_HASH_MODE:-ordered}"
ROUTE_PROBE_JOBS="${ROUTE_PROBE_JOBS:-}"
SAV_TABLE_PROBE_BIN="${SAV_TABLE_PROBE_BIN:-$(resolve_bin sav_table_probe)}"
SAV_TABLE_STABLE="${SAV_TABLE_STABLE:-auto}"
SAV_TABLE_STABLE_APPS="${SAV_TABLE_STABLE_APPS:-rpdp,passport}"
SAV_TABLE_STABLE_TIMEOUT="${SAV_TABLE_STABLE_TIMEOUT:-$WAIT}"
SAV_TABLE_STABLE_POLL="${SAV_TABLE_STABLE_POLL:-$ROUTE_STABLE_POLL}"
SAV_TABLE_STABLE_HOLD="${SAV_TABLE_STABLE_HOLD:-$ROUTE_STABLE_HOLD}"
SAV_TABLE_PROBE_JOBS="${SAV_TABLE_PROBE_JOBS:-}"
SAV_TABLE_PROBE_TIMEOUT_MS="${SAV_TABLE_PROBE_TIMEOUT_MS:-5000}"
POST_FIB_BGP_WAIT="${POST_FIB_BGP_WAIT:-0}"
BGP_STABLE_HOLD="${BGP_STABLE_HOLD:-0}"
STATUS_POLL="${STATUS_POLL:-1}"
SWAP_GUARD="${SWAP_GUARD:-1}"
MAX_SWAP_USED_MIB="${MAX_SWAP_USED_MIB:-0}"
MEM_GUARD_PER_NODE_MIB="${MEM_GUARD_PER_NODE_MIB:-9}"
MEM_GUARD_RESERVE_MIB="${MEM_GUARD_RESERVE_MIB:-2048}"
NETNS_PREFIX="${NETNS_PREFIX:-}"
NETNS_PREFIX_ACTIVE=""
STATUS_SCRIPT="status_clab.sh"
DESTROY_SCRIPT="destroy_clab.sh"
BIRD_RSS_PATTERN="/savop/lab/bird"

abs_path() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s\n' "$ROOT/$1" ;;
  esac
}

BENCH_ROOT="$(abs_path "$BENCH_ROOT")"

if [ -z "$ROUTE_PROBE_JOBS" ]; then
  ROUTE_PROBE_JOBS="$(nproc 2>/dev/null || echo 8)"
  if [ "$ROUTE_PROBE_JOBS" -gt 16 ]; then
    ROUTE_PROBE_JOBS=16
  fi
fi
if [ "$ROUTE_PROBE_JOBS" -lt 1 ]; then
  ROUTE_PROBE_JOBS=1
fi
if [ -z "$SAV_TABLE_PROBE_JOBS" ]; then
  SAV_TABLE_PROBE_JOBS="$ROUTE_PROBE_JOBS"
fi
if [ "$SAV_TABLE_PROBE_JOBS" -lt 1 ]; then
  SAV_TABLE_PROBE_JOBS=1
fi

if [ "$#" -gt 0 ]; then
  CONFIGS=("$@")
else
  CONFIGS=(
    "246_5_50_50_12_nodes_inter_v4.json"
    "246_10_50_50_24_nodes_inter_v4.json"
    "246_20_50_50_49_nodes_inter_v4.json"
  )
fi

mkdir -p "$BENCH_ROOT"
SUMMARY="${SUMMARY:-$BENCH_ROOT/summary_clab_${MODE}.csv}"
SUMMARY="$(abs_path "$SUMMARY")"
mkdir -p "$(dirname "$SUMMARY")"
if [ "${APPEND:-0}" != "1" ] || [ ! -f "$SUMMARY" ]; then
  echo "config,nodes,links,mode,setup_sec,start_sec,route_stable_hold_sec,route_stable_sec,route_stable_nodes,route_stable_complete,route_poll_count,established,bad,agent_count,agent_rss_mib,agent_avg_mib,bird_count,bird_rss_mib,bird_avg_mib,mem_available_mib,bgp_wait_sec,bgp_stable_complete,active_sav_app,sav_table_required,sav_table_stable_hold_sec,sav_table_stable_sec,sav_table_stable_nodes,sav_table_stable_complete,sav_table_poll_count" > "$SUMMARY"
fi

cfg_path() {
  local cfg="$1"
  if [ -f "$cfg" ]; then
    echo "$cfg"
  elif [ -f "$ROOT/$cfg" ]; then
    echo "$ROOT/$cfg"
  else
    echo "$CONFIG_DIR/$cfg"
  fi
}

generate_lab() {
  local config="$1"
  local out_rel="$2"
  if [ "$MODE" != "rust" ]; then
    echo "MODE=$MODE is unsupported; the Rust generator currently supports MODE=rust only." >&2
    exit 2
  fi
  if [ ! -x "$LAB_GEN_BIN" ]; then
    echo "missing Rust lab generator: $LAB_GEN_BIN" >&2
    echo "build it with: cd $ROOT && cargo build --release --workspace --bin sav_lab_gen" >&2
    exit 2
  fi
  "$LAB_GEN_BIN" --config "$config" --out "$out_rel" --agent-mode rust
}

rss_stats() {
  local pids="$1"
  local pattern="$2"
  if [ -z "$pids" ]; then
    echo "0,0.0,0.0"
    return
  fi
  # shellcheck disable=SC2086
  ps -o rss=,args= -p $pids | awk -v pat="$pattern" '
    index($0, pat) { sum += $1; count += 1 }
    END {
      if (count == 0) { printf "0,0.0,0.0"; }
      else { printf "%d,%.1f,%.1f", count, sum / 1024, sum / count / 1024; }
    }'
}

agent_pattern() {
  echo "sav_agent"
}

float_ge() {
  awk -v left="$1" -v right="$2" 'BEGIN { exit !(left >= right) }'
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

memory_preflight() {
  local nodes="$1"
  local label="$2"
  if [ "$SWAP_GUARD" != "1" ]; then
    return 0
  fi

  local mem_avail swap_used required
  mem_avail="$(mem_available_mib)"
  swap_used="$(swap_used_mib)"
  required="$((nodes * MEM_GUARD_PER_NODE_MIB + MEM_GUARD_RESERVE_MIB))"

  if [ "$swap_used" -gt "$MAX_SWAP_USED_MIB" ]; then
    echo "MEMORY_LIMIT: $label swap_used_mib=$swap_used max_swap_used_mib=$MAX_SWAP_USED_MIB mem_available_mib=$mem_avail" >&2
    return 75
  fi
  if [ "$mem_avail" -lt "$required" ]; then
    echo "MEMORY_LIMIT: $label mem_available_mib=$mem_avail required_mib=$required nodes=$nodes per_node_mib=$MEM_GUARD_PER_NODE_MIB reserve_mib=$MEM_GUARD_RESERVE_MIB" >&2
    return 75
  fi
}

memory_swap_guard() {
  local label="$1"
  if [ "$SWAP_GUARD" != "1" ]; then
    return 0
  fi

  local swap_used mem_avail
  swap_used="$(swap_used_mib)"
  if [ "$swap_used" -gt "$MAX_SWAP_USED_MIB" ]; then
    mem_avail="$(mem_available_mib)"
    echo "MEMORY_LIMIT: $label swap_used_mib=$swap_used max_swap_used_mib=$MAX_SWAP_USED_MIB mem_available_mib=$mem_avail" >&2
    return 75
  fi
}

semantic_bird_routes() {
  sed -E \
    -e '/^BIRD [0-9.]+ ready\.$/d' \
    -e 's/\[[^][]+ [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\]/[PROTO_TIME]/g'
}

route_snapshot_hash() {
  local node="$1"
  local snapshot="$2"
  local detail=()
  if [ "$ROUTE_STABLE_ALL_PATHS" = "1" ]; then
    detail=(all)
  fi
  {
    echo "### bird master4"
    ip netns exec "${NETNS_PREFIX_ACTIVE}${node}" env LD_LIBRARY_PATH="$PWD/lib" \
      "$PWD/birdc" -s "$PWD/${node}/bird.ctl" show route table master4 "${detail[@]}"
    echo "### bird master6"
    ip netns exec "${NETNS_PREFIX_ACTIVE}${node}" env LD_LIBRARY_PATH="$PWD/lib" \
      "$PWD/birdc" -s "$PWD/${node}/bird.ctl" show route table master6 "${detail[@]}"
    echo "### kernel ipv4"
    ip netns exec "${NETNS_PREFIX_ACTIVE}${node}" ip route show table main
    echo "### kernel ipv6"
    ip netns exec "${NETNS_PREFIX_ACTIVE}${node}" ip -6 route show table main
  } > "$snapshot" 2>"${snapshot}.err" || {
    if [ "$ROUTE_STABLE_KEEP_SNAPSHOTS" != "1" ]; then
      rm -f "$snapshot" "${snapshot}.normalized"
    fi
    return 1
  }
  semantic_bird_routes < "$snapshot" | LC_ALL=C sort > "${snapshot}.normalized"
  local hash
  hash="$(sha256sum "${snapshot}.normalized" | awk '{print $1}')"
  if [ "$ROUTE_STABLE_KEEP_SNAPSHOTS" != "1" ]; then
    rm -f "$snapshot" "${snapshot}.normalized" "${snapshot}.err"
  fi
  echo "$hash"
}

collect_route_hashes() {
  local stable_dir="$1"
  shift
  local nodes=("$@")
  if [ "$ROUTE_STABLE_ALL_PATHS" != "1" ] && [ "$ROUTE_PROBE_MODE" = "rust" ] && [ -x "$ROUTE_PROBE_BIN" ]; then
    "$ROUTE_PROBE_BIN" \
      --netns-dir "$PWD" \
      --netns-prefix "$NETNS_PREFIX_ACTIVE" \
      --jobs "$ROUTE_PROBE_JOBS" \
      --hash-mode "$ROUTE_PROBE_HASH_MODE" \
      --nodes "${nodes[@]}" \
      2>> "$stable_dir/probe.err"
    return
  fi

  local node
  for node in "${nodes[@]}"; do
    local snapshot="$stable_dir/${node}.snapshot"
    local hash
    if hash="$(route_snapshot_hash "$node" "$snapshot")"; then
      printf "%s,%s,%s,%s,%s\n" "$node" "$hash" "$hash" "$hash" "$hash"
    fi
  done
}

select_route_hash() {
  local raw="$1"
  local rib="$2"
  local fib="$3"
  local combo="$4"
  case "$ROUTE_STABLE_HASH" in
    raw) echo "$raw" ;;
    rib) echo "$rib" ;;
    fib) echo "$fib" ;;
    combo) echo "$combo" ;;
    *)
      echo "unsupported ROUTE_STABLE_HASH=$ROUTE_STABLE_HASH; use raw|rib|fib|combo" >&2
      exit 2
      ;;
  esac
}

active_sav_app_from_config() {
  local config="$1"
  jq -r '.active_sav_app // .enabled_sav_app // "rpdp"' "$config"
}

sav_table_stability_required() {
  local active_app="$1"
  case "$SAV_TABLE_STABLE" in
    1|yes|true|on) return 0 ;;
    0|no|false|off) return 1 ;;
    auto)
      local item
      IFS=, read -ra items <<< "$SAV_TABLE_STABLE_APPS"
      for item in "${items[@]}"; do
        item="${item//[[:space:]]/}"
        if [ "$item" = "$active_app" ]; then
          return 0
        fi
      done
      return 1
      ;;
    *)
      echo "unsupported SAV_TABLE_STABLE=$SAV_TABLE_STABLE; use auto|1|0" >&2
      exit 2
      ;;
  esac
}

collect_sav_table_hashes() {
  local stable_dir="$1"
  shift
  local nodes=("$@")
  if [ ! -x "$SAV_TABLE_PROBE_BIN" ]; then
    echo "missing SAV table probe: $SAV_TABLE_PROBE_BIN" >&2
    echo "build it with: cd $ROOT && cargo build --release --workspace --bin sav_table_probe" >&2
    return 1
  fi
  "$SAV_TABLE_PROBE_BIN" \
    --netns-prefix "$NETNS_PREFIX_ACTIVE" \
    --jobs "$SAV_TABLE_PROBE_JOBS" \
    --timeout-ms "$SAV_TABLE_PROBE_TIMEOUT_MS" \
    --nodes "${nodes[@]}" \
    2>> "$stable_dir/probe.err"
}

measure_sav_table_stability() {
  local started_ns="$1"
  local active_app="$2"
  shift 2
  local nodes=("$@")
  local stable_dir="$out/sav_table_stability"
  mkdir -p "$stable_dir"
  echo "node,stable_sec,stable_for_sec,stable_since_sec,last_hash,rule_count,complete" > "$stable_dir/per_node.csv"

  declare -A last_hash=()
  declare -A stable_since=()
  declare -A stable_for=()
  declare -A stable_done=()
  declare -A stable_time=()
  declare -A rule_count=()
  local remaining="${#nodes[@]}"
  local poll_count=0
  local elapsed="0.00"

  while true; do
    poll_count="$((poll_count + 1))"
    memory_swap_guard "sav_table_stability_poll_$poll_count"
    local now_ns
    now_ns="$(date +%s%N)"
    elapsed="$(awk -v start="$started_ns" -v now="$now_ns" 'BEGIN { printf "%.2f", (now - start) / 1000000000 }')"

    declare -A poll_hash=()
    declare -A poll_rules=()
    local poll_output=""
    if poll_output="$(collect_sav_table_hashes "$stable_dir" "${nodes[@]}")"; then
      while IFS=, read -r node hash rules; do
        [ -n "$node" ] || continue
        poll_hash[$node]="$hash"
        poll_rules[$node]="$rules"
      done <<< "$poll_output"
    fi

    for node in "${nodes[@]}"; do
      if [ "${stable_done[$node]:-0}" = "1" ]; then
        continue
      fi

      local hash
      hash="${poll_hash[$node]:-}"
      if [ -n "$hash" ]; then
        rule_count[$node]="${poll_rules[$node]:-0}"
        if [ "${last_hash[$node]:-}" = "$hash" ]; then
          stable_for[$node]="$(awk -v since="${stable_since[$node]:-$elapsed}" -v now="$elapsed" 'BEGIN { printf "%.2f", now - since }')"
        else
          last_hash[$node]="$hash"
          stable_since[$node]="$elapsed"
          stable_for[$node]="0.00"
        fi

        if float_ge "${stable_for[$node]}" "$SAV_TABLE_STABLE_HOLD"; then
          stable_done[$node]="1"
          stable_time[$node]="$elapsed"
          remaining="$((remaining - 1))"
        fi
      else
        stable_since[$node]="$elapsed"
        stable_for[$node]="0.00"
      fi
    done

    echo "sav-table-stability app=$active_app poll=$poll_count elapsed=${elapsed}s remaining=$remaining hold=${SAV_TABLE_STABLE_HOLD}s"
    if [ "$remaining" -eq 0 ]; then
      break
    fi
    if float_ge "$elapsed" "$SAV_TABLE_STABLE_TIMEOUT"; then
      break
    fi
    sleep "$SAV_TABLE_STABLE_POLL"
  done

  local stable_nodes=0
  local sav_table_stable_sec="0.00"
  for node in "${nodes[@]}"; do
    local complete="${stable_done[$node]:-0}"
    if [ "$complete" = "1" ]; then
      stable_nodes="$((stable_nodes + 1))"
      if float_ge "${stable_time[$node]}" "$sav_table_stable_sec"; then
        sav_table_stable_sec="${stable_time[$node]}"
      fi
    fi
    echo "$node,${stable_time[$node]:-},${stable_for[$node]:-0.00},${stable_since[$node]:-},${last_hash[$node]:-},${rule_count[$node]:-0},$complete" >> "$stable_dir/per_node.csv"
  done

  local complete=0
  if [ "$stable_nodes" -eq "${#nodes[@]}" ]; then
    complete=1
  fi
  echo "$sav_table_stable_sec,$stable_nodes,$complete,$poll_count"
}

measure_route_stability() {
  local started_ns="$1"
  shift
  local nodes=("$@")
  local stable_dir="$out/route_stability"
  mkdir -p "$stable_dir"
  echo "node,stable_sec,stable_for_sec,stable_since_sec,last_hash,complete" > "$stable_dir/per_node.csv"

  declare -A last_hash=()
  declare -A stable_since=()
  declare -A stable_for=()
  declare -A stable_done=()
  declare -A stable_time=()
  local remaining="${#nodes[@]}"
  local poll_count=0
  local elapsed="0.00"

  while true; do
    poll_count="$((poll_count + 1))"
    memory_swap_guard "route_stability_poll_$poll_count"
    local now_ns
    now_ns="$(date +%s%N)"
    elapsed="$(awk -v start="$started_ns" -v now="$now_ns" 'BEGIN { printf "%.2f", (now - start) / 1000000000 }')"

    declare -A poll_hash=()
    local poll_output=""
    if poll_output="$(collect_route_hashes "$stable_dir" "${nodes[@]}")"; then
      while IFS=, read -r node raw_hash rib_hash fib_hash combo_hash; do
        [ -n "$node" ] || continue
        poll_hash[$node]="$(select_route_hash "$raw_hash" "$rib_hash" "$fib_hash" "$combo_hash")"
      done <<< "$poll_output"
    fi

    for node in "${nodes[@]}"; do
      if [ "${stable_done[$node]:-0}" = "1" ]; then
        continue
      fi

      local hash
      hash="${poll_hash[$node]:-}"
      if [ -n "$hash" ]; then
        if [ "${last_hash[$node]:-}" = "$hash" ]; then
          stable_for[$node]="$(awk -v since="${stable_since[$node]:-$elapsed}" -v now="$elapsed" 'BEGIN { printf "%.2f", now - since }')"
        else
          last_hash[$node]="$hash"
          stable_since[$node]="$elapsed"
          stable_for[$node]="0.00"
        fi

        if float_ge "${stable_for[$node]}" "$ROUTE_STABLE_HOLD"; then
          stable_done[$node]="1"
          stable_time[$node]="$elapsed"
          remaining="$((remaining - 1))"
        fi
      else
        stable_since[$node]="$elapsed"
        stable_for[$node]="0.00"
      fi
    done

    echo "route-stability poll=$poll_count elapsed=${elapsed}s remaining=$remaining hold=${ROUTE_STABLE_HOLD}s"
    if [ "$remaining" -eq 0 ]; then
      break
    fi
    if float_ge "$elapsed" "$ROUTE_STABLE_TIMEOUT"; then
      break
    fi
    sleep "$ROUTE_STABLE_POLL"
  done

  local stable_nodes=0
  local route_stable_sec="0.00"
  for node in "${nodes[@]}"; do
    local complete="${stable_done[$node]:-0}"
    if [ "$complete" = "1" ]; then
      stable_nodes="$((stable_nodes + 1))"
      if float_ge "${stable_time[$node]}" "$route_stable_sec"; then
        route_stable_sec="${stable_time[$node]}"
      fi
    fi
    echo "$node,${stable_time[$node]:-},${stable_for[$node]:-0.00},${stable_since[$node]:-},${last_hash[$node]:-},$complete" >> "$stable_dir/per_node.csv"
  done

  local complete=0
  if [ "$stable_nodes" -eq "${#nodes[@]}" ]; then
    complete=1
  fi
  echo "$route_stable_sec,$stable_nodes,$complete,$poll_count"
}

wait_bgp_established() {
  local expected="$1"
  local timeout="$2"
  local hold="$3"
  local status_file="$4"
  local log_file="$5"
  local start_ns
  start_ns="$(date +%s%N)"
  local bgp_stable_since=""
  local bgp_stable_for="0.00"
  local elapsed="0.00"
  local complete=0

  : > "$log_file"
  while true; do
    memory_swap_guard "bgp_wait"
    "./$STATUS_SCRIPT" > "$status_file"
    local established bad now_ns
    established="$(grep -c Established "$status_file" || true)"
    bad="$(grep -E -c 'Active|Connect|Idle|OpenSent|OpenConfirm| start ' "$status_file" || true)"
    now_ns="$(date +%s%N)"
    elapsed="$(awk -v start="$start_ns" -v now="$now_ns" 'BEGIN { printf "%.2f", (now - start) / 1000000000 }')"

    if [ "$established" -eq "$expected" ] && [ "$bad" -eq 0 ]; then
      if [ -z "$bgp_stable_since" ]; then
        bgp_stable_since="$elapsed"
        bgp_stable_for="0.00"
      else
        bgp_stable_for="$(awk -v since="$bgp_stable_since" -v now="$elapsed" 'BEGIN { printf "%.2f", now - since }')"
      fi
    else
      bgp_stable_since=""
      bgp_stable_for="0.00"
    fi

    echo "bgp-wait elapsed=${elapsed}s established=${established}/${expected} bad=${bad} stable_for=${bgp_stable_for}s hold=${hold}s" | tee -a "$log_file" >&2
    if [ "$established" -eq "$expected" ] && [ "$bad" -eq 0 ] && float_ge "$bgp_stable_for" "$hold"; then
      complete=1
      break
    fi
    if float_ge "$elapsed" "$timeout"; then
      break
    fi
    sleep "$STATUS_POLL"
  done

  echo "$elapsed,$complete"
}

for idx in "${!CONFIGS[@]}"; do
  cfg="${CONFIGS[$idx]}"
  path="$(cfg_path "$cfg")"
  name="$(basename "$cfg" .json)"
  safe_mode="${MODE//[^A-Za-z0-9_.-]/_}"
  out="$BENCH_ROOT/${safe_mode}_${name}"
  node_count="$(jq '.devices | length' "$path")"
  links="$(jq '.links | length' "$path")"
  active_sav_app="$(active_sav_app_from_config "$path")"
  mapfile -t node_ids < <(jq -r '.devices | keys | sort_by(tonumber) | .[]' "$path")

  echo "=== $cfg ($node_count nodes, $links links, mode=$MODE, orchestrator=containerlab, active_sav_app=$active_sav_app) ==="
  memory_preflight "$node_count" "$cfg preflight"
  cd "$ROOT"
  generate_lab "$path" "$out"

  run_dir="$out"
  setup_script="setup_clab.sh"
  start_script="start_clab.sh"
  STATUS_SCRIPT="status_clab.sh"
  DESTROY_SCRIPT="destroy_clab.sh"
  clab_name="$(cat "$out/.clab_name")"
  NETNS_PREFIX_ACTIVE="${NETNS_PREFIX:-clab-${clab_name}-r}"
  BIRD_RSS_PATTERN="/savop/lab/bird"

  cd "$run_dir"
  /usr/bin/time -f "%e" -o "$out/setup.seconds" "./$setup_script"
  memory_swap_guard "$cfg after_setup"
  ./prepare_libs.sh
  start_ns="$(date +%s%N)"
  /usr/bin/time -f "%e" -o "$out/start.seconds" "./$start_script"
  memory_swap_guard "$cfg after_start"

  (measure_route_stability "$start_ns" "${node_ids[@]}" | tee "$out/route_stability.log" | tail -1 > "$out/route_stability.result") &
  route_stability_pid=$!
  if sav_table_stability_required "$active_sav_app"; then
    sav_table_required=1
    (measure_sav_table_stability "$start_ns" "$active_sav_app" "${node_ids[@]}" | tee "$out/sav_table_stability.log" | tail -1 > "$out/sav_table_stability.result") &
    sav_table_stability_pid=$!
  else
    sav_table_required=0
    sav_table_stability_pid=""
    printf "0.00,%s,1,0\n" "$node_count" > "$out/sav_table_stability.result"
  fi

  wait "$route_stability_pid"
  if [ -n "$sav_table_stability_pid" ]; then
    wait "$sav_table_stability_pid"
  fi
  route_stability="$(cat "$out/route_stability.result")"
  sav_table_stability="$(cat "$out/sav_table_stability.result")"

  expected_sessions="$((links * 2))"
  if [ "$POST_FIB_BGP_WAIT" -gt 0 ]; then
    bgp_wait="$(wait_bgp_established "$expected_sessions" "$POST_FIB_BGP_WAIT" "$BGP_STABLE_HOLD" "$out/status.txt" "$out/bgp_wait.log")"
  else
    "./$STATUS_SCRIPT" > "$out/status.txt"
    bgp_wait="0.00,0"
  fi

  established="$(grep -c Established "$out/status.txt" || true)"
  bad="$(grep -E -c 'Active|Connect|Idle|OpenSent|OpenConfirm| start ' "$out/status.txt" || true)"
  pids="$(for node in "${node_ids[@]}"; do ip netns pids "${NETNS_PREFIX_ACTIVE}${node}" 2>/dev/null || true; done | xargs echo)"
  agent_stats="$(rss_stats "$pids" "$(agent_pattern)")"
  bird_stats="$(rss_stats "$pids" "$BIRD_RSS_PATTERN")"
  mem_available_mib="$(awk '/MemAvailable/ { printf "%.0f", $2 / 1024 }' /proc/meminfo)"
  setup_sec="$(cat "$out/setup.seconds")"
  start_sec="$(cat "$out/start.seconds")"

  echo "$cfg,$node_count,$links,$MODE,$setup_sec,$start_sec,$ROUTE_STABLE_HOLD,$route_stability,$established,$bad,$agent_stats,$bird_stats,$mem_available_mib,$bgp_wait,$active_sav_app,$sav_table_required,$SAV_TABLE_STABLE_HOLD,$sav_table_stability" >> "$SUMMARY"
  tail -1 "$SUMMARY"

  is_last=0
  if [ "$idx" -eq "$((${#CONFIGS[@]} - 1))" ]; then
    is_last=1
  fi
  if [ "$KEEP_LAST" != "1" ] || [ "$is_last" != "1" ]; then
    "./$DESTROY_SCRIPT" || true
  fi
done

echo "summary: $SUMMARY"
