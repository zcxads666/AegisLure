#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PID_FILE="$ROOT_DIR/runtime/native.pid"
CONFIG_PATH="${HP_CONFIG:-$ROOT_DIR/runtime/config.json}"

is_matching_process() {
  local candidate="$1" command_line
  [[ "$candidate" =~ ^[0-9]+$ && -r "/proc/$candidate/cmdline" ]] || return 1
  command_line="$(tr '\0' ' ' < "/proc/$candidate/cmdline")"
  [[ "$command_line" == "$ROOT_DIR/bin/aegislure -config $CONFIG_PATH "* ]]
}

pid=""
if [[ -f "$PID_FILE" ]]; then
  candidate="$(<"$PID_FILE")"
  if is_matching_process "$candidate"; then
    pid="$candidate"
  fi
fi

if [[ -z "$pid" ]]; then
  for proc_dir in /proc/[0-9]*; do
    candidate="${proc_dir##*/}"
    if is_matching_process "$candidate"; then
      pid="$candidate"
      break
    fi
  done
fi

if [[ -n "$pid" ]]; then
  kill "$pid"
  for _ in {1..20}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
fi
rm -f "$PID_FILE"
echo "AegisLure native process stopped"
