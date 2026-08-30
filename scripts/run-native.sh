#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source scripts/env.sh

CONFIG_PATH="${HP_CONFIG:-$ROOT_DIR/runtime/config.json}"
DATA_DIR="${HP_DATA_DIR:-$ROOT_DIR/runtime/data}"
PID_FILE="$ROOT_DIR/runtime/native.pid"
LOG_FILE="$ROOT_DIR/runtime/native.log"

is_matching_process() {
  local candidate="$1" command_line
  [[ "$candidate" =~ ^[0-9]+$ && -r "/proc/$candidate/cmdline" ]] || return 1
  command_line="$(tr '\0' ' ' < "/proc/$candidate/cmdline")"
  [[ "$command_line" == "$ROOT_DIR/bin/aegislure -config $CONFIG_PATH "* ]]
}

if [[ ! -x "$ROOT_DIR/bin/aegislure" ]]; then
  mkdir -p "$ROOT_DIR/bin"
  go build -trimpath -ldflags='-s -w' -o "$ROOT_DIR/bin/aegislure" ./cmd/aegislure
fi
if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Missing config: $CONFIG_PATH. Run ./bin/hpctl init first." >&2
  exit 1
fi
for proc_dir in /proc/[0-9]*; do
  candidate="${proc_dir##*/}"
  if [[ "$candidate" != "$$" ]] && is_matching_process "$candidate"; then
    echo "AegisLure native process is already running (pid=$candidate)" >&2
    exit 1
  fi
done

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(<"$PID_FILE")"
  if is_matching_process "$old_pid"; then
    echo "AegisLure native process is already running (pid=$old_pid)" >&2
    exit 1
  fi
  rm -f "$PID_FILE"
fi

mkdir -p "$DATA_DIR"
export HP_DATA_DIR="$DATA_DIR"
export HP_PUBLIC_BIND="${HP_PUBLIC_BIND:-0.0.0.0}"
export HP_ADMIN_BIND="${HP_ADMIN_BIND:-0.0.0.0}"
export HP_TLS_CERT="${HP_TLS_CERT:-$ROOT_DIR/runtime/secrets/admin.crt}"
export HP_TLS_KEY="${HP_TLS_KEY:-$ROOT_DIR/runtime/secrets/admin.key}"
export HP_PUBLIC_COOKIE_SECURE="${HP_PUBLIC_COOKIE_SECURE:-0}"
if [[ -z "${HP_COOKIE_SECURE:-}" ]]; then
  if [[ -f "$HP_TLS_CERT" && -f "$HP_TLS_KEY" ]]; then
    export HP_COOKIE_SECURE=1
  else
    export HP_COOKIE_SECURE=0
  fi
else
  export HP_COOKIE_SECURE
fi

nohup "$ROOT_DIR/bin/aegislure" -config "$CONFIG_PATH" >"$LOG_FILE" 2>&1 &
pid=$!
echo "$pid" >"$PID_FILE"
sleep 1
if ! kill -0 "$pid" 2>/dev/null; then
  echo "AegisLure failed to start; see $LOG_FILE" >&2
  exit 1
fi
echo "AegisLure native process started (pid=$pid)"
echo "log=$LOG_FILE"
