#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker Engine is not reachable" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aegislure-docker.XXXXXX")"
PROJECT_NAME="aegislure-smoke-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.pg.yml" --profile bundled-pg down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/runtime/secrets"
chmod 700 "$TEST_ROOT/runtime" "$TEST_ROOT/runtime/secrets"
printf '%s\n' docker-smoke-postgres-secret > "$TEST_ROOT/runtime/secrets/postgres_password"
chmod 600 "$TEST_ROOT/runtime/secrets/postgres_password"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$TEST_ROOT/runtime/secrets/admin.key" \
  -out "$TEST_ROOT/runtime/secrets/admin.crt" >/dev/null 2>&1
chmod 600 "$TEST_ROOT/runtime/secrets/admin.key"
chmod 644 "$TEST_ROOT/runtime/secrets/admin.crt"

export HP_IMAGE="aegislure:docker-smoke"
export HP_RUNTIME_DIR="$TEST_ROOT/runtime"
export HP_POSTGRES_PASSWORD_FILE="$TEST_ROOT/runtime/secrets/postgres_password"
export HP_PORT_BIND_IP=127.0.0.1
PORT_BASE=$((40000 + $(od -An -N2 -tu2 /dev/urandom) % 10000))
export HP_ADMIN_PORT=$((PORT_BASE + 900))
export HP_PROFILES=ollama,vllm
export NEW_API_PORT=$((PORT_BASE + 1000)) NEW_API_PORT_1=$((PORT_BASE + 1001)) NEW_API_PORT_2=$((PORT_BASE + 1002)) NEW_API_PORT_3=$((PORT_BASE + 1003)) NEW_API_PORT_4=$((PORT_BASE + 1004)) NEW_API_PORT_5=$((PORT_BASE + 1005)) NEW_API_PORT_6=$((PORT_BASE + 1006)) NEW_API_PORT_7=$((PORT_BASE + 1007))
export OLLAMA_PORT=$((PORT_BASE + 1100)) OLLAMA_PORT_1=$((PORT_BASE + 1101)) OLLAMA_PORT_2=$((PORT_BASE + 1102)) OLLAMA_PORT_3=$((PORT_BASE + 1103)) OLLAMA_PORT_4=$((PORT_BASE + 1104)) OLLAMA_PORT_5=$((PORT_BASE + 1105)) OLLAMA_PORT_6=$((PORT_BASE + 1106)) OLLAMA_PORT_7=$((PORT_BASE + 1107))
export VLLM_PORT=$((PORT_BASE + 1200)) VLLM_PORT_1=$((PORT_BASE + 1201)) VLLM_PORT_2=$((PORT_BASE + 1202)) VLLM_PORT_3=$((PORT_BASE + 1203)) VLLM_PORT_4=$((PORT_BASE + 1204)) VLLM_PORT_5=$((PORT_BASE + 1205)) VLLM_PORT_6=$((PORT_BASE + 1206)) VLLM_PORT_7=$((PORT_BASE + 1207))
export SGLANG_PORT=$((PORT_BASE + 1300)) SGLANG_PORT_1=$((PORT_BASE + 1301)) SGLANG_PORT_2=$((PORT_BASE + 1302)) SGLANG_PORT_3=$((PORT_BASE + 1303)) SGLANG_PORT_4=$((PORT_BASE + 1304)) SGLANG_PORT_5=$((PORT_BASE + 1305)) SGLANG_PORT_6=$((PORT_BASE + 1306)) SGLANG_PORT_7=$((PORT_BASE + 1307))
export LOCALAI_PORT=$((PORT_BASE + 1400)) LOCALAI_PORT_1=$((PORT_BASE + 1401)) LOCALAI_PORT_2=$((PORT_BASE + 1402)) LOCALAI_PORT_3=$((PORT_BASE + 1403)) LOCALAI_PORT_4=$((PORT_BASE + 1404)) LOCALAI_PORT_5=$((PORT_BASE + 1405)) LOCALAI_PORT_6=$((PORT_BASE + 1406)) LOCALAI_PORT_7=$((PORT_BASE + 1407))
export HP_DATABASE_URL=
export HP_DATABASE_URL_FILE=
export HP_DB_HOST=
export HP_DB_PORT=
export HP_DB_NAME=
export HP_DB_USER=
export HP_DB_PASSWORD_FILE=
export HP_DB_SSLMODE=

compose=(docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml")
echo "Building common image"
"${compose[@]}" build

run_mode() {
  local mode="$1"
  local mode_compose=("${compose[@]}")
  export HP_DB_DRIVER="$mode"
  if [[ "$mode" == postgres ]]; then
    mode_compose+=( -f "$ROOT_DIR/docker-compose.pg.yml" )
    "${mode_compose[@]}" --profile bundled-pg up -d postgres
  fi
  "${mode_compose[@]}" run --rm --no-deps --entrypoint /usr/local/bin/hpctl aegislure \
    init --config /var/lib/aegislure/config.json --data-dir /var/lib/aegislure/data
  if [[ "$mode" == postgres ]]; then
    "${mode_compose[@]}" --profile bundled-pg up -d aegislure
  else
    "${mode_compose[@]}" up -d aegislure
  fi
  for _ in $(seq 1 30); do
    if [[ "$("${mode_compose[@]}" ps --status running --services | grep -c '^aegislure$' || true)" -eq 1 ]]; then
      break
    fi
    sleep 2
  done
  local admin_path
  admin_path="$(awk -F'"' '/"admin_path"/ { print $4; exit }' "$TEST_ROOT/runtime/config.json")"
  [[ -n "$admin_path" ]] || { echo "admin path was not initialized" >&2; return 1; }
  local health_url="https://127.0.0.1:${HP_ADMIN_PORT}${admin_path}admin/api/v1/health"
  for _ in $(seq 1 60); do
    if curl -ksf -H 'Host: 127.0.0.1' "$health_url" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  curl -ksf -H 'Host: 127.0.0.1' "$health_url" >/dev/null
  "${mode_compose[@]}" run --rm --no-deps --entrypoint /usr/local/bin/hpctl aegislure \
    status --config /var/lib/aegislure/config.json | grep -q "\"database_driver\": \"${mode}\""
  curl -sf "http://127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null
  "${mode_compose[@]}" stop aegislure >/dev/null
  if [[ "$mode" == postgres ]]; then
    "${mode_compose[@]}" --profile bundled-pg stop postgres >/dev/null
  fi
  rm -f "$TEST_ROOT/runtime/config.json"
  rm -rf "$TEST_ROOT/runtime/data"
  mkdir -p "$TEST_ROOT/runtime/data"
}

echo "Testing SQLite mode"
run_mode sqlite
echo "Testing bundled PostgreSQL mode"
run_mode postgres
echo "Docker smoke test passed"
