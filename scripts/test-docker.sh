#!/usr/bin/env bash
set -Eeuo pipefail

report_failure() {
  local exit_code=$?
  local line="${BASH_LINENO[0]:-0}"
  local command="${BASH_COMMAND//$'\n'/ }"
  trap - ERR
  printf 'Docker smoke test failed at line %s (exit %s): %s\n' "$line" "$exit_code" "$command" >&2
  printf '::error file=scripts/test-docker.sh,line=%s::exit %s: %s\n' "$line" "$exit_code" "$command"
  exit "$exit_code"
}
trap report_failure ERR

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
command -v docker >/dev/null 2>&1 || { echo "Docker CLI is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker Engine is not reachable" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/aegislure-docker.XXXXXX")"
PROJECT_NAME="aegislure-smoke-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
export COMPOSE_PROJECT_NAME="$PROJECT_NAME"
remove_test_runtime_data() {
  [[ -n "${HP_IMAGE:-}" && -d "$TEST_ROOT/runtime" ]] || return 0
  # The fixture runs the app as UID 10001. On Linux CI that UID may own
  # mode-0700 data directories, so use a disposable root helper container to
  # remove only this temporary bind-mounted test data.
  docker run --rm --user 0:0 --network none --read-only \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    -v "$TEST_ROOT/runtime:/runtime" --entrypoint /bin/sh "$HP_IMAGE" \
    -ec 'rm -rf /runtime/data'
}
cleanup() {
  docker compose -p "$PROJECT_NAME" -f "$ROOT_DIR/docker-compose.yml" -f "$ROOT_DIR/docker-compose.pg.yml" --profile bundled-pg down -v --remove-orphans >/dev/null 2>&1 || true
  remove_test_runtime_data >/dev/null 2>&1 || true
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/runtime/secrets"
# Keep the test bind mount writable by the fixed non-root container UID even
# when CI itself runs as an unrelated non-root user. The temporary source
# password remains mode 0600; the named volume copies are checked at 0400.
chmod 777 "$TEST_ROOT/runtime"
chmod 755 "$TEST_ROOT/runtime/secrets"
printf '%s\n' docker-smoke-postgres-secret > "$TEST_ROOT/runtime/secrets/postgres_password"
chmod 600 "$TEST_ROOT/runtime/secrets/postgres_password"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$TEST_ROOT/runtime/secrets/admin.key" \
  -out "$TEST_ROOT/runtime/secrets/admin.crt" >/dev/null 2>&1
chmod 644 "$TEST_ROOT/runtime/secrets/admin.key"
chmod 644 "$TEST_ROOT/runtime/secrets/admin.crt"
# The fixture intentionally uses the image UID to model a root-run install.
# install.sh normally chowns this key to that UID while retaining mode 0600;
# this standalone fixture does not perform host ownership changes, so make
# only the temporary test key readable to the container.

export HP_IMAGE="aegislure:docker-smoke"
export HP_RUNTIME_DIR="$TEST_ROOT/runtime"
export HP_POSTGRES_PASSWORD_FILE="$TEST_ROOT/runtime/secrets/postgres_password"
export HP_PUBLIC_PORT_BIND_IP=0.0.0.0
export HP_ADMIN_PORT_BIND_IP=0.0.0.0
export HP_ADMIN_PORT=$((20000 + $(od -An -N2 -tu2 /dev/urandom) % 40999))
export HP_PROFILES=new-api,vllm,ollama,sglang,localai
export HP_CONTAINER_UID=10001
export HP_CONTAINER_GID=10001
export NEW_API_PORT=3000 OLLAMA_PORT=11434 VLLM_PORT=8000 SGLANG_PORT=30000 LOCALAI_PORT=8080
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

wait_for_health() {
  local service="$1"
  shift
  local mode_compose=("$@")
  for _ in $(seq 1 90); do
    local id health state
    id="$("${mode_compose[@]}" ps -q "$service" 2>/dev/null | head -n 1)"
    if [[ -n "$id" ]]; then
      state="$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || true)"
      health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null || true)"
      [[ "$health" == healthy ]] && return 0
      [[ "$state" == exited || "$state" == dead ]] && return 1
    fi
    sleep 2
  done
  return 1
}

assert_edge_network_egress() {
  local network masquerade
  network="${PROJECT_NAME}_edge_net"
  masquerade="$(docker network inspect "$network" --format '{{index .Options "com.docker.network.bridge.enable_ip_masquerade"}}' 2>/dev/null || true)"
  [[ "$masquerade" == "true" ]] || {
    echo "edge_net must enable outbound egress for IPinfo API queries: $masquerade" >&2
    return 1
  }
}

assert_public_port() {
  local id="$1"
  local port="$2"
  local mapping
  mapping="$(docker port "$id" "$port/tcp" 2>/dev/null || true)"
  grep -Eq '(^|[[:space:]])0\.0\.0\.0:' <<<"$mapping" || {
    echo "port ${port} is not published on 0.0.0.0: ${mapping}" >&2
    return 1
  }
}

run_mode() {
  local mode="$1"
  local mode_compose=("${compose[@]}")
  export HP_DB_DRIVER="$mode"
  if [[ "$mode" == postgres ]]; then
    # Exercise the Compose default; install.sh writes the same path explicitly
    # into .env for an installed project.
    unset HP_DB_PASSWORD_FILE
    mode_compose+=( -f "$ROOT_DIR/docker-compose.pg.yml" )
    "${mode_compose[@]}" --profile bundled-pg up -d postgres
    wait_for_health postgres "${mode_compose[@]}" || {
      "${mode_compose[@]}" --profile bundled-pg logs --no-color --tail=100 postgres-secret-init postgres postgres-init >&2 || true
      return 1
    }
  else
    export HP_DB_PASSWORD_FILE=
  fi
  "${mode_compose[@]}" run --rm --no-deps --entrypoint /usr/local/bin/hpctl aegislure \
    init --config /var/lib/aegislure/config.json --data-dir /var/lib/aegislure/data
  if [[ "$mode" == postgres ]]; then
    "${mode_compose[@]}" --profile bundled-pg up -d aegislure
  else
    "${mode_compose[@]}" up -d aegislure
  fi
  wait_for_health aegislure "${mode_compose[@]}" || {
    "${mode_compose[@]}" --profile bundled-pg logs --no-color --tail=100 aegislure >&2 || true
    return 1
  }
  assert_edge_network_egress
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
  status_output="$("$ROOT_DIR/hpctl" status --config /var/lib/aegislure/config.json)"
  grep -q "\"database_driver\": \"${mode}\"" <<<"$status_output"
  health_output="$("$ROOT_DIR/hpctl" health --config /var/lib/aegislure/config.json)"
  grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true' <<<"$health_output"
  grep -Eq '"database_connected"[[:space:]]*:[[:space:]]*true' <<<"$health_output"
  local app_id
  app_id="$("${mode_compose[@]}" ps -q aegislure | head -n 1)"
  for public_port in 3000 8000 8080 11434 30000; do
    assert_public_port "$app_id" "$public_port"
  done
  if [[ "$mode" == postgres ]]; then
    local postgres_id
    local postgres_secret_owner postgres_user app_secret_owner app_user
    postgres_id="$("${mode_compose[@]}" ps -q postgres | head -n 1)"
    "${mode_compose[@]}" exec -T postgres sh -ec 'test -r /run/aegislure-db-secrets/postgres_password; test "$(stat -c %a /run/aegislure-db-secrets/postgres_password)" = 400'
    "${mode_compose[@]}" exec -T aegislure sh -ec 'test -r /run/aegislure-db-secrets/application_password; test "$(stat -c %a /run/aegislure-db-secrets/application_password)" = 400'
    postgres_secret_owner="$("${mode_compose[@]}" exec -T postgres sh -ec 'stat -c %u:%g /run/aegislure-db-secrets/postgres_password' | tr -d '\r\n')"
    postgres_user="$("${mode_compose[@]}" exec -T postgres sh -ec 'id -u postgres; id -g postgres' | paste -sd: - | tr -d '\r\n')"
    [[ "$postgres_secret_owner" == "$postgres_user" ]] || {
      echo "PostgreSQL secret owner ${postgres_secret_owner} does not match image postgres user ${postgres_user}" >&2
      return 1
    }
    app_secret_owner="$("${mode_compose[@]}" exec -T aegislure sh -ec 'stat -c %u:%g /run/aegislure-db-secrets/application_password' | tr -d '\r\n')"
    app_user="$("${mode_compose[@]}" exec -T aegislure sh -ec 'id -u; id -g' | paste -sd: - | tr -d '\r\n')"
    [[ "$app_secret_owner" == "$app_user" ]] || {
      echo "application secret owner ${app_secret_owner} does not match app user ${app_user}" >&2
      return 1
    }
    [[ -z "$(docker port "$postgres_id" 5432/tcp 2>/dev/null || true)" ]] || {
      echo "PostgreSQL unexpectedly has a published host port" >&2
      return 1
    }
    [[ -n "$postgres_id" ]] || return 1
  fi
  assert_public_port "$app_id" "$HP_ADMIN_PORT"
  curl -sf "http://127.0.0.1:${NEW_API_PORT}/v1/models" >/dev/null
  curl -sf "http://127.0.0.1:${VLLM_PORT}/v1/models" >/dev/null
  curl -sf "http://127.0.0.1:${OLLAMA_PORT}/api/tags" >/dev/null
  curl -sf "http://127.0.0.1:${SGLANG_PORT}/server_info" >/dev/null
  curl -sf "http://127.0.0.1:${LOCALAI_PORT}/models/available" >/dev/null
  "${mode_compose[@]}" stop aegislure >/dev/null
  stopped_status="$("$ROOT_DIR/hpctl" status --config /var/lib/aegislure/config.json)"
  grep -q "\"database_driver\": \"${mode}\"" <<<"$stopped_status"
  if "$ROOT_DIR/hpctl" health --config /var/lib/aegislure/config.json >"$TEST_ROOT/stopped-health.log" 2>&1; then
    echo "hpctl health unexpectedly succeeded without a running AegisLure service" >&2
    return 1
  fi
  grep -q 'AegisLure service is not running' "$TEST_ROOT/stopped-health.log"
  if [[ "$mode" == postgres ]]; then
    "${mode_compose[@]}" --profile bundled-pg stop postgres >/dev/null
  fi
  rm -f "$TEST_ROOT/runtime/config.json"
  remove_test_runtime_data
}

test_installer_failure_semantics() {
  local failure_root failure_project rc log
  failure_root="$(mktemp -d "${TMPDIR:-/tmp}/aegislure-installer-failure.XXXXXX")"
  failure_project="aegislure-installer-failure-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
  cp "$ROOT_DIR/docker-compose.yml" "$ROOT_DIR/docker-compose.pg.yml" \
    "$ROOT_DIR/.env.example" "$ROOT_DIR/install.sh" "$ROOT_DIR/hpctl" "$failure_root/"
  mkdir -p "$failure_root/runtime/secrets"
  printf '%s\n' installer-failure-secret > "$failure_root/runtime/secrets/postgres_password"
  chmod 600 "$failure_root/runtime/secrets/postgres_password"
  export COMPOSE_PROJECT_NAME="$failure_project"
  export HP_IMAGE=aegislure:docker-smoke
  # The already-built AegisLure image intentionally lacks a `postgres` user.
  # It is a local, deterministic stand-in for a PostgreSQL image that cannot
  # initialize; the installer must stop at the PG startup stage.
  export HP_POSTGRES_IMAGE=aegislure:docker-smoke
  export HP_RUNTIME_DIR="$failure_root/runtime"
  export HP_POSTGRES_PASSWORD_FILE="$failure_root/runtime/secrets/postgres_password"
  export HP_CONTAINER_UID=10001 HP_CONTAINER_GID=10001
  export HP_PUBLIC_PORT_BIND_IP=0.0.0.0 HP_ADMIN_PORT_BIND_IP=0.0.0.0 HP_ADMIN_PORT=40565
  export HP_PROFILES=new-api,vllm,ollama,sglang,localai
  export HP_DATABASE_URL= HP_DATABASE_URL_FILE= HP_DB_DRIVER=postgres HP_DB_PASSWORD_FILE=
  log="$failure_root/install.log"
  set +e
  (cd "$failure_root" && ./install.sh --mode postgres --version v0.1.0 --image aegislure:docker-smoke --no-build >"$log" 2>&1)
  rc=$?
  set -e
  docker compose -p "$failure_project" -f "$failure_root/docker-compose.yml" \
    -f "$failure_root/docker-compose.pg.yml" --profile bundled-pg down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$rc" -eq 0 ]]; then
    echo "installer failure fixture unexpectedly succeeded" >&2
    sed -n '1,160p' "$log" >&2
    rm -rf "$failure_root"
    return 1
  fi
  if grep -q 'AegisLure is running' "$log"; then
    echo "installer printed success after a critical service failure" >&2
    sed -n '1,160p' "$log" >&2
    rm -rf "$failure_root"
    return 1
  fi
  grep -q 'AegisLure installation failed during bundled PostgreSQL startup.' "$log" || {
    echo "installer failure stage was not reported" >&2
    sed -n '1,160p' "$log" >&2
    rm -rf "$failure_root"
    return 1
  }
  rm -rf "$failure_root"
  export COMPOSE_PROJECT_NAME="$PROJECT_NAME"
  unset HP_POSTGRES_IMAGE
  echo "Installer failure semantics passed"
}

echo "Testing SQLite mode"
run_mode sqlite
echo "Testing bundled PostgreSQL mode"
run_mode postgres
test_installer_failure_semantics
echo "Docker smoke test passed"
