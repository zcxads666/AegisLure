#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if [[ -f scripts/env.sh ]]; then
  # shellcheck source=/dev/null
  source scripts/env.sh
fi

DEFAULT_VERSION="v0.1.0"
MODE="${HP_DB_DRIVER:-}"
VERSION="${HP_VERSION:-}"
IMAGE="${HP_IMAGE:-}"
if [[ -f .env ]]; then
  [[ -n "$MODE" ]] || MODE="$(awk -F= '/^HP_DB_DRIVER=/ { print substr($0, index($0, "=")+1); exit }' .env)"
  [[ -n "$VERSION" ]] || VERSION="$(awk -F= '/^HP_VERSION=/ { print substr($0, index($0, "=")+1); exit }' .env)"
  [[ -n "$IMAGE" ]] || IMAGE="$(awk -F= '/^HP_IMAGE=/ { print substr($0, index($0, "=")+1); exit }' .env)"
fi
MODE="${MODE:-sqlite}"
VERSION="${VERSION:-$DEFAULT_VERSION}"
NO_BUILD=0
PULL=0

usage() {
  cat <<'EOF'
Usage: ./install.sh [options]

  --mode sqlite|postgres   backend (default: sqlite)
  --version vX.Y.Z         release tag used for the default image
  --image IMAGE            explicit image reference (remote installer uses a digest)
  --no-build               use the configured image without building locally
  --pull                   pull the configured image before starting
  --help                   show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      [[ $# -ge 2 ]] || { echo "--mode requires a value" >&2; exit 2; }
      MODE="$2"
      shift 2
      ;;
    --version)
      [[ $# -ge 2 ]] || { echo "--version requires a value" >&2; exit 2; }
      VERSION="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || { echo "--image requires a value" >&2; exit 2; }
      IMAGE="$2"
      shift 2
      ;;
    --no-build)
      NO_BUILD=1
      shift
      ;;
    --pull)
      PULL=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

MODE="$(printf '%s' "$MODE" | tr '[:upper:]' '[:lower:]')"
case "$MODE" in
  sqlite) MODE=sqlite ;;
  postgres|postgresql) MODE=postgres ;;
  *) echo "--mode must be sqlite or postgres" >&2; exit 2 ;;
esac
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--version must look like v0.1.0" >&2; exit 2; }
if [[ -z "$IMAGE" ]]; then
  IMAGE="ghcr.io/zcxads666/aegislure:${VERSION}"
fi
[[ "$IMAGE" != *[[:space:]]* ]] || { echo "image reference contains whitespace" >&2; exit 2; }

command -v docker >/dev/null 2>&1 || { echo "Docker Engine is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker CLI is installed, but Docker Engine is not reachable; install/start the daemon or set DOCKER_HOST" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

mkdir -p runtime/data runtime/data/geoip runtime/secrets
chmod 700 runtime runtime/data runtime/data/geoip runtime/secrets
touch .env
chmod 600 .env

CONTAINER_UID_DEFAULT="$(id -u)"
CONTAINER_GID_DEFAULT="$(id -g)"
if [[ "$CONTAINER_UID_DEFAULT" == "0" ]]; then
  # Never make the application container root just because the installer was
  # invoked by root. The runtime bind mount is chowned below after secrets are
  # generated.
  CONTAINER_UID_DEFAULT=10001
  CONTAINER_GID_DEFAULT=10001
fi

set_env_value() {
  local key="$1"
  local value="$2"
  local temporary
  temporary="$(mktemp .env.XXXXXX)"
  awk -v key="$key" -v value="$value" '
    BEGIN { replaced = 0 }
    $0 ~ "^" key "=" {
      if (!replaced) { print key "=" value; replaced = 1 }
      next
    }
    { print }
    END { if (!replaced) print key "=" value }
  ' .env >"$temporary"
  chmod 600 "$temporary"
  mv "$temporary" .env
}

dotenv_value() {
  local key="$1"
  awk -v key="$key" 'index($0, key "=") == 1 { sub("^" key "=", ""); print; exit }' .env
}

set_env_value HP_IMAGE "$IMAGE"
set_env_value HP_VERSION "$VERSION"
set_env_value HP_DB_DRIVER "$MODE"
if [[ -z "${HP_ADMIN_PORT:-}" ]]; then
  if ! grep -q '^HP_ADMIN_PORT=' .env; then
    set_env_value HP_ADMIN_PORT "$((20000 + $(od -An -N2 -tu2 /dev/urandom) % 40999))"
  fi
else
  set_env_value HP_ADMIN_PORT "$HP_ADMIN_PORT"
fi
if [[ -n "${HP_PROFILES:-}" ]]; then set_env_value HP_PROFILES "$HP_PROFILES"; elif ! grep -q '^HP_PROFILES=' .env; then set_env_value HP_PROFILES 'new-api,vllm,ollama,sglang,localai'; fi
if ! grep -q '^HP_CONTAINER_UID=' .env; then set_env_value HP_CONTAINER_UID "$CONTAINER_UID_DEFAULT"; fi
if ! grep -q '^HP_CONTAINER_GID=' .env; then set_env_value HP_CONTAINER_GID "$CONTAINER_GID_DEFAULT"; fi
if ! grep -q '^HP_PUBLIC_PORT_BIND_IP=' .env; then set_env_value HP_PUBLIC_PORT_BIND_IP "${HP_PUBLIC_PORT_BIND_IP:-0.0.0.0}"; fi
if ! grep -q '^HP_ADMIN_PORT_BIND_IP=' .env; then set_env_value HP_ADMIN_PORT_BIND_IP "${HP_ADMIN_PORT_BIND_IP:-0.0.0.0}"; fi

CONTAINER_UID="$(dotenv_value HP_CONTAINER_UID)"
CONTAINER_GID="$(dotenv_value HP_CONTAINER_GID)"
if ! [[ "$CONTAINER_UID" =~ ^[1-9][0-9]*$ ]] || (( CONTAINER_UID > 65535 )); then
  echo "HP_CONTAINER_UID must be a non-root numeric UID" >&2
  exit 2
fi
if ! [[ "$CONTAINER_GID" =~ ^[1-9][0-9]*$ ]] || (( CONTAINER_GID > 65535 )); then
  echo "HP_CONTAINER_GID must be a non-root numeric GID" >&2
  exit 2
fi

POSTGRES_PASSWORD_FILE="${HP_POSTGRES_PASSWORD_FILE:-$(dotenv_value HP_POSTGRES_PASSWORD_FILE)}"
if [[ -z "$POSTGRES_PASSWORD_FILE" ]]; then
  POSTGRES_PASSWORD_FILE="./runtime/secrets/postgres_password"
fi
if [[ "$MODE" == postgres ]]; then
  set_env_value HP_POSTGRES_PASSWORD_FILE "$POSTGRES_PASSWORD_FILE"
  if [[ ! -f "$POSTGRES_PASSWORD_FILE" ]]; then
    mkdir -p "$(dirname -- "$POSTGRES_PASSWORD_FILE")"
    umask 077
    openssl rand -hex 32 >"$POSTGRES_PASSWORD_FILE"
  fi
  chmod 600 "$POSTGRES_PASSWORD_FILE"
fi

if [[ ! -f runtime/secrets/admin.crt || ! -f runtime/secrets/admin.key ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -subj "/CN=aegislure.local" \
    -addext "subjectAltName=DNS:aegislure.local" \
    -keyout runtime/secrets/admin.key -out runtime/secrets/admin.crt >/dev/null 2>&1
  chmod 600 runtime/secrets/admin.key
  chmod 644 runtime/secrets/admin.crt
fi
if [[ "$(id -u)" == "0" ]]; then
  # Only application-owned paths are changed here. In particular, the
  # PostgreSQL source secret may be consumed by a different container user;
  # bundled PostgreSQL gets per-consumer copies in a named secret volume.
  chown "$CONTAINER_UID:$CONTAINER_GID" runtime runtime/secrets
  chown -R "$CONTAINER_UID:$CONTAINER_GID" runtime/data
  if [[ -f runtime/config.json ]]; then
    chown "$CONTAINER_UID:$CONTAINER_GID" runtime/config.json
  fi
  for admin_secret in runtime/secrets/admin.crt runtime/secrets/admin.key; do
    if [[ -f "$admin_secret" ]]; then
      chown "$CONTAINER_UID:$CONTAINER_GID" "$admin_secret"
    fi
  done
fi

CONFIGURED_DATABASE_URL="${HP_DATABASE_URL:-$(dotenv_value HP_DATABASE_URL)}"
CONFIGURED_DATABASE_URL_FILE="${HP_DATABASE_URL_FILE:-$(dotenv_value HP_DATABASE_URL_FILE)}"
if [[ "$MODE" == postgres ]]; then
  configured_password_file="${HP_DB_PASSWORD_FILE:-$(dotenv_value HP_DB_PASSWORD_FILE)}"
  if [[ -z "$CONFIGURED_DATABASE_URL" && -z "$CONFIGURED_DATABASE_URL_FILE" ]]; then
    # The bundled secret initializer creates this file with the application
    # UID/GID. Do not make the app read the host source file directly.
    set_env_value HP_DB_PASSWORD_FILE /run/aegislure-db-secrets/application_password
    export HP_DB_PASSWORD_FILE=/run/aegislure-db-secrets/application_password
  elif [[ -z "$configured_password_file" || "$configured_password_file" == "/run/aegislure-db-secrets/application_password" ]]; then
    # External PostgreSQL uses the Compose secret mount unless the operator
    # explicitly selected another in-container password file.
    set_env_value HP_DB_PASSWORD_FILE /run/secrets/aegislure_db_password
    export HP_DB_PASSWORD_FILE=/run/secrets/aegislure_db_password
  fi
fi

COMPOSE_FILES=(-f docker-compose.yml)
if [[ "$MODE" == postgres ]]; then
  COMPOSE_FILES+=(-f docker-compose.pg.yml)
fi
compose() {
  docker compose "${COMPOSE_FILES[@]}" "$@"
}

compose_has_edge_egress() {
  local rendered
  rendered="$(compose config 2>/dev/null)" || return 1
  awk '
    $0 == "  edge_net:" { in_edge = 1; next }
    in_edge && $0 ~ /^  [^[:space:]][^:]*:/ { in_edge = 0 }
    in_edge && $0 ~ /com\.docker\.network\.bridge\.enable_ip_masquerade:/ {
      value = $0
      sub(/^.*enable_ip_masquerade:[[:space:]]*/, "", value)
      gsub(/[^[:alnum:]_]/, "", value)
      found = (value == "true")
    }
    END { exit found ? 0 : 1 }
  ' <<<"$rendered"
}

require_edge_egress() {
  if ! compose_has_edge_egress; then
    echo "AegisLure requires edge_net outbound egress (enable_ip_masquerade=true) for IPinfo API queries." >&2
    return 1
  fi
}

compose_container_id() {
  local service="$1"
  compose ps -q "$service" 2>/dev/null | head -n 1
}

service_is_running() {
  local service="$1"
  local container_id
  container_id="$(compose_container_id "$service")"
  [[ -n "$container_id" ]] || return 1
  [[ "$(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null || true)" == "true" ]]
}

wait_for_service_health() {
  local service="$1"
  local timeout_seconds="$2"
  local container_id state health
  local elapsed=0
  while (( elapsed < timeout_seconds )); do
    container_id="$(compose_container_id "$service")"
    if [[ -n "$container_id" ]]; then
      state="$(docker inspect -f '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
      health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || true)"
      if [[ "$health" == "healthy" ]]; then
        return 0
      fi
      if [[ "$state" == "exited" || "$state" == "dead" ]]; then
        echo "AegisLure installation failed during ${service} startup (container state: ${state}, health: ${health})." >&2
        return 1
      fi
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "AegisLure installation timed out waiting for ${service} to become healthy." >&2
  return 1
}

wait_for_aegislure_health() {
  local health_output container_id container_health container_state
  local elapsed=0
  health_output="$(mktemp runtime/.health.XXXXXX)"
  while (( elapsed < 180 )); do
    container_id="$(compose_container_id aegislure)"
    if [[ -n "$container_id" ]]; then
      container_state="$(docker inspect -f '{{.State.Status}}' "$container_id" 2>/dev/null || true)"
      if [[ "$container_state" == "exited" || "$container_state" == "dead" ]]; then
        rm -f "$health_output"
        echo "AegisLure installation failed during application health verification (container state: ${container_state})." >&2
        return 1
      fi
    fi
    if service_is_running aegislure && compose exec -T aegislure /usr/local/bin/hpctl \
      health --config /var/lib/aegislure/config.json >"$health_output" 2>/dev/null; then
      if grep -Eq '"healthy"[[:space:]]*:[[:space:]]*true' "$health_output" \
        && grep -Eq '"database_connected"[[:space:]]*:[[:space:]]*true' "$health_output"; then
        container_health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container_id" 2>/dev/null || true)"
        if [[ "$container_health" == "healthy" ]]; then
          cat "$health_output"
          rm -f "$health_output"
          return 0
        fi
      fi
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  rm -f "$health_output"
  echo "AegisLure installation timed out waiting for the application health check and Docker health status (healthy=true and database_connected=true)." >&2
  return 1
}

show_startup_diagnostics() {
  if [[ "$MODE" == postgres && -z "$CONFIGURED_DATABASE_URL" && -z "$CONFIGURED_DATABASE_URL_FILE" ]]; then
    compose --profile bundled-pg ps >&2 || true
    compose --profile bundled-pg logs --no-color --tail=100 postgres-secret-init postgres postgres-init aegislure >&2 || true
  else
    compose ps >&2 || true
    compose logs --no-color --tail=100 aegislure >&2 || true
  fi
}

if ! compose config >/dev/null; then
  echo "AegisLure installation failed during Compose configuration validation." >&2
  exit 1
fi
if ! require_edge_egress; then
  echo "AegisLure installation failed during edge network validation." >&2
  exit 1
fi
if [[ "$NO_BUILD" -eq 0 ]]; then
  if ! compose build; then
    echo "AegisLure installation failed during image build." >&2
    exit 1
  fi
fi
if [[ "$PULL" -eq 1 ]]; then
  if ! compose pull; then
    echo "AegisLure installation failed during image pull." >&2
    exit 1
  fi
fi

if [[ "$MODE" == postgres && -z "$CONFIGURED_DATABASE_URL" && -z "$CONFIGURED_DATABASE_URL_FILE" ]]; then
  if ! compose --profile bundled-pg up -d postgres; then
    echo "AegisLure installation failed during bundled PostgreSQL startup." >&2
    show_startup_diagnostics
    exit 1
  fi
  if ! wait_for_service_health postgres 180; then
    show_startup_diagnostics
    exit 1
  fi
fi
if [[ ! -f runtime/config.json ]]; then
  if ! compose run --rm --no-deps --entrypoint /usr/local/bin/hpctl aegislure \
    init --config /var/lib/aegislure/config.json --data-dir /var/lib/aegislure/data; then
    echo "AegisLure installation failed during runtime initialization." >&2
    show_startup_diagnostics
    exit 1
  fi
fi

if [[ "$MODE" == postgres && -z "$CONFIGURED_DATABASE_URL" && -z "$CONFIGURED_DATABASE_URL_FILE" ]]; then
  if ! compose --profile bundled-pg up -d aegislure; then
    echo "AegisLure installation failed during application startup." >&2
    show_startup_diagnostics
    exit 1
  fi
else
  if ! compose up -d aegislure; then
    echo "AegisLure installation failed during application startup." >&2
    show_startup_diagnostics
    exit 1
  fi
fi
if ! wait_for_aegislure_health; then
  show_startup_diagnostics
  exit 1
fi
if ! compose exec -T aegislure /usr/local/bin/hpctl \
  status --config /var/lib/aegislure/config.json; then
  echo "AegisLure installation failed during final status verification." >&2
  show_startup_diagnostics
  exit 1
fi
echo "AegisLure is running and passed the database and application health checks. Open the hidden admin path to create the first owner."
echo "Admin TLS certificate fingerprint (SHA-256):"
openssl x509 -in runtime/secrets/admin.crt -noout -fingerprint -sha256
echo "Use: ./hpctl status"
