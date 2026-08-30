#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
if [[ -f scripts/env.sh ]]; then
  source scripts/env.sh
fi

command -v docker >/dev/null 2>&1 || { echo "Docker Engine is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker CLI is installed, but Docker Engine is not reachable; install/start the daemon or set DOCKER_HOST" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }

mkdir -p runtime/data runtime/secrets
chmod 700 runtime runtime/data runtime/secrets

if [[ ! -f .env ]]; then
  admin_port=$((20000 + $(od -An -N2 -tu2 /dev/urandom) % 40999))
  cat > .env <<EOF
HP_ADMIN_PORT=${admin_port}
HP_PROFILES=${HP_PROFILES:-ollama,vllm}
HP_CONTAINER_UID=$(id -u)
HP_CONTAINER_GID=$(id -g)
EOF
  chmod 600 .env
else
  # Bind mounts must remain writable by the non-root container user.  Add
  # these values to older .env files without changing existing settings.
  if ! grep -q '^HP_CONTAINER_UID=' .env; then
    printf 'HP_CONTAINER_UID=%s\n' "$(id -u)" >> .env
  fi
  if ! grep -q '^HP_CONTAINER_GID=' .env; then
    printf 'HP_CONTAINER_GID=%s\n' "$(id -g)" >> .env
  fi
fi

if [[ ! -f runtime/secrets/admin.crt || ! -f runtime/secrets/admin.key ]]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -subj "/CN=aegislure.local" \
    -addext "subjectAltName=DNS:aegislure.local" \
    -keyout runtime/secrets/admin.key -out runtime/secrets/admin.crt >/dev/null 2>&1
  chmod 600 runtime/secrets/admin.key
  chmod 644 runtime/secrets/admin.crt
fi

docker compose build
if [[ ! -f runtime/config.json ]]; then
  docker compose run --rm --entrypoint /usr/local/bin/hpctl aegislure \
    init --config /var/lib/aegislure/config.json --data-dir /var/lib/aegislure/data
fi

docker compose up -d
echo "AegisLure is running. Open the hidden admin path to create the first owner."
echo "Use: ./hpctl status"
