#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="zcxads666/AegisLure"
DEFAULT_VERSION="v0.1.0"
MODE="sqlite"
VERSION="$DEFAULT_VERSION"
TARGET_DIR="${AEGISLURE_DIR:-$PWD/aegislure}"

usage() {
  cat <<'EOF'
Usage: curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | bash -s -- [options]

  --mode sqlite|postgres   backend (default: sqlite)
  --version vX.Y.Z|last    fixed release, or resolve the latest GitHub release
  --dir PATH               installation directory (default: ./aegislure)
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
    --dir)
      [[ $# -ge 2 ]] || { echo "--dir requires a value" >&2; exit 2; }
      TARGET_DIR="$2"
      shift 2
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

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  SHA256_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  SHA256_TOOL=shasum
else
  echo "sha256sum or shasum is required" >&2
  exit 1
fi

if [[ "$VERSION" == "last" || "$VERSION" == "latest" ]]; then
  latest_json="$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/${REPOSITORY}/releases/latest")"
  VERSION="$(printf '%s\n' "$latest_json" | sed -n 's/^[[:space:]]*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
fi
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "release version must look like v0.1.0 or last" >&2; exit 2; }

release_url="https://github.com/${REPOSITORY}/releases/download/${VERSION}"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/aegislure-remote.XXXXXX")"
cleanup() { rm -rf "$temporary"; }
trap cleanup EXIT

manifest_path="$temporary/release-manifest.json"
checksums_path="$temporary/sha256sums.txt"
bundle_name="aegislure-${VERSION}.tar.gz"
bundle_path="$temporary/$bundle_name"
curl -fsSL "$release_url/release-manifest.json" -o "$manifest_path"
curl -fsSL "$release_url/sha256sums.txt" -o "$checksums_path"
curl -fsSL "$release_url/$bundle_name" -o "$bundle_path"

json_string() {
  local key="$1"
  tr '\n' ' ' <"$manifest_path" | sed -n "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

manifest_version="$(json_string version)"
manifest_image="$(json_string image)"
[[ "$manifest_version" == "$VERSION" ]] || { echo "release manifest version mismatch" >&2; exit 1; }
[[ "$manifest_image" =~ ^ghcr\.io/zcxads666/aegislure@sha256:[a-f0-9]{64}$ ]] || { echo "release manifest has no immutable GHCR image digest" >&2; exit 1; }

expected="$(awk -v name="$bundle_name" '$2 == name { print $1; exit }' "$checksums_path")"
if [[ -z "$expected" ]]; then
  echo "bundle checksum is missing from sha256sums.txt" >&2
  exit 1
fi
if [[ "$SHA256_TOOL" == "sha256sum" ]]; then
  actual="$(sha256sum "$bundle_path" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$bundle_path" | awk '{print $1}')"
fi
[[ "$actual" == "$expected" ]] || { echo "bundle checksum verification failed" >&2; exit 1; }

if tar -tzf "$bundle_path" | awk -v prefix="aegislure-${VERSION}/" 'index($0, prefix) != 1 { bad = 1 } END { exit bad }'; then
  :
else
  echo "release archive contains an unsafe path" >&2
  exit 1
fi
tar -xzf "$bundle_path" -C "$temporary"
source_dir="$temporary/aegislure-${VERSION}"
[[ -f "$source_dir/install.sh" && -f "$source_dir/docker-compose.yml" && -f "$source_dir/docker-compose.pg.yml" ]] || { echo "release archive is incomplete" >&2; exit 1; }

mkdir -p "$TARGET_DIR"
for file in Dockerfile docker-compose.yml docker-compose.pg.yml .env.example install.sh hpctl; do
  if [[ -e "$source_dir/$file" ]]; then
    install -m 0755 "$source_dir/$file" "$TARGET_DIR/$file"
  fi
done
chmod 0644 "$TARGET_DIR/Dockerfile" "$TARGET_DIR/docker-compose.yml" "$TARGET_DIR/docker-compose.pg.yml" "$TARGET_DIR/.env.example"
chmod 0755 "$TARGET_DIR/install.sh" "$TARGET_DIR/hpctl"

cd "$TARGET_DIR"
./install.sh --mode "$MODE" --version "$VERSION" --image "$manifest_image" --no-build --pull
echo "Installed ${manifest_image} in ${TARGET_DIR}"
