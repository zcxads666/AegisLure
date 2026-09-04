#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
source_root="${SUB2API_WEB_SOURCE:-/Volumes/1/code/sub2api/frontend}"
source_root="$(cd -- "$source_root" && pwd)"
source_repo="$(cd -- "$source_root/.." && pwd)"
node_modules_root="${SUB2API_WEB_NODE_MODULES:-$source_root/node_modules}"
artifact_root="$project_root/internal/app/ui/sub2api-dist"
stage_root="$(mktemp -d /tmp/aegislure-sub2api.XXXXXX)"

cleanup() {
  rm -rf "$stage_root"
}
trap cleanup EXIT

if [[ ! -d "$source_root/src" || ! -f "$source_root/package.json" ]]; then
  echo "Sub2API frontend source not found: $source_root" >&2
  exit 1
fi
if [[ ! -d "$node_modules_root" ]]; then
  echo "Sub2API frontend node_modules not found: $node_modules_root" >&2
  exit 1
fi

echo "Staging official Sub2API frontend from $source_root"
mkdir -p "$stage_root/frontend" "$stage_root/docs"
rsync -a --exclude '.git' --exclude 'node_modules' --exclude 'dist' "$source_root/" "$stage_root/frontend/"
if [[ -d "$source_repo/docs" ]]; then
  rsync -a "$source_repo/docs/" "$stage_root/docs/"
fi
ln -s "$node_modules_root" "$stage_root/frontend/node_modules"

source_commit="$(git -C "$source_repo" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
echo "Building official Sub2API frontend commit $source_commit"
(
  cd "$stage_root/frontend"
  pnpm build
)

if [[ ! -f "$stage_root/backend/internal/web/dist/index.html" ]]; then
  echo "Sub2API frontend build did not produce index.html" >&2
  exit 1
fi

rm -rf "$artifact_root"
mkdir -p "$artifact_root"
cp -a "$stage_root/backend/internal/web/dist/." "$artifact_root/"
if [[ ! -f "$source_repo/LICENSE" ]]; then
  echo "Sub2API upstream LICENSE not found: $source_repo/LICENSE" >&2
  exit 1
fi
cp "$source_repo/LICENSE" "$artifact_root/UPSTREAM-LICENSE.txt"
cat > "$artifact_root/SOURCE.txt" <<EOF
Sub2API frontend source commit: $source_commit
Source checkout: $source_repo
Build command: pnpm build
Upstream copyright: (c) 2026 Wesley Liddick
Upstream license: GNU Lesser General Public License v3.0 or later (see UPSTREAM-LICENSE.txt)
EOF

echo "Embedded artifact written to $artifact_root"
