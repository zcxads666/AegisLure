#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ -f scripts/env.sh ]]; then
  source scripts/env.sh
fi

OUTPUT="${1:-sbom.spdx.json}"
GOPROXY="${GOPROXY:-off}" GOSUMDB="${GOSUMDB:-off}" go run ./cmd/sbom -output "$OUTPUT"
chmod 600 "$OUTPUT"
