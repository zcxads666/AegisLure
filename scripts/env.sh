#!/usr/bin/env bash
# Load the project-local toolchain without changing system directories.
PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$PROJECT_ROOT/.tools/bin:$PROJECT_ROOT/.tools/go/bin:$PATH"
export DOCKER_CONFIG="$PROJECT_ROOT/.tools/docker-config"
export GOPATH="$PROJECT_ROOT/.tools/gopath"
export GOMODCACHE="$PROJECT_ROOT/.tools/gopath/pkg/mod"
export GOCACHE="$PROJECT_ROOT/.tools/gocache"
