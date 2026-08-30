#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="$PROJECT_ROOT/.tools"
BIN_DIR="$TOOLS_DIR/bin"
GO_VERSION="go1.26.5"
DOCKER_VERSION="29.1.3"
COMPOSE_VERSION="5.4.0"
BUILDX_VERSION="0.36.1"
ROOTLESSKIT_VERSION="3.1.0"
SLIRP4NETNS_VERSION="1.3.4"

mkdir -p "$BIN_DIR" "$TOOLS_DIR/docker-config/cli-plugins" "$TOOLS_DIR/gopath" "$TOOLS_DIR/gocache"

if [[ ! -x "$TOOLS_DIR/go/bin/go" ]]; then
  archive="$(mktemp /tmp/aegislure-go.XXXXXX.tar.gz)"
  trap 'rm -f "$archive"' EXIT
  curl -fsSL "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz" -o "$archive"
  printf '%s  %s\n' '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053' "$archive" | sha256sum -c -
  rm -rf "$TOOLS_DIR/go"
  tar -C "$TOOLS_DIR" -xzf "$archive"
fi

if [[ ! -x "$BIN_DIR/docker" ]]; then
  archive="$(mktemp /tmp/aegislure-docker.XXXXXX.tgz)"
  curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o "$archive"
  tar -xzf "$archive" -C "$TOOLS_DIR"
  cp "$TOOLS_DIR/docker/docker" "$BIN_DIR/docker"
  for binary in dockerd containerd containerd-shim-runc-v2 ctr docker-init docker-proxy runc; do
    if [[ -x "$TOOLS_DIR/docker/$binary" ]]; then
      cp "$TOOLS_DIR/docker/$binary" "$BIN_DIR/$binary"
    fi
  done
  rm -rf "$TOOLS_DIR/docker" "$archive"
  chmod 0755 "$BIN_DIR/docker"
fi

if [[ ! -x "$BIN_DIR/dockerd" ]]; then
  archive="$(mktemp /tmp/aegislure-docker-engine.XXXXXX.tgz)"
  curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o "$archive"
  tar -xzf "$archive" -C "$TOOLS_DIR"
  for binary in dockerd containerd containerd-shim-runc-v2 ctr docker-init docker-proxy runc; do
    if [[ -x "$TOOLS_DIR/docker/$binary" ]]; then
      cp "$TOOLS_DIR/docker/$binary" "$BIN_DIR/$binary"
    fi
  done
  rm -rf "$TOOLS_DIR/docker" "$archive"
  chmod 0755 "$BIN_DIR/dockerd" "$BIN_DIR/containerd" "$BIN_DIR/containerd-shim-runc-v2" "$BIN_DIR/ctr" "$BIN_DIR/docker-init" "$BIN_DIR/docker-proxy" "$BIN_DIR/runc" 2>/dev/null || true
fi

if [[ ! -x "$TOOLS_DIR/docker-config/cli-plugins/docker-compose" ]]; then
  compose="$TOOLS_DIR/docker-config/cli-plugins/docker-compose"
  curl -fsSL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-x86_64" -o "$compose"
  printf '%s  %s\n' '837fd1d35bf6a494f41b5b5988269a7be79de337cf1a1a6ff0e45ab51bb4e9be' "$compose" | sha256sum -c -
  chmod 0755 "$compose"
  cp "$compose" "$BIN_DIR/docker-compose"
fi

if [[ ! -x "$TOOLS_DIR/docker-config/cli-plugins/docker-buildx" ]]; then
  buildx="$TOOLS_DIR/docker-config/cli-plugins/docker-buildx"
  curl -fsSL "https://github.com/docker/buildx/releases/download/v${BUILDX_VERSION}/buildx-v${BUILDX_VERSION}.linux-amd64" -o "$buildx"
  printf '%s  %s\n' '48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778' "$buildx" | sha256sum -c -
  chmod 0755 "$buildx"
  cp "$buildx" "$BIN_DIR/docker-buildx"
fi

if [[ ! -x "$BIN_DIR/rootlesskit" ]]; then
  archive="$(mktemp /tmp/aegislure-rootlesskit.XXXXXX.tar.gz)"
  checksums="$(mktemp /tmp/aegislure-rootlesskit.XXXXXX.sha256)"
  curl -fsSL "https://github.com/rootless-containers/rootlesskit/releases/download/v${ROOTLESSKIT_VERSION}/rootlesskit-x86_64.tar.gz" -o "$archive"
  curl -fsSL "https://github.com/rootless-containers/rootlesskit/releases/download/v${ROOTLESSKIT_VERSION}/SHA256SUMS" -o "$checksums"
  expected="$(awk '/rootlesskit-x86_64\.tar\.gz$/ {print $1 "  " FILENAME; exit}' "$checksums")"
  if [[ -n "$expected" ]]; then
    printf '%s  %s\n' "${expected%%  *}" "$archive" | sha256sum -c -
  fi
  tar -xzf "$archive" -C "$BIN_DIR"
  rm -f "$archive" "$checksums"
  chmod 0755 "$BIN_DIR/rootlesskit"
fi

if [[ ! -x "$BIN_DIR/slirp4netns" ]]; then
  slirp="$BIN_DIR/slirp4netns"
  checksums="$(mktemp /tmp/aegislure-slirp4netns.XXXXXX.sha256)"
  curl -fsSL "https://github.com/rootless-containers/slirp4netns/releases/download/v${SLIRP4NETNS_VERSION}/slirp4netns-x86_64" -o "$slirp"
  curl -fsSL "https://github.com/rootless-containers/slirp4netns/releases/download/v${SLIRP4NETNS_VERSION}/SHA256SUMS" -o "$checksums"
  expected="$(awk '/slirp4netns-x86_64$/ {print $1; exit}' "$checksums")"
  if [[ -n "$expected" ]]; then
    printf '%s  %s\n' "$expected" "$slirp" | sha256sum -c -
  fi
  rm -f "$checksums"
  chmod 0755 "$slirp"
fi

printf 'Installed project-local tools in %s\n' "$TOOLS_DIR"
printf 'Load them with: source scripts/env.sh\n'
source "$PROJECT_ROOT/scripts/env.sh"
go version
docker --version
docker compose version
