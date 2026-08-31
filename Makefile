SHELL := /usr/bin/env bash
SBOM_OUTPUT ?= sbom.spdx.json

.PHONY: fmt test vet build sbom tools run compose-build

tools:
	./scripts/install-tools.sh

fmt:
	source scripts/env.sh && gofmt -w cmd internal

test:
	source scripts/env.sh && go test ./...

vet:
	source scripts/env.sh && go vet ./...

build:
	source scripts/env.sh && mkdir -p bin && go build -trimpath -ldflags='-s -w' -o bin/aegislure ./cmd/aegislure && go build -trimpath -ldflags='-s -w' -o bin/hpctl ./cmd/hpctl

sbom:
	./scripts/generate-sbom.sh "$(SBOM_OUTPUT)"

run:
	source scripts/env.sh && go run ./cmd/aegislure -config ./config.json

compose-build:
	source scripts/env.sh && docker compose build
