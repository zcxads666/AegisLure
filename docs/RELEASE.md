# Standalone release checklist

This checklist separates repository evidence from deployment-owner gates.
The source tree can prove tests and bounded configuration; it cannot prove a
particular host's firewall, packet capture, image registry or multi-week soak.

## Reproducible local checks

Run from the repository root:

```bash
env GOPROXY=off GOSUMDB=off go test ./...
env GOPROXY=off GOSUMDB=off go vet ./...
make sbom
```

`make sbom` reads the committed `go.mod` and `go.sum` directly and emits an
SPDX 2.3 JSON inventory without resolving modules from the network. Review the
resulting `sbom.spdx.json` together with [NOTICE](../NOTICE) and the exact
source revision.

When the host has the required tools, run the Ollama/vLLM compatibility suite:

```bash
./scripts/check-ai-mac.sh
# Windows PowerShell:
./scripts/check-ai.ps1
```

The scripts exercise public surfaces and reject internal markers; they do not
replace packet capture or an isolated adversarial test.

## Image and deployment gates

- Build for every target architecture used by the deployment and record the
  resulting image digest. Use only `registry/name@sha256:<64 hex>` in
  `hpctl upgrade` and `hpctl rollback`.
- Sign the immutable image with the organization's signing key and verify it
  on the destination before `docker compose up -d`. AegisLure does not ship a
  signing key or claim that a registry artifact is already signed. A typical
  operator workflow is `cosign sign <image@digest>` followed by
  `cosign verify <image@digest>` under the organization's policy.
- Keep `runtime/secrets` outside the image and do not pass OAuth credentials in
  Compose environment variables. Confirm the generated admin certificate
  fingerprint through `install.sh` or the deployment's certificate inventory.
- Restrict the admin port using a VPN, security group or host firewall. Test
  wrong paths, wrong Host values, unauthenticated writes, brute-force limits,
  cookie attributes and setup/recovery races from an external test host.
- Capture host/container traffic with all non-broker egress blocked. Verify
  that public profile requests cannot reach a canary, metadata service,
  private address, model registry, shell or GPU. If OAuth is enabled, verify
  that only the fixed official endpoints are contacted.
- Exercise restart, host reboot, retention pruning, backup restore on a clean
  data directory, and failed-image rollback. Preserve the previous immutable
  digest until the new image passes health and profile checks.

## Scope boundary

Standalone v1 does not include sensor enrollment, mTLS fleet control,
PostgreSQL Hive, durable cross-node ACK, global identity reputation or remote
blocklist propagation. Those are Distributed v2 requirements and must not be
represented as completed by a local importer or SQLite backup.
