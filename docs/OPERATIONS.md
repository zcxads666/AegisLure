# Operations

## Commands

```bash
./hpctl init
./hpctl status
./hpctl health
./hpctl start
./hpctl stop
./hpctl restart
./hpctl admin entry rotate
./hpctl admin reset issue --user owner
./hpctl ports plan
./hpctl ports plan --profile ollama --port 11435 --output /tmp/ollama-port-plan.json
./hpctl ports apply --input /tmp/ollama-port-plan.json --project-dir .
./hpctl backup --output aegislure-backup.zip
./hpctl restore --input aegislure-backup.zip --config ./runtime/config.json --data-dir ./runtime/data
./hpctl logs --lines 100
./hpctl import --input promptpot-events.jsonl --product ollama --source-id promptpot --file-id run-2026-08-31
./hpctl upgrade --image registry.example/aegislure@sha256:<64-hex-digest>
./hpctl rollback --image registry.example/aegislure@sha256:<64-hex-digest>
./hpctl uninstall
./hpctl uninstall --purge-data --confirm-purge
make sbom
```

`admin entry rotate` writes a new path into the runtime config; restart the service before using it. It invalidates active web sessions when performed through the authenticated API. A host port change is a signed declarative `PortChangePlan`; `hpctl ports apply` updates the selected profile's runtime mapping and `.env`, but deliberately does not restart the service. For a default pool candidate it updates that profile's `*_PORT_1` … `*_PORT_7` published slot; for a pool-external port it updates the base `*_PORT`/`*_TARGET_PORT` mapping. Confirm the plan is current, then run `hpctl restart` or `docker compose up -d`.

`hpctl health` checks the local HTTPS/HTTP setup status endpoint with proxy use disabled. The response includes readiness for every selected public profile and its actual/configured port; verify the host-side published mapping with `ss -ltnp` and the admin instance view. The service refuses to start if a selected profile has no valid configured port.

The Compose installation requires the generated admin certificate/key and sets `HP_REQUIRE_TLS=1`. Native development can remain HTTP only when TLS is intentionally not configured. Set `HP_ADMIN_HOSTS` to a comma-separated allowlist when the management listener is reached through known hostnames; keep the management port behind a VPN, trusted reverse proxy or host firewall because the random path is only an additional locator.

Event storage is bounded by `event_retention_days` (default 30) and `event_max_entries` (default 100000). The equivalent environment overrides are `HP_EVENT_RETENTION_DAYS` and `HP_EVENT_MAX_ENTRIES`; invalid or out-of-range values are ignored by the config loader. `HP_DB_DRIVER=sqlite` is the default. Set `HP_DB_DRIVER=postgres` with `HP_DATABASE_URL`/`HP_DATABASE_URL_FILE`, or with the `HP_DB_HOST`, `HP_DB_PORT`, `HP_DB_NAME`, `HP_DB_USER`, `HP_DB_PASSWORD_FILE` and `HP_DB_SSLMODE` component settings. SQLite keeps bounded JSONL/state mirrors; PostgreSQL is authoritative without those mirrors.

The current admin profile intentionally has no Bootstrap code and no TOTP/MFA. The first owner is created directly at `<admin_path>/setup/create-owner`; use an 8+ character password and store the one-time recovery codes. Treat the hidden path as an additional locator only: restrict the management port to a trusted network or VPN in production.

## Backups

The current backup archive contains `config.json`, `snapshot.json` and `manifest.json`. The logical snapshot records its backend, SHA-256-checked contents, state, retained events, audit chain and imported-event idempotency references. Protect it like a secret because the config contains the instance key and the state contains keyed hashes. Restore only onto an isolated, stopped installation after validating ownership and permissions. Restore accepts bounded fixed names and refuses a SQLite snapshot on PostgreSQL or a PostgreSQL snapshot on SQLite; cross-backend migration is not implemented. TLS secrets, OAuth secrets and arbitrary paths are never restored. Older SQLite archives with `aegislure.sqlite`, `state.json` and `events.jsonl` remain readable for compatibility.

SQLite uses `aegislure.sqlite` in WAL mode as its authoritative local store and maintains append-only `events.jsonl` plus atomic `state.json` compatibility mirrors. PostgreSQL stores the same logical state, event stream, audit chain and import provenance in its own schema and does not read local SQLite files. Both backends use database transactions/locks for state, event sequence, audit-chain and quota updates. Imported third-party events use a local provenance key for idempotency; this is not a distributed durable ACK protocol.

`hpctl import` is an offline, bounded JSONL importer for the allowlisted local products (`new-api`, `vllm`, `ollama`, `sglang`, and `localai`). It accepts only the documented event fields, requires an IP address, redacts body previews, and records source product/schema/file/offset/hash provenance. Re-running the same file identity and byte offsets is idempotent. It never downloads models, opens a source URL, or forwards imported content to an external service.

The admin import-source registry stores only a bounded source declaration (`source_type`, installation-owned `root_path_alias`, product and schema). The control plane cannot browse that alias or read the source file; `hpctl import` remains the explicit local read operation. Validate, dry-run, enable and disable update lifecycle/audit counters without echoing source content.

IP review actions are local, manual decisions with a 60-second to 7-day TTL. `status=approved` is required for the `nftables` projection; exports are filtered, bounded and synthetic. `POST /admin/api/v1/exports` creates a transient 15-minute local export job, and the status/download endpoints do not persist the generated document in the event store.

## Optional IPinfo Lite lookup

The admin console's Settings page can store an optional IPinfo Lite token in
the owner-readable runtime config. The backend never returns the raw token to
the browser; `GET /admin/api/v1/ipinfo-lite` returns only configuration status,
a masked suffix and bounded timeout/cache metadata, while
`PUT /admin/api/v1/ipinfo-lite` accepts `{"token":"..."}` or an empty token to
disable the lookup. Only public IPs are sent to the provider. Loopback,
private, link-local, multicast, unspecified and documentation ranges are
classified locally. Missing credentials, provider errors and timeouts fall
back to the deterministic local label or `未知`; successful responses are
cached for 24 hours and failures for 5 minutes. See the [IPinfo Lite API
documentation](https://ipinfo.io/developers//lite-api) for the provider
endpoint and response fields.

## Optional OAuth broker

OAuth is disabled when no config file is present. To enable it, copy `configs/oauth.example.json` to `runtime/secrets/oauth.json`, replace the provider credentials and exact HTTPS callback URLs, set mode `0600`, and restart. The process also accepts an explicit `HP_OAUTH_CONFIG` path. The loader rejects symlinks, group/world-readable files, unknown fields, custom endpoints and non-minimal scopes; provider tokens and authorization codes are memory-only.

Only the official GitHub, Discord and LinuxDO authorization/token/userinfo endpoints are accepted. Discord and LinuxDO identities are local-only by policy; a GitHub identity can be exported only with an explicit approved policy reference. The admin API exposes provider/HMAC/timestamp metadata without raw provider IDs, email or tokens:

```text
GET    <admin_path>/admin/api/v1/identities
POST   <admin_path>/admin/api/v1/identities/<id>/revoke
DELETE <admin_path>/admin/api/v1/identities/<id>
```

Revoke disables the local association. Delete removes the association and, when it is the user's last identity, the local honey user, its honey tokens and quota ledger. Historical events remain until the configured retention policy removes them. See [docs/PRIVACY.md](PRIVACY.md) for the data lifecycle.

## Upgrade and rollback

Use immutable `@sha256:<digest>` image references:

```bash
./hpctl upgrade --image registry.example/aegislure@sha256:<64-hex-digest>
./hpctl rollback --image registry.example/aegislure@sha256:<64-hex-digest>
```

The command refuses tag-only references. Capture `./hpctl status`, the current image digest and a backend-matched backup before an upgrade; verify health and the expected profile set after restart. Roll back to the previously recorded digest if the new image fails validation. Database migration is not performed by upgrade or restore; test a same-backend backup on a clean destination before a production change.

For the bundled PostgreSQL topology, start the database and application with:

```bash
docker compose -f docker-compose.yml -f docker-compose.pg.yml --profile bundled-pg up -d
```

For a managed PostgreSQL service, set `HP_DATABASE_URL` (or provide a URL file
through the deployment's secret mechanism) and omit `--profile bundled-pg`. In
Compose, a file under `runtime/secrets` is visible inside the container under
`/var/lib/aegislure/secrets`; set `HP_DATABASE_URL_FILE` to that container path.

## Incident response

If a decoy appears to make an outbound connection, stop the public listener, preserve only the bounded event hashes and process/container metadata, block egress at the host firewall, and inspect the exact image digest and config pack revision. Do not reproduce the payload on a production machine.

The native helper validates its PID against the exact AegisLure binary and config path before stopping it, and scans for a matching process if the PID file is stale. This avoids leaving an old listener behind after a failed start while refusing to kill an unrelated PID.

## Release checklist

Run `env GOPROXY=off GOSUMDB=off go test ./...`, `env GOPROXY=off GOSUMDB=off go vet ./...`, and `make sbom`. Review `NOTICE`, `docs/PRIVACY.md`, the generated SBOM and the image digest together. The repository does not contain a production signing key or a signed registry artifact; signing and verification must be performed by the deployment owner before publication.
