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
./hpctl upgrade --image registry.example/aegislure@sha256:<64-hex-digest>
./hpctl rollback --image registry.example/aegislure@sha256:<64-hex-digest>
./hpctl uninstall
./hpctl uninstall --purge-data --confirm-purge
```

`admin entry rotate` writes a new path into the runtime config; restart the service before using it. It invalidates active web sessions when performed through the authenticated API. A host port change is a signed declarative `PortChangePlan`; `hpctl ports apply` updates the selected profile's runtime mapping and `.env`, but deliberately does not restart the service. Confirm the plan is current, then run `hpctl restart` or `docker compose up -d`.

`hpctl health` checks the local HTTPS/HTTP setup status endpoint with proxy use disabled. A healthy admin endpoint does not by itself prove every selected public profile is listening; verify the expected listener set with `ss -ltnp` and the admin instance view. The service refuses to start if a selected profile has no valid configured port.

The current admin profile intentionally has no Bootstrap code and no TOTP/MFA. The first owner is created directly at `<admin_path>/setup/create-owner`; use an 8+ character password and store the one-time recovery codes. Treat the hidden path as an additional locator only: restrict the management port to a trusted network or VPN in production.

## Backups

The backup archive contains the runtime config and event/state files. Protect it like a secret because the config contains the instance key and the state contains keyed hashes. Restore only onto an isolated, stopped installation after validating ownership and permissions. Restore accepts only the three expected archive members, applies size limits, stages extraction, and atomically replaces state/data files; it does not restore TLS secrets or arbitrary paths.

The standalone backend uses `aegislure.sqlite` in WAL mode as its authoritative local store, plus append-only `events.jsonl` and atomic `state.json` compatibility/backup mirrors. Event sequence numbers and virtual state are restored after restart. Imported third-party events use a local provenance key for idempotency; this is not the later distributed durable ACK protocol. Do not treat this standalone store as the later PostgreSQL/Hive sensor transport.

## Incident response

If a decoy appears to make an outbound connection, stop the public listener, preserve only the bounded event hashes and process/container metadata, block egress at the host firewall, and inspect the exact image digest and config pack revision. Do not reproduce the payload on a production machine.

The native helper validates its PID against the exact AegisLure binary and config path before stopping it, and scans for a matching process if the PID file is stale. This avoids leaving an old listener behind after a failed start while refusing to kill an unrelated PID.
