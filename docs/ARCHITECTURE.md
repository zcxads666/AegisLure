# AegisLure architecture

## Standalone data flow

```text
Internet
   │
   ├── public profile listeners (one port → one product profile)
   │          │
   │          └── bounded HTTP reader → safe classifier → synthetic response
   │                                      │
   │                                      └── event JSONL + virtual state
   │
   └── random admin port + exact random path → authenticated control API
```

The current binary combines the first-stage `hp-edge`, `hp-core`, `hp-collector`, `hp-controller` and `hp-admin-gateway` responsibilities so it can run on a single small node. SQLite WAL is the authoritative local store; `events.jsonl` and `state.json` remain bounded compatibility/backup mirrors. The code keeps product routing, event storage, detection and admin paths separated behind package boundaries so they can become processes in Distributed v2 without changing the event contract.

The Standalone v1 boundary is deliberately complete without a center node: profile listeners, the admin gateway, OAuth broker (disabled unless configured), detector packs, retention, backup/restore and upgrade/rollback control all operate from the local installation. PostgreSQL, Hive, sensors, mTLS enrollment and durable cross-node ACKs are not hidden dependencies of this binary.

## Four configuration contracts

- `FingerprintPack`: product/version, route family and public response shape.
- `ModelCatalog`: display-only model metadata and aliases; never endpoint/secret/path.
- `ScenarioPack`: auth posture, synthetic stream and virtual effect TTL.
- `DetectorRulePack`: data-only reason codes and bounded score rules.

Each new anonymous product session pins the active model-catalog revision when it
is first observed. Later pack activation therefore cannot change the model list
halfway through that session. Public renderers project that pinned catalog into
the product-specific Ollama/vLLM/OpenAI shapes; control-plane fields such as
visibility, auth requirement and virtual pricing never cross that boundary.

The checked-in JSON packs are declarative fixtures. No pack can load code, a URL, a shell command, a template, SQL or an arbitrary regex.

## Event contract

Every request becomes an event with product, profile, route template, real socket peer, bounded body hash/preview, status, timing, session, auth outcome, execution outcome, effect outcome, invocation level, intent and reason codes. The store aggregates indicators from those events and applies the configured age/count retention policy. Expired rows and their imported provenance are pruned from SQLite; the JSONL mirror is rewritten from the authoritative rows when it exceeds its bounded policy.

Invocation levels are orthogonal to risk:

```text
L0 scan → L1 rejected attempt → L2 synthetic accepted → L3 response consumed → L4 effect verified
```

The service never emits a `real_inference` outcome. All accepted model work is deterministic protocol emulation, and virtual effects are scoped to the local session/tenant with a bounded lifetime.

## Local persistence and release controls

- `aegislure.sqlite` is opened in WAL mode with foreign keys enabled. `state.json` and `events.jsonl` are compatibility mirrors, not competing sources of truth.
- Event retention defaults to 30 days and 100,000 rows. Operators can set `event_retention_days`/`event_max_entries` in the runtime config or use `HP_EVENT_RETENTION_DAYS`/`HP_EVENT_MAX_ENTRIES`; values are bounded by the config loader.
- `hpctl backup` creates a bounded ZIP containing the config, a SQLite snapshot, and the two mirrors. `hpctl restore` accepts only those members, validates a staged SQLite copy, applies per-file/total limits, and replaces runtime files atomically.
- OAuth is an opt-in broker boundary. Its credentials are loaded from an owner-readable-only local file, endpoints are fixed to the official provider hosts, state/PKCE/nonce are short-lived, and provider tokens are not persisted in local state, logs or backups.
- Local indicator decisions, import-source lifecycle and identity review state are
  persisted in the same WAL-backed state transaction. Approval, challenge and
  ignore records always carry a bounded expiry; no local route creates a
  permanent block or a cross-site identity feed.
- Indicator exports support bounded JSON/CSV/plain/STIX 2.1/nftables projections.
  The synchronous indicator route and the transient 15-minute export-job route
  return only filtered safe projections; raw imported files and body payloads
  are not copied into an export job.
- `make sbom` generates an offline SPDX 2.3 dependency inventory from the committed `go.mod`/`go.sum`. Image signing and the final registry digest remain operator release gates.

## Standalone v1 gates

1. Before public deployment, validate the host firewall/VPN restriction for the random admin port, the no-egress container behavior and the broker's fixed OAuth egress separately from unit tests.
2. Build and publish only an immutable image digest after running the Go tests, `go vet`, compatibility scripts where available, SBOM generation and the operator's image-signing workflow.
3. Run the standalone installation through restart, backup/restore, failed-image rollback and retention checks on the target architecture. The repository includes the deterministic controls; a multi-week production soak is an operational gate, not something a source checkout can claim to have completed.

## Explicitly excluded Distributed v2

Sensor enrollment, mTLS certificate lifecycle, signed desired state, durable ACK/replay, PostgreSQL Hive, cross-node activity correlation, RDAP/ASN enrichment and reviewed global blocklists remain online/distributed design work. They are intentionally excluded from the single-machine implementation and must not be enabled by interpreting local JSONL import as distributed transport.
