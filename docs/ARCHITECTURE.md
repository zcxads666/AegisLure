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

The current binary combines the first-stage `hp-edge`, `hp-core`, `hp-collector`, `hp-controller` and `hp-admin-gateway` responsibilities so it can run on a single small node. The code keeps product routing, event storage, detection and admin paths separated behind package boundaries so they can become processes in Distributed v2 without changing the event contract.

## Four configuration contracts

- `FingerprintPack`: product/version, route family and public response shape.
- `ModelCatalog`: display-only model metadata and aliases; never endpoint/secret/path.
- `ScenarioPack`: auth posture, synthetic stream and virtual effect TTL.
- `DetectorRulePack`: data-only reason codes and bounded score rules.

The checked-in JSON packs are declarative fixtures. No pack can load code, a URL, a shell command, a template, SQL or an arbitrary regex.

## Event contract

Every request becomes an event with product, profile, route template, real socket peer, bounded body hash/preview, status, timing, session, auth outcome, execution outcome, effect outcome, invocation level, intent and reason codes. The store aggregates indicators from those events but does not delete the underlying observations.

Invocation levels are orthogonal to risk:

```text
L0 scan → L1 rejected attempt → L2 synthetic accepted → L3 response consumed → L4 effect verified
```

The service never emits a `real_inference` outcome.

## Next release gates

1. Replace the Lite JSONL store with the planned SQLite WAL adapter and retention jobs while keeping the same event schema.
2. Split OAuth broker and mailer into separate egress-allowlisted services; no provider credentials belong in the current binary.
3. Add New API upstream fork build metadata and a source-code/NOTICE synchronization check.
4. Add compatibility golden fixtures from safe public contracts, fuzzing, no-egress integration tests and arm64 image builds.
5. Add sensor enrollment, mTLS, signed desired state, durable ACK and PostgreSQL Hive only after Standalone remains stable offline.
