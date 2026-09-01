# Privacy and data lifecycle

AegisLure is a security telemetry honeypot. Deploy it only where collection
of network metadata and decoy-account activity is lawful and disclosed to the
operator's users and hosting provider. It is not an identity-verification
service: an OAuth account is an observed association, not proof of who sent a
request.

## What the standalone service stores

- Requests store the real socket peer IP, bounded User-Agent/product/session
  fingerprints, route and status, timing, authentication/execution/effect
  outcomes, reason codes, and bounded hashes/previews. Request bodies are not
  retained without the redaction and size limits enforced by the service.
- Passwords, recovery codes, honey API keys, OAuth authorization codes and
  provider tokens are never stored as plaintext. The local state keeps keyed
  fingerprints or hashes and the minimum virtual-account metadata required to
  continue a decoy workflow.
- The optional OAuth broker returns only provider, stable subject HMAC, scopes
  and completion time to the application. It does not return raw provider IDs,
  email addresses, handles, passwords or tokens. The broker config contains
  client credentials and must be protected as a secret.
- SQLite WAL is authoritative. `events.jsonl` and `state.json` are bounded
  compatibility/backup mirrors. Imported events include source/schema/file/
  offset/hash provenance so local migration data can be audited.
- Import-source declarations contain only an installation-owned alias and
  allowlisted schema/product metadata. The admin API cannot use that alias to
  browse a host path; the explicit local `hpctl import` command performs the
  bounded read. Transient indicator export jobs expire after 15 minutes and are
  not copied into the event store.

If the operator explicitly configures an IPinfo Lite token, public source IPs
may be sent to IPinfo for country/continent/ASN enrichment. Local, private,
link-local, multicast, unspecified and documentation addresses are classified
without an outbound lookup. The raw token is kept in the owner-readable
runtime config and is never returned by the admin API; unset, failed and
timed-out lookups fall back to `未知` or the deterministic local label. See
the [IPinfo Lite API documentation](https://ipinfo.io/developers//lite-api)
for the provider's documented fields and endpoint.

## Retention and deletion

Event retention defaults to 30 days and 100,000 rows. Configure
`event_retention_days` and `event_max_entries`, or the equivalent
`HP_EVENT_RETENTION_DAYS` and `HP_EVENT_MAX_ENTRIES` environment variables.
Pruning removes expired/over-limit SQLite event rows and imported provenance;
the event mirror is rewritten from the retained authoritative rows.

An administrator can inspect safe identity metadata at
`<admin_path>/admin/api/v1/identities`, revoke an association with
`POST .../identities/<id>/revoke`, or delete it with
`DELETE .../identities/<id>`. Delete does not require a provider token. If the
identity was the user's last provider association, the local honey user,
honey tokens and quota ledger are removed. Historical events remain until
normal retention removes them, so use the configured retention window or
explicitly purge the runtime installation when that is required.

IP indicators are evidence aggregates, not identity proof. Approval, ignore,
challenge and revoke decisions are reviewer-attributed local records with a
bounded expiry; the standalone API has no permanent-block action and does not
publish a cross-site identity or blocklist feed.

`hpctl uninstall` retains runtime data. The explicit command
`hpctl uninstall --purge-data --confirm-purge` removes the configured data,
secret directory and config file; treat that as irreversible and take any
required legal or forensic export first.

## OAuth disclosure and controls

OAuth is disabled unless the operator supplies an owner-readable-only
`runtime/secrets/oauth.json` (or `HP_OAUTH_CONFIG`). The user is redirected to
the provider's official authorization endpoint. The broker uses exact HTTPS
callbacks, short-lived one-time state, PKCE where configured, minimal scopes,
fixed provider endpoints, no redirects and bounded responses. Discord and
LinuxDO associations are local-only. A GitHub association is exportable only
when the operator has set an explicit approved policy reference.

Do not put OAuth secrets in Git, container images, Compose environment values,
support bundles, backups or issue reports. The standalone backup command
intentionally excludes the secrets directory.

## Operator responsibilities

Publish the deployment's notice, purpose, retention period, contact and lawful
basis as required by the applicable jurisdiction. Restrict the admin port at
the host firewall/VPN layer, review exports before sharing them, and destroy
runtime data and OAuth credentials when the collection purpose ends.
