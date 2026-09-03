# Privacy and data lifecycle

AegisLure is a security telemetry honeypot. Deploy it only where collection
of network metadata and decoy-account activity is lawful and disclosed to the
operator's users and hosting provider. It is not an identity-verification
service: an OAuth account is an observed association, not proof of who sent a
request.

## What the standalone service stores

- Requests store the real socket peer IP, bounded User-Agent/product/session
  fingerprints, route and status, timing, authentication/execution/effect
  outcomes, reason codes, and bounded hashes/previews. New events also retain
  the parsed original request URL/target, full path, Host, repeated headers and
  a Base64 request-body prefix for owner/admin-only audit display. The service
  caps bodies at 1 MiB and headers at 100 values/32 KiB; oversized requests
  retain only a prefix with an explicit truncation reason. Historical rows
  created before this field existed are marked as missing rather than inferred.
- Passwords, recovery codes, honey API keys, OAuth authorization codes and
  provider tokens are never stored as plaintext. The local state keeps keyed
  fingerprints or hashes and the minimum virtual-account metadata required to
  continue a decoy workflow.
- The optional OAuth broker returns only provider, stable subject HMAC, scopes
  and completion time to the application. It does not return raw provider IDs,
  email addresses, handles, passwords or tokens. The broker config contains
  client credentials and must be protected as a secret.
- SQLite WAL is the default authority. PostgreSQL is an alternative authority
  for a new single-node deployment. SQLite `events.jsonl` and `state.json` are
  bounded compatibility mirrors; PostgreSQL does not read or write those
  mirrors. Imported events include source/schema/file/offset/hash provenance so
  local imported data can be audited.
- Import-source declarations contain only an installation-owned alias and
  allowlisted schema/product metadata. The admin API cannot use that alias to
  browse a host path; the explicit local `hpctl import` command performs the
  bounded read. Transient indicator export jobs expire after 15 minutes and are
  not copied into the event store.

Public source IP enrichment uses the local MaxMind GeoLite2 City and ASN
databases by default, or the local IPinfo Location and ASN MMDB databases when
that provider is selected. The readers are opened from the owner-selected
runtime paths and reused locally; the database files and their full paths are
not returned by the admin API. Local, private, link-local, multicast,
unspecified and documentation addresses are classified without any provider
lookup.
Missing files, missing records and lookup errors fall back to `未知` or the
deterministic local label.

The operator can explicitly switch the provider in Settings to IPinfo API or
IPinfo Lite. Only then may public source IPs be sent to IPinfo for
country/continent/ASN enrichment. The raw token is kept in the owner-readable
runtime config and is never returned by the admin API; the response exposes
only a masked suffix and bounded status metadata. See the [MaxMind GeoLite2 documentation](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/),
the [GeoIP2 Go reader documentation](https://github.com/oschwald/geoip2-golang),
the [IPinfo database documentation](https://ipinfo.io/developers/database-download),
the [IPinfo geolocation database documentation](https://ipinfo.io/developers/ip-to-geolocation-database)
and the [IPinfo Lite API documentation](https://ipinfo.io/developers/lite-api)
for provider details.

## Retention and deletion

Event retention defaults to 30 days and 100,000 rows. Configure
`event_retention_days` and `event_max_entries`, or the equivalent
`HP_EVENT_RETENTION_DAYS` and `HP_EVENT_MAX_ENTRIES` environment variables.
Pruning removes expired/over-limit event rows and imported provenance in the
selected backend; the SQLite event mirror is rewritten from retained rows.
Management-page deletion is logical: an `event_tombstones` row hides an event
from active and derived views while leaving the append-only event row intact.
The deletion action is recorded in the append-only audit hash chain, and the
event can be restored by an operator recovery tool.

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
support bundles or issue reports. Backups also contain owner/admin-visible raw
request evidence and must be protected like secrets; the standalone backup
command intentionally excludes the secrets directory.

## Operator responsibilities

Publish the deployment's notice, purpose, retention period, contact and lawful
basis as required by the applicable jurisdiction. Restrict the admin port at
the host firewall/VPN layer, review exports before sharing them, and destroy
runtime data and OAuth credentials when the collection purpose ends.
