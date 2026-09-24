<p align="center"><a href="README.md">简体中文</a> | <strong>English</strong></p>

<h1 align="center"><img src="docs/images/logo.png" alt="AegisLure" width="220"></h1>

<p align="center"><strong>AI/LLM Honeypot & IP Threat Intelligence Platform</strong></p>

<p align="center">
  <a href="https://github.com/zcxads666/AegisLure/actions/workflows/ci.yml"><img src="https://github.com/zcxads666/AegisLure/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Go-1.25.0-00ADD8?logo=go" alt="Go 1.25.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT License"></a>
</p>

<p align="center">
  Protocol-compatible honeypot endpoints for New API, vLLM, Ollama, SGLang, LocalAI, and Sub2API. Records access, authentication, usage behavior, and risk events.
</p>

<p align="center"><em>All responses are synthetic. AegisLure does not connect to real model providers, run real inference, or forward content submitted by visitors.</em></p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#dashboard-preview">Dashboard Preview</a> ·
  <a href="#network-ports">Network Ports</a> ·
  <a href="#ip-list-api">IP List API</a> ·
  <a href="docs/OPERATIONS.md">Operations</a>
</p>

<h2 align="center" id="dashboard-preview">Dashboard Preview</h2>

<p align="center">
  <img src="docs/images/dashboard-overview.png" alt="AegisLure admin dashboard overview" width="100%">
</p>

<p align="center"><sub>Admin overview with observations, risk trends, and IP origin regions.</sub></p>

<h2 align="center" id="core-capabilities">Core Capabilities</h2>

- **Multi-protocol honeypots:** Six AI/LLM protocol-compatible endpoints with simulated model catalogs.
- **Full admin interface:** New API-style home, sign-in, sign-up, model, key, usage, and call-log pages, plus dashboards for observations, call analytics, interaction chains, IP intelligence, honeypot instances, rules, and system settings.
- **Rules and identity policies:** View and manage rules, regular-expression conditions, identity policies, OAuth channels, and risk levels.
- **Simulated sign-in flows:** GitHub, LinuxDO, and Discord sign-in/sign-up entry points, plus Sub2API's existing GitHub, LinuxDO, Google, WeChat, OIDC, and DingTalk entry points, shown according to the corresponding official login or registration pages. All flows are local simulations and can be enabled or disabled by identity policy.
- **IP risk intelligence:** Local and reserved addresses are classified locally. Public IP addresses are looked up through the IPinfo API; lookup failures fall back to “Unknown”.
- **Audit and export:** Risk events, audit records, and IP/identity metrics, with JSON/CSV/plain/STIX2/nftables exports and bounded retention.
- **Flexible deployment:** SQLite by default, with PostgreSQL also supported. Both modes load the default rules and model catalog automatically.

<h2 align="center" id="quick-start">One-Command Docker Deployment</h2>

The only prerequisites are Docker Engine on Linux or Docker Desktop on macOS, with Docker Compose v2 enabled. Supported platforms include `linux/amd64`, `linux/arm64`, and Apple Silicon. The installer also checks that the Docker daemon, Compose, and OpenSSL are available.

<p align="center"><strong>SQLite (default; suitable for a single host)</strong></p>

~~~bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | bash -s -- --mode sqlite
~~~

<p align="center"><strong>Bundled PostgreSQL (database port is not exposed on the host)</strong></p>

~~~bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | bash -s -- --mode postgres
~~~

By default, the command downloads the GitHub `main` source, builds it with local Docker, and installs it into `aegislure/` under the current directory. To choose an install directory or public hostname/IP:

~~~bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | \
  bash -s -- --mode postgres --dir /opt/aegislure --public-host aegis.example.com
~~~

After installation, the script confirms that the container is healthy and the database connection works, then prints:

- The local admin URL.
- The public admin URL, detected automatically or set with `--public-host`.
- The first-run setup prompt. The admin username is prefilled as `owner`; set a password of at least 8 characters in the browser.
- The SHA-256 fingerprint of the admin self-signed TLS certificate.

After confirming the final status, if this run built a local image, the installer removes only Docker builder cache records that were created by this build and did not exist beforehand. It skips cache cleanup if it cannot read the cache snapshot. The installer does not remove pre-existing `.tools` Go caches, images, containers, runtime data, database volumes, or Docker caches belonging to other projects.

On first visit, the browser warns that the certificate is self-signed. Verify the fingerprint printed by the installer before continuing. The recovery code is shown only once after creating the owner account; save it offline immediately. The installer does not generate, save, or print the admin password.

To use a fixed Release image, replace `--version main` with a version number or `latest`:

~~~bash
curl -fsSL https://raw.githubusercontent.com/zcxads666/AegisLure/main/install-remote.sh | \
  bash -s -- --mode sqlite --version latest
~~~

`latest` and fixed versions verify the Release archive SHA-256 and use the immutable GHCR image digest in the manifest. `main` deploys the current source and is useful for trying the latest code; for production, prefer a fixed version after a release is published.

If you have already cloned the source, you can install it directly:

~~~bash
./install.sh --mode sqlite
# or
./install.sh --mode postgres --public-host 203.0.113.10
~~~

Check status and health:

~~~bash
cd aegislure
./hpctl status
./hpctl health
~~~

Remove a deployment (this deletes local runtime data, recovery codes, TLS certificates, and the bundled PostgreSQL data volume; an external PostgreSQL database is not affected):

~~~bash
INSTALL_DIR=/path/to/aegislure
(
  cd "$INSTALL_DIR"
  docker compose -f docker-compose.yml -f docker-compose.pg.yml --profile bundled-pg down --remove-orphans --volumes
)
rm -rf "$INSTALL_DIR"
~~~

<h2 align="center" id="network-ports">Network Ports</h2>

Docker enables five public profiles by default and uses the standard project ports. LocalAI and Sub2API are mutually exclusive; Sub2API is enabled by default:

| Service | Port |
| --- | ---: |
| New API | 3000 |
| vLLM | 8000 |
| Ollama | 11434 |
| SGLang | 30000 |
| LocalAI (optional) | 8081 |
| Sub2API | 8080 |

The admin endpoint uses the high port specified by `HP_ADMIN_PORT` and binds to `0.0.0.0` by default for remote access. Public honeypot ports also bind to `0.0.0.0` by default. Configure the bind addresses in `.env` if needed:

~~~env
HP_PROFILES=new-api,vllm,ollama,sglang,sub2api
HP_PUBLIC_PORT_BIND_IP=0.0.0.0
HP_ADMIN_PORT_BIND_IP=0.0.0.0
~~~

To run LocalAI, replace `sub2api` with `localai` in `HP_PROFILES`. If both are selected, the service keeps Sub2API.

The admin path is generated randomly and can be found with `./hpctl status`. One-command installation prints the full URL, including this hidden path. On first access, create the owner account; the username is prefilled as `owner`, and you choose the password. Save the recovery code offline, and restrict access to the admin port with a firewall, VPN, or trusted reverse proxy. For local-only access, set `HP_ADMIN_PORT_BIND_IP` to `127.0.0.1`.

On a VPS, allow at least the reported `HP_ADMIN_PORT`; open public honeypot ports only if needed. DNS, cloud security groups, firewalls, and NAT are outside the Docker host, so the installer prints URLs but does not modify those systems. If the automatically detected public IP is not suitable, rerun the installer with `--public-host`.

<h2 align="center" id="ip-list-api">IP List API</h2>

The admin console can expose a read-only IP risk list API at `/api` under the current hidden admin path. The API is disabled by default. When enabled, it returns only IP metrics already aggregated locally and does not contact real models or upstream services.

### Configure the admin console and API key

In the admin console, open **Admin Settings → IP List API**:

- Use the toggle to enable or disable the API. Requests return `404` while it is disabled.
- The page shows the API URL, HTTP method, and authentication method.
- Enabling the API for the first time generates an API key. You can also rotate the key; the old key becomes invalid immediately.
- The full key is returned only in the create or rotate response. After a page refresh, only a masked prefix is shown. Save the key as soon as it is returned.
- The service stores only a one-way fingerprint of the key, never the full key.
- Enabling/disabling the API and rotating the key are not public API operations; they are available only in the admin console. For changes, the server requires a browser `Origin` matching the current admin URL and a page token. Direct commands, missing page tokens, and cross-site requests return `403`.

`{ADMIN_BASE}` is the full URL of the current admin console, for example `https://admin.example.com/<random-admin-path>`.

### Query the API

~~~text
GET {ADMIN_BASE}/api
~~~

Two equivalent authentication methods are supported. Bearer authentication is recommended:

~~~bash
curl -fsS \
  -H 'Authorization: Bearer <API_KEY>' \
  '{ADMIN_BASE}/api'

# or
curl -fsS \
  -H 'X-API-Key: <API_KEY>' \
  '{ADMIN_BASE}/api'
~~~

Query parameters:

| Parameter | Type | Allowed values | Description |
| --- | --- | --- | --- |
| `days` | Integer | `1`–`3650` | Query the last N days; mutually exclusive with `month`. |
| `month` | String | `YYYY-MM` | Query a calendar month, for example `2026-09`; mutually exclusive with `days` and parsed in `Asia/Shanghai`. |
| `risk_level` | String | `all`, `low`, `medium`, `high` | Risk filter; defaults to `all`. |
| `risk` | String | `all`, `low`, `medium`, `high` | Compatibility alias for `risk_level`; `risk_level` takes precedence if both are provided. |

Without filter parameters, the API returns all IPs. Risk levels are based on the metric score: `low` is `0–29`, `medium` is `30–59`, and `high` is `60` or above (the current score range is `0–100`).

Examples:

~~~bash
# All IPs
curl -fsS -H 'Authorization: Bearer <API_KEY>' \
  '{ADMIN_BASE}/api'

# High-risk IPs from the last 7 days
curl -fsS -H 'Authorization: Bearer <API_KEY>' \
  '{ADMIN_BASE}/api?days=7&risk_level=high'

# Medium-risk IPs in September 2026
curl -fsS -H 'X-API-Key: <API_KEY>' \
  '{ADMIN_BASE}/api?month=2026-09&risk=medium'
~~~

`days` and `month` cannot be used together. `days` must be between `1` and `3650`; `month` must be a valid `YYYY-MM`. The API allows 60 requests per minute per source IP and returns `Retry-After: 60` when rate-limited.

### Response format

The response is JSON. The `items` array contains one aggregated metric per IP:

~~~json
{
  "schema_version": 1,
  "success": true,
  "generated_at": "2026-09-22T08:00:00Z",
  "timezone": "Asia/Shanghai",
  "filters": {
    "days": 7,
    "risk": "high",
    "start_at": "2026-09-15T00:00:00Z",
    "end_at": "2026-09-22T00:00:00Z"
  },
  "count": 1,
  "items": [
    {
      "id": "indicator-id",
      "ip": "203.0.113.10",
      "score": 80,
      "risk_level": "high",
      "confidence": "high",
      "first_seen": "2026-09-20T12:00:00Z",
      "last_seen": "2026-09-22T07:30:00Z",
      "expires_at": "2026-10-22T07:30:00Z",
      "reason_codes": ["example_reason"],
      "products": ["new-api"],
      "sensor_count": 1,
      "site_count": 1,
      "recommended_action": "observe",
      "evidence_count": 3,
      "associated": false,
      "associated_ips": null,
      "association_reasons": null
    }
  ]
}
~~~

Field reference: `count` is the number of returned items; `score` is the risk score; `first_seen`, `last_seen`, and `expires_at` are RFC 3339 timestamps; `reason_codes` lists the reasons; `products` lists the observed service types; `evidence_count` is the evidence count; `associated`, `associated_ips`, and `association_reasons` describe IP associations.

Common errors: `401` means the key is missing or invalid, `404` means the API is disabled, `400` means a query parameter is invalid, and `429` means the rate limit was reached.

<h2 align="center" id="database-ip-intelligence">Database and IP Intelligence</h2>

SQLite is the default database. PostgreSQL mode uses `docker-compose.pg.yml`; the database port is not published on the host. You can also connect to a managed PostgreSQL database with `HP_DATABASE_URL` or `HP_DATABASE_URL_FILE`.

IP intelligence uses the IPinfo API (City + ASN) only for public IP addresses. Local, reserved, and documentation addresses are classified deterministically on the host and are never sent to IPinfo. When saving an IPinfo key in admin settings, the service first validates it by querying `8.8.8.8`; on failure, it reports the error and keeps the existing configuration. The key is used only by the backend. After a key change, the next dashboard refresh clears the old cache and queries again.

Docker Compose enables masquerading on `edge_net` by default to allow outbound HTTPS requests to the IPinfo API. `bait_net` and `admin_net` remain internal. If the host firewall restricts outbound traffic, allow TCP 443 to `ipinfo.io`.

Backups can only be restored to the same database type. No implicit migration is performed between SQLite and PostgreSQL.

<h2 align="center" id="security-and-data-boundary">Security and Data Boundaries</h2>

- All model responses, quotas, keys, and account data are synthetic.
- No real model inference, tool calls, URL access, redirects, downloads, or upstream forwarding are performed.
- Uploaded content receives bounded classification, hashing, or safe-field extraction; it does not enter dangerous parsing flows.
- Passwords, cookies, `Authorization` headers, verification codes, and tokens are not written in plaintext to event previews. Full restricted raw requests for new events are available only in the authenticated admin console; protect backups as sensitive evidence.
- Risk scores represent observed evidence. They are not proof of real-world identity and do not trigger automatic blocking.

<h2 align="center" id="project-documentation">Project Documentation</h2>

- [Operations](docs/OPERATIONS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Privacy and data lifecycle](docs/PRIVACY.md)
- [Release guide](docs/RELEASE.md)
- [Security policy](SECURITY.md)
- [Third-party notices](NOTICE)

<h2 align="center" id="license">License</h2>

This project is licensed under the MIT License. See [LICENSE](LICENSE) for the full terms.

<h2 align="center" id="friends">Friends</h2>

<p align="center"><a href="https://linux.do/">Linux.Do — A new ideal community</a></p>
