# Security boundary

AegisLure is intended for an isolated honeynet, never a production VPC. The
public decoy handlers do not fetch user-supplied URLs or make general outbound
requests. When the operator selects an IPinfo API provider, the Compose
`edge_net` permits the built-in provider client to make HTTPS lookups; restrict
that network's destinations with the host firewall where possible. The
process must not be given Docker socket, host networking, host PID, GPU, cloud
credentials or production routes.

## Report

Do not send live exploit payloads or credentials in an issue. Report a suspected isolation bug privately to the deployment owner, including the commit, profile, route, safe reproduction shape and whether an outbound connection, file write, process spawn or secret disclosure was observed.

## Non-goals

The project deliberately does not execute attacker-controlled code, shell,
templates, SQL, WASM, pickle/torch loading, FFmpeg, archive extraction, model
loading, DNS resolution or attacker-controlled remote URL fetching. The
application egress exceptions are limited to the operator-selected IPinfo
provider lookup and the optional OAuth broker's fixed official endpoints. A
failure of this boundary is a release-blocking security bug.

## Deployment requirements

Use a separate VPS/VPC/security group, enable HTTPS for the admin gateway, set a strong owner password, restrict the management port at the host/firewall layer, and treat all IP and identity output as security telemetry subject to local privacy and retention requirements. This deployment intentionally disables Bootstrap code and TOTP/MFA at the operator's request; the hidden path is not an authentication factor.
