# Security boundary

AegisLure is intended for an isolated honeynet, never a production VPC. The decoy process has no general outbound network capability and must not be given Docker socket, host networking, host PID, GPU, cloud credentials or production routes.

## Report

Do not send live exploit payloads or credentials in an issue. Report a suspected isolation bug privately to the deployment owner, including the commit, profile, route, safe reproduction shape and whether an outbound connection, file write, process spawn or secret disclosure was observed.

## Non-goals

The project deliberately does not execute attacker-controlled code, shell, templates, SQL, WASM, pickle/torch loading, FFmpeg, archive extraction, model loading, DNS resolution or remote URL fetching. A failure of this boundary is a release-blocking security bug.

## Deployment requirements

Use a separate VPS/VPC/security group, enable HTTPS for the admin gateway, set a strong owner password, restrict the management port at the host/firewall layer, and treat all IP and identity output as security telemetry subject to local privacy and retention requirements. This deployment intentionally disables Bootstrap code and TOTP/MFA at the operator's request; the hidden path is not an authentication factor.
