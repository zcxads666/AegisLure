# Change log

## 2026-08-30 — Ollama/vLLM protocol persona hardening

- Removed the public `hp_session` cookie; public visitor correlation remains server-side by bounded IP, product and User-Agent fingerprints.
- Split Ollama native/OpenAI-compatible rendering from vLLM ModelCard/OpenAI rendering. Public responses no longer serialize the internal catalog shape.
- Added deterministic, per-model Ollama metadata with architecture/family, parameter size, quantization, digest, size and distinct modification time; `/api/ps` now follows recent model use with an expiry.
- Added stable vLLM ModelCards, consistent Uvicorn headers, FastAPI-style errors, docs/OpenAPI routes and a coherent Prometheus metric set with request counters.
- Removed internal marker fields and strings from public product responses, including model lifecycle, LocalAI, SGLang and New API user-facing paths; internal event names remain available to analysis.
- Added `scripts/check-ai.ps1` and Go regression tests for anti-leak responses, persona separation, model metadata, errors, headers, state and metrics.

## 2026-08-30 — Admin frontend repair

- Removed the nested full-document wrapper around the admin page so browser layout and script parsing remain standards-compliant.
- Added a local-first font stack with Chinese fallbacks, responsive grid breakpoints, mobile card sizing and visible keyboard focus states.
- Made decorative layers ignore pointer input and raised button interaction layers so setup, login, refresh and logout controls remain clickable.

## 2026-08-30 — Admin console usability profile

- Replaced the previous Bootstrap-code and TOTP/MFA setup flow with direct first-owner creation.
- Lowered the administrator password minimum to 8 characters (maximum remains 128).
- Removed TOTP material and verification from the admin state, setup form, login form and recovery flow. Legacy `totp_secret` JSON fields are ignored during state migration.
- Reworked the admin page into a responsive dark control-plane UI with setup, login and overview states.
- Added explicit `setup/status` and `setup/create-owner` endpoints; removed the `admin bootstrap issue` CLI flow.
- Recorded the security trade-off: the management port must be restricted to a trusted network or VPN because the hidden path is only a locator.
