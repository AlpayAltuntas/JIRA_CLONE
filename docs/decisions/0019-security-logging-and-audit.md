# ADR-0019: Security logging and append-only audit log

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V16.1.1, V16.2.1–V16.2.5, V16.3.1–V16.3.4, V16.4.1–V16.4.3, V16.5.x; OWASP A09:2025

## Context
ASVS V16.4.3 (L2) requires logs to be sent to a logically separate system so a breach doesn't compromise them. The runtime is limited to three containers.

## Decision
- **Application log:** structured JSON to stdout/stderr from Uvicorn and Nginx: UTC ISO-8601 timestamp, level, event name, request ID, user ID, session ID hash (first 16 hex characters), client IP, method, route template (not the raw URL with IDs), status, latency. Values are JSON-encoded (prevents log injection, V16.4.1). A redaction filter drops passwords, tokens, cookies, `Authorization`, CSRF tokens, TOTP codes, recovery codes and secret file contents (V16.2.5).
- **Security event catalogue:** fixed event names listed in `docs/security/security-requirements.md` §10 (auth success/failure, MFA events, session lifecycle, authz denied, CSRF/Origin failure, rate-limit hit, validation-bypass attempts, admin actions, configuration changes, unexpected errors, TLS/DB connection failures).
- **Audit log table:** every security event and admin action is also written to `audit_log` (append-only by grants and trigger, ADR-0012), with a hash chain (`row_hash = SHA-256(prev_hash || canonical_json(row))`). A verification command (`make audit-verify`) detects tampering. Admins can view it in the UI (read-only).
- **Alerting:** threshold detectors in the app emit `severity=high` `alert.*` events (e.g. ≥ 20 failed logins/min from one IP, ≥ 5 MFA failures for one account, ≥ 10 authz denials/min for one user, audit-chain verification failure).
- **Separate system (V16.4.3):** containers log through the Docker logging driver, which runs outside the containers. The reference config uses `json-file` with rotation; `compose.yaml` documents switching to `syslog`/`fluentd`/`gelf` pointed at an external collector via `LOG_DRIVER`/`LOG_OPTS`. Forwarding to an external collector is an **operator deployment requirement** for full V16.4.3 compliance, verified in the reference deployment by sending to a local syslog listener, and stated in the security review.
- Time: containers use the host clock (NTP-synchronized on the host — operator requirement, V16.2.2); everything logged in UTC.

## Security impact
Supports detection of attacks (A09), forensic timelines, and integrity of audit evidence.

## Consequences
The log inventory (V16.1.1) is kept in `docs/security/security-requirements.md` §10.
