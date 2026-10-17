# ADR-0004: Nginx to Uvicorn over a Unix domain socket

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V12.3.3, V13.2.2, V15.3.4, V4.1.3

## Context
ASVS L2 requires encrypted transport between internal HTTP services. Nginx and Uvicorn run in the same container.

## Options considered
1. **TCP on 127.0.0.1 with TLS** — needs extra certificates for a loopback hop.
2. **TCP on 127.0.0.1 without TLS** — a plaintext network hop; harder to defend in a review.
3. **Unix domain socket** — no network transport at all; access controlled by file permissions.

## Decision
Uvicorn listens only on `unix:/run/app/uvicorn.sock` (tmpfs, mode 0660, group shared by nginx and app user). Nginx proxies to it. Nginx overwrites `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-Proto`; the app trusts these headers only from the socket and ignores client-supplied values. The builder must verify the exact Uvicorn proxy-header trust settings for UDS and add a test proving a client-supplied `X-Forwarded-For` cannot change the IP the app logs or rate-limits on.

## Security impact
Removes an internal network endpoint (no SSRF/port-scan target). Supports V12.3.3 by eliminating network transport between these components, and V15.3.4 by establishing a trusted source for the client IP.

## Consequences
Health checks must use the socket (e.g. `curl --unix-socket`) or go through Nginx.
