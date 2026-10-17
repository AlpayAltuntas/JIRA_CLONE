# ADR-0009: CSRF defense in depth

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V3.3.2, V3.5.1–V3.5.3, V4.4.2; ADR-0006

## Context
Cookie-based sessions need protection against cross-site request forgery.

## Decision
Three independent layers:
1. Session cookie `SameSite=Strict`.
2. Double-submit token: `GET /auth/csrf` sets `__Host-csrf` (Secure, not HttpOnly, SameSite=Strict, 256-bit random); the SPA sends it as `X-CSRF-Token` on POST/PUT/PATCH/DELETE; the server compares in constant time and binds the token to the session (HMAC of the session ID).
3. `Origin` (falling back to `Referer`) must match `https://APP_HOST[:port]` on every unsafe request and on the WebSocket handshake.
No state-changing GET endpoints. CORS is not enabled (same-origin only); no `Access-Control-Allow-Origin` header is ever emitted.

## Security impact
Mitigates T-010 (CSRF) and cross-site WebSocket hijacking (T-011).

## Consequences
The API client attaches the header automatically; integration tests cover a missing token, a wrong token, and a foreign Origin.
