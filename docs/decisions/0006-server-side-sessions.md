# ADR-0006: Server-side opaque sessions instead of JWT

- **Status:** Accepted (replaces the JWT access/refresh design in the first draft of PLAN.md)
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V3.3.1–V3.3.4, V7.2.1–V7.2.4, V7.4.1–V7.4.5, V9 (becomes N/A), ADR-0008, ADR-0009

## Context
ASVS V7.4.1 requires that once a session ends (logout, expiry), it can't be used again; V7.4.2 requires ending all sessions when an account is disabled. Short-lived JWTs stay valid until they expire unless a denylist is added, and JWTs bring algorithm, key-source and audience checks (V9).

## Options considered
1. **JWT access + refresh tokens** — stateless, but revocation needs a denylist (i.e. state anyway) and adds attack surface.
2. **Opaque reference tokens in a server-side session table** — immediate revocation, simpler to verify.

## Decision
On successful authentication the server generates a 256-bit token with `secrets.token_urlsafe(32)`, stores only its SHA-256 hash in `sessions`, and sets cookie `__Host-session` with `Secure; HttpOnly; SameSite=Strict; Path=/` and no `Domain`. The token is only ever sent via `Set-Cookie`, never in a response body or URL. A new token is issued and the old one revoked at login, after MFA verification, and after step-up re-authentication. Each request looks up the session by hash, checks revocation, idle and absolute expiry (ADR-0008), and slides `idle_expires_at`. Sessions have states `mfa_pending` and `active`. The WebSocket handshake uses the same cookie.

## Security impact
Meets V7.2.1–V7.2.4 and V7.4.x directly. No self-contained tokens anywhere in the system, so ASVS V9 is proposed N/A (justification in the verification matrix). An attacker with DB read access can't use stored hashes as tokens.

## Consequences
One indexed DB lookup per request (acceptable at this scale). `last_seen_at` writes are throttled to once per minute per session to limit write load.
