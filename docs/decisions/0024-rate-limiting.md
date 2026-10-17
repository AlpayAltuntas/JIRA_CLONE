# ADR-0024: Rate limiting and anti-automation without Redis

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V6.1.1, V6.3.1, V2.4.1, V15.1.3, V15.2.2; threats T-001, T-070

## Decision
Two layers, no extra container:
1. **Nginx (per IP, shared memory across workers):** `/api/v1/auth/*` 10 requests/min with burst 10; all `/api/` 300 requests/min with burst 100; `limit_conn` 50 per IP. Excess → 429.
2. **Application (per account/user, PostgreSQL-backed):**
   - Login: after 5 failures for an account within 15 minutes, exponential backoff (1, 2, 4… minutes, max 30) applied to that account regardless of IP; the response is identical to a wrong password (no enumeration, no hard lockout that an attacker could use to lock out users). Per-IP failures across accounts (credential stuffing) trigger the `alert.credential_stuffing` event.
   - MFA: 5 failed codes → `mfa_pending` session revoked; 10 failures/hour per account → backoff + alert.
   - Writes: 120 mutations/min per user; issue creation 30/min; comments 30/min; uploads 20/min and 200 MB/hour per user.
   - Search/JQL: 60 queries/min per user.
   - Argon2 hashing concurrency is capped by a per-worker semaphore so login floods cannot exhaust memory.
   Counters use fixed windows in an `UNLOGGED` table with periodic cleanup (acceptable to lose on DB crash).
The resource-intensive features list and their limits are documented in `docs/security/security-requirements.md` §7 (V15.1.3).

## Security impact
Mitigates brute force, credential stuffing, scraping/exfiltration and resource-exhaustion attacks.

## Consequences
Limits are configurable; E2E tests use a test-only config with higher limits (refused when `APP_ENV=production`).
