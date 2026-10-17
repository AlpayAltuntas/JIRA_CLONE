# ADR-0007: Mandatory MFA (TOTP or WebAuthn) with recovery codes

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator (required by ASVS L2); user confirmed on 2026-10-17: authenticator-app TOTP with HMAC-SHA-256 (no SHA-1 fallback, no SMS/email codes)
- **Related:** ASVS V6.3.3, V6.4.4, V6.5.1–V6.5.5, V11.4.1, Appendix C; ADR-0022

## Context
ASVS 5.0.0 V6.3.3 (L2) requires multi-factor authentication, or a combination of single-factor mechanisms, to access the application. ASVS Appendix C rates HMAC-SHA-1 as **Legacy** ("should not be used in applications… not considered a vulnerability in itself") and HMAC-SHA-256 as **Approved**. Classic TOTP authenticator apps default to SHA-1.

## Options considered
1. **Optional MFA** — fails V6.3.3.
2. **TOTP only (SHA-1)** — widest app support, but uses a Legacy primitive.
3. **TOTP (SHA-256 default) + WebAuthn passkeys + recovery codes** — Approved primitives; phishing-resistant option.

## Decision
Every account must enroll a second factor before any non-MFA endpoint becomes reachable. Supported factors:
- **TOTP** (RFC 6238): 160-bit seed from a CSPRNG, HMAC-SHA-256, 6 digits, 30-second step, seed encrypted with AES-256-GCM (ADR-0010). **Each code is accepted for exactly one 30-second step** (V6.5.5 sets a 30 s maximum lifetime), and each step can be used once (`last_used_step`, V6.5.1). Clock drift is handled with RFC 6238 §6 resynchronization rather than a wider acceptance window: at enrollment confirmation the server searches ±2 steps for the code, stores the matching offset (`drift_steps`) for that authenticator, and from then on accepts only the single step at `now + drift_steps`. If a user's clock drifts later, they re-sync with two consecutive codes (accepted only within the ±2 search window, then the new offset is stored) or log in with a recovery code or WebAuthn. The enrollment UI lists authenticator apps known to support SHA-256; the builder must verify that list before publishing it.
- **WebAuthn** passkeys/security keys via `py_webauthn`, user verification preferred, RP ID = `APP_HOST`.
- **Recovery codes:** 10 codes, each ≥ 112 bits of entropy (e.g. 20 base32 characters), hashed with Argon2id, single-use, regenerable after step-up.
MFA verification attempts are throttled (5 failures per session → session revoked; per-account backoff). There is no SHA-1 option in v1 (user decision): the TOTP algorithm is fixed to SHA-256, not configurable. Adding SHA-1 later requires a new ADR accepting the Legacy primitive. SMS and email codes are not offered (ASVS V6.6 stays N/A).

## Security impact
Satisfies V6.3.3 and the V6.5 family. WebAuthn mitigates phishing (T-003). MFA-reset abuse is covered in ADR-0022.

## Consequences
More onboarding friction; mitigated by passkeys. E2E tests need a TOTP helper and a virtual WebAuthn authenticator (Playwright supports this via CDP).
