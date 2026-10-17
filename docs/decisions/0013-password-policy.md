# ADR-0013: Password policy and breached-password checks

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V6.1.2, V6.2.1–V6.2.12, V11.4.2

## Decision
- Length 15–128 characters (ASVS minimum is 8, with 15 strongly recommended; L2 requires at least 64 to be allowed). Counted in Unicode code points after NFC normalization; no other transformation, truncation or case folding (V6.2.8).
- No composition rules (V6.2.5); paste and password managers allowed (V6.2.7); no periodic rotation (V6.2.10); no hints or security questions (V6.4.2).
- Rejected if the password: appears in the bundled breached/common list; contains a context-specific word (list in `docs/security/security-requirements.md` §3, V6.1.2/V6.2.11); or contains the user's email local part or display name.
- Breached list: an offline file built from a pinned, checksummed public breach corpus (e.g. a SecLists "Pwdb"/top-millions list). The file keeps the most common entries **that satisfy the length policy (≥ 15 characters)** and must contain at least 3,000 of them (the V6.2.4 floor), with a target of ≥ 100,000. A candidate password is rejected on a case-insensitive exact match. The build script, source URL, source checksum and resulting entry count are recorded in `backend/app/core/security/data/README.md`. This satisfies V6.2.4 and V6.2.12 without sending data to a third party. An optional Have I Been Pwned k-anonymity check (`HIBP_ENABLED=false` by default) can be enabled by operators; it needs an outbound allowlist entry (V13.2.4).
- Stored with Argon2id (ADR-0010); rehash on login if parameters changed.
- Password change requires the current password and a fresh step-up (V6.2.3, V7.5.1).

## Security impact
Mitigates credential stuffing and guessing (T-001, T-002) together with MFA and throttling (ADR-0024).

## Consequences
The frontend shows a strength meter (e.g. zxcvbn-ts) for guidance only; the server is authoritative.
