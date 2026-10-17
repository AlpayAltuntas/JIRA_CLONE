# ADR-0010: TLS everywhere, internal CA, and cryptographic choices

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V11.1–V11.6, V12.1.1–V12.1.3, V12.2.1, V12.2.2, V12.3.1–V12.3.4, V13.2.1, V3.4.1; Appendix C

## Context
ASVS L2 requires TLS for all inbound and outbound connections, including databases and management tools (V12.3.1), with trusted certificates or a pinned internal CA (V12.3.4), and only Approved crypto (Appendix C rates AES-128 and HMAC-SHA-1 as Legacy).

## Decision
**Transport**
- External: Nginx TLS 1.2 + 1.3 (1.3 preferred), Mozilla "intermediate" cipher suites (all with forward secrecy), HSTS `max-age=31536000; includeSubDomains`. Production must use publicly trusted certificates (V12.2.2) — operator requirement, documented in the README and the security review; development uses the internal CA.
- Internal: `make certs` creates a project CA (ECDSA P-256, SHA-256, 5-year validity, name-constrained to the configured hostnames) and leaf certificates (≤ 397 days) for `APP_HOST`, `PGADMIN_HOST`, `db`, `pgadmin`. App → Postgres: `sslmode=verify-full` with the CA, plus a client certificate (mTLS, ADR-0012). pgAdmin → Postgres: `verify-full` plus a client certificate for `jira_readonly`. Client certificates: ECDSA P-256, 90-day lifetime. Nginx → pgAdmin: TLS with `proxy_ssl_verify on`. Postgres `ssl_min_protocol_version = 'TLSv1.3'`. Nginx → Uvicorn uses a Unix socket (ADR-0004).
**Primitives** (all through `cryptography`, `argon2-cffi`, Python `secrets`, Web Crypto — never hand-rolled)
- Random: `secrets` module (OS CSPRNG); every token ≥ 128 bits, session tokens 256 bits.
- Password hashing: Argon2id m=64 MiB, t=3, p=4 (stronger than the Appendix C minimum m=46 MiB, t=1, p=1).
- Field encryption: AES-256-GCM with a 96-bit random nonce per encryption, associated data = table+column+row ID, ciphertext prefixed with a key ID to allow rotation (crypto agility, V11.2.2).
- Token hashing: SHA-256. MACs: HMAC-SHA-256. TOTP: HMAC-SHA-256 (ADR-0007).
- Disallowed: MD5, SHA-1 (except where a protocol requires it and only with an ADR), AES-ECB, AES-CBC without MAC, RSA PKCS#1 v1.5 encryption, AES-128 for new data.
The cryptographic inventory and key lifecycle live in `docs/security/security-requirements.md` §9 (V11.1.1, V11.1.2).

## Security impact
Mitigates eavesdropping and MITM on every link (T-020, T-021, T-042); protects secrets at rest if the DB is dumped (T-024).

## Consequences
Users must trust the internal CA locally, or use public certificates. Certificate expiry is checked at startup, and a warning is logged 30 days before expiry.
