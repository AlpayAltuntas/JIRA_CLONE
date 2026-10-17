# ADR-0012: Least-privilege database roles

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V13.2.1, V13.2.2, V13.2.3, V12.1.3, V16.4.2, V15.2.2

## Context
If the application is compromised, its DB credentials should allow as little as possible, and audit records must not be modifiable by the app (V16.4.2).

## Decision
| Role | Login | Privileges | Used by |
|---|---|---|---|
| `postgres` | yes (break-glass) | superuser | nobody day to day; password in a secret file |
| `jira_owner` | yes | owns schema `jira`; DDL | Alembic at container start only |
| `jira_app` | yes | SELECT/INSERT/UPDATE/DELETE on app tables; INSERT + SELECT only on `audit_log`; USAGE on sequences; no DDL; `statement_timeout=5s`; `idle_in_transaction_session_timeout=30s`; connection limit sized to workers × pool | runtime API |
| `jira_readonly` | yes | SELECT on app tables except secret columns (`password_hash`, `mfa_totp.secret_ciphertext`, `sessions.token_hash`, `one_time_tokens.token_hash`, `mfa_recovery_codes.code_hash`) through column-level grants | pgAdmin default connection |
**Authentication (V13.2.1, V12.1.3):** ASVS L2 rules out relying on unchanging credentials such as passwords alone between backend components. Service roles (`jira_owner`, `jira_app`, `jira_readonly`) therefore authenticate with **both** a client certificate issued by the internal CA (CN = role name; `pg_hba.conf` method `scram-sha-256 clientcert=verify-full`, which requires the certificate CN to match the role) **and** a SCRAM-SHA-256 password. Client certificates have a 90-day lifetime and are rotated with `make certs-rotate-clients`. `postgres` (break-glass) is allowed only via local socket inside the db container. Every connection uses `hostssl`; `host` (non-TLS) entries don't exist. A trigger on `audit_log` rejects UPDATE, DELETE and TRUNCATE for everyone except the break-glass superuser. `PUBLIC` privileges on schema `public` and database are revoked.

## Security impact
Limits SQL-injection and app-compromise blast radius (T-022, T-023); protects log integrity (T-050).

## Consequences
Migrations must include grants for every new table; a test asserts `jira_app` privileges match the expected set.
