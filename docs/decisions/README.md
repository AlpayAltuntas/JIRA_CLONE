# Decision Log (Architecture Decision Records)

Every significant decision — architecture, technology, security control, accepted risk, ASVS N/A justification,
or deviation from `docs/PLAN.md` — is recorded here as an ADR. ADRs are never deleted or rewritten after acceptance;
a changed decision gets a **new** ADR that supersedes the old one, and the old one's status is updated to point to it.

## How to add a decision
1. Copy `template.md` to `NNNN-short-title.md` using the next free number.
2. Fill in every section. Reference ASVS IDs (e.g. `V7.4.1`) and threat IDs (e.g. `T-012`) where relevant.
3. Add a row to the index below in the same commit.
4. If it changes a mitigation, update `docs/security/threat-model/detailed.md` (and the summary if it is a top threat).

## Decisions that always require an ADR
- Marking an ASVS requirement **N/A** or accepting a finding/risk.
- Adding a dependency that handles security (crypto, auth, parsing, sanitization).
- Changing any value listed in `docs/security/security-requirements.md` (timeouts, limits, algorithms).
- Any deviation from `docs/PLAN.md`.

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record decisions as ADRs | Accepted | 2026-10-17 |
| [0002](0002-technology-stack.md) | Technology stack | Accepted | 2026-10-17 |
| [0003](0003-three-container-topology.md) | Three-container topology with Nginx inside the app container | Accepted | 2026-10-17 |
| [0004](0004-nginx-uvicorn-unix-socket.md) | Nginx to Uvicorn over a Unix domain socket | Accepted | 2026-10-17 |
| [0005](0005-pgadmin-separate-hostname.md) | pgAdmin on a separate hostname behind an IP allowlist | Accepted | 2026-10-17 |
| [0006](0006-server-side-sessions.md) | Server-side opaque sessions instead of JWT | Accepted | 2026-10-17 |
| [0007](0007-mandatory-mfa.md) | Mandatory MFA (TOTP or WebAuthn) with recovery codes | Accepted | 2026-10-17 |
| [0008](0008-session-lifetimes.md) | Session timeouts and concurrency limits | Accepted | 2026-10-17 |
| [0009](0009-csrf-defense.md) | CSRF defense in depth | Accepted | 2026-10-17 |
| [0010](0010-tls-and-cryptography.md) | TLS everywhere, internal CA, and cryptographic choices | Accepted | 2026-10-17 |
| [0011](0011-secrets-management.md) | Secrets management with Compose secrets | Accepted | 2026-10-17 |
| [0012](0012-database-least-privilege.md) | Least-privilege database roles | Accepted | 2026-10-17 |
| [0013](0013-password-policy.md) | Password policy and breached-password checks | Accepted | 2026-10-17 |
| [0014](0014-rich-text-handling.md) | Rich text stored as validated JSON, never raw HTML | Accepted | 2026-10-17 |
| [0015](0015-attachment-handling.md) | Attachment upload, storage and download | Accepted | 2026-10-17 |
| [0016](0016-realtime-websockets.md) | Realtime over WebSockets with LISTEN/NOTIFY | Accepted | 2026-10-17 |
| [0017](0017-fractional-ranking.md) | Fractional-index ranking | Accepted | 2026-10-17 |
| [0018](0018-jql-implementation.md) | JQL subset via a lark grammar with limits | Accepted | 2026-10-17 |
| [0019](0019-security-logging-and-audit.md) | Security logging and append-only audit log | Accepted | 2026-10-17 |
| [0020](0020-security-tooling-containers.md) | Security tools run as ephemeral containers | Accepted | 2026-10-17 |
| [0021](0021-security-standards-baseline.md) | Security standards baseline | Accepted | 2026-10-17 |
| [0022](0022-account-recovery-without-email.md) | Password reset and MFA recovery without email | Accepted | 2026-10-17 |
| [0023](0023-dependency-and-supply-chain-policy.md) | Dependency and supply-chain policy | Accepted | 2026-10-17 |
| [0024](0024-rate-limiting.md) | Rate limiting and anti-automation without Redis | Accepted | 2026-10-17 |
