# Security Requirements and Control Specification

- **Status:** Living document. Changes to any value here require an ADR (see `docs/decisions/README.md`).
- **Scope:** the JIRA clone runtime (app, db, pgadmin containers), its build pipeline, and its operation.
- **Baseline:** OWASP ASVS 5.0.0 L1+L2, OWASP Top 10:2025 (ADR-0021).

Several ASVS requirements are *documentation* requirements: the application must document a policy and
then follow it. Each section below names the ASVS IDs it satisfies. The verification matrix cites this file as
evidence for those rows, and white-box review checks that the code matches it.

---

## 1. Assets and actors (summary)

Full detail is in `threat-model/detailed.md` §1.

| Asset | Why it matters |
|---|---|
| Issue, comment and attachment content | Confidential business information |
| User credentials, MFA secrets, session tokens | Account takeover |
| Authorization data (memberships, roles, site-admin flag) | Privilege escalation |
| Audit log | Detection and forensics; must be tamper-evident |
| Secrets (DB passwords, field-encryption key, TLS keys, setup token) | Full compromise |
| Availability of the service | Teams depend on it |

Actors: anonymous internet user, registered user without project access, project Viewer, Member, Project Admin, Site Admin,
operator (host access), CI/supply chain.

---

## 2. Authentication pathways (V6.1.3, V6.3.4)

These are the **only** ways to obtain an authenticated session. Any other pathway is a defect.

| # | Pathway | Factors | Result |
|---|---|---|---|
| A1 | Login: email + password → second factor (TOTP, WebAuthn, or recovery code) | 2 | `active` session |
| A2 | Initial setup: setup token → create admin → enroll MFA | token + password + MFA | `active` session after enrollment |
| A3 | Invite acceptance: invite token → set password → enroll MFA | token + password + MFA | `active` session after enrollment |
| A4 | Admin-issued password reset: reset token → new password → existing second factor | token + password + MFA | `active` session; all prior sessions revoked |
| A5 | Self-registration (only if `registration_open`): email + password → enroll MFA | password + MFA | `active` session after enrollment |

An `mfa_pending` session (after the password step, or before first enrollment) can only call: MFA verify/enroll endpoints,
`GET /auth/me` (minimal), `POST /auth/logout`. This is enforced centrally and tested by enumerating every route.
There are no API keys, basic auth, "remember me" tokens, or service accounts in v1. The WebSocket uses the same session.

---

## 3. Password policy and context-specific words (V6.1.2, V6.2.x, V6.2.11)

Policy: ADR-0013. Context-specific words: rejected if the password contains any of them (case-insensitive, after removing
spaces and common separators):

```
jira, jiraclone, atlassian, confluence, kanban, scrum, sprint, backlog, epic, storypoint,
admin, administrator, root, superuser, postgres, pgadmin, password, passw0rd, letmein, welcome,
changeme, default, qwerty, 123456, abcdef, <APP_HOST labels>, <project keys and names the user belongs to>,
<user's email local part>, <user's display name tokens ≥ 3 chars>
```

The static part of the list is stored in `backend/app/core/security/data/context_words.txt`; the dynamic parts are
computed per request.

---

## 4. Anti-automation and account recovery (V6.1.1, V6.3.1, V6.4.3, V6.4.4, V2.4.1)

Controls against credential stuffing, brute force and abuse are specified in ADR-0024 (rate limits, backoff, alerts)
and ADR-0007 (MFA throttling). Summary:

| Attack | Control | Response |
|---|---|---|
| Password brute force on one account | Per-account exponential backoff after 5 failures in 15 min | Same generic error; `auth.login.throttled` event |
| Credential stuffing across accounts | Per-IP Nginx limit (10/min on auth), per-IP failure counter | 429; `alert.credential_stuffing` |
| MFA code guessing | 5 failures → pending session revoked; 10/h per account → backoff | `alert.mfa_bruteforce` |
| Account enumeration | Identical responses and similar timing for unknown email vs wrong password; registration returns a generic message | — |
| Scraping/exfiltration | Per-user read and search limits; pagination caps | 429; `alert.excessive_reads` |

**MFA-loss identity proofing procedure** (V6.4.4), performed by a Site Admin other than the user:
1. The user requests reset through a channel other than the app account (e.g. in person, phone number from HR records).
2. The admin verifies identity at least at the level used for enrollment: live video or in-person check against the
   employee record, plus a detail only the real user would know from outside the app (e.g. manager name confirmed by the manager).
3. The admin performs step-up auth, then `POST /admin/users/{id}/mfa-reset` with a mandatory reason that records the
   verification method used.
4. The system revokes all of the user's sessions, deletes their factors and recovery codes, and requires re-enrollment
   at next login. Audit events: `admin.mfa_reset`, `session.revoked_all`.

---

## 5. Authorization rules (V8.1.1, V8.1.2, V8.2.x, V8.3.1, V8.4.1)

Enforced only in `backend/app/services/policy.py`; every route declares its permission; the authorization matrix test
covers every route × role. Projects are treated as isolation boundaries (tenants for V8.4.1).

### 5.1 Function- and data-level rules

| Action | Anon | Authenticated, not member | Viewer | Member | Project Admin | Site Admin |
|---|---|---|---|---|---|---|
| View project, issues, comments, attachments, board, history | — | 404 | ✓ | ✓ | ✓ | ✓ |
| Create/edit issues, transition, move, comment, upload, watch | — | 404 | 403 | ✓ | ✓ | ✓ |
| Edit/delete own comment | — | 404 | — | ✓ (own) | ✓ (any) | ✓ (any) |
| Delete issue, delete any attachment | — | 404 | 403 | 403 | ✓ | ✓ |
| Manage members, workflow, board config, sprints, labels | — | 404 | 403 | 403 | ✓ | ✓ |
| Archive project | — | 404 | 403 | 403 | ✓ | ✓ |
| Create project | — | ✓ (becomes Project Admin) | ✓ | ✓ | ✓ | ✓ |
| User directory search (`GET /users`) | — | only users sharing a project | ✓ same | ✓ same | ✓ same | all |
| Admin endpoints (users, invites, settings, audit log) | — | 403 | 403 | 403 | 403 | ✓ |
| Own profile, password, MFA, sessions | — | ✓ | ✓ | ✓ | ✓ | ✓ |

Additional rules:
- A project must always keep at least one Project Admin; the last one can't be demoted or removed.
- A Site Admin can't remove their own site-admin flag if they are the last one.
- Assignee must be a project Member or Project Admin; mentions must be project members (otherwise stored as plain text).
- Moves and links between issues require write access to **both** issues' projects; cross-project parent links are not allowed.
- Archived projects are read-only for everyone except unarchive by Project Admin or Site Admin.
- Notifications and realtime events are delivered only if the recipient can read the target at delivery time.

### 5.2 Field-level rules (BOPLA, V8.2.3, V15.3.1, V15.3.3)

| Resource | Field | Read | Write |
|---|---|---|---|
| User | `email` | self, Site Admin, and members of shared projects only if the user enabled "show email" (default off) | self (with step-up), Site Admin |
| User | `is_site_admin`, `is_active` | self, Site Admin | Site Admin only |
| User | `password_hash`, MFA data, `failed_login_count`, `locked_until` | never returned by the API | via dedicated flows only |
| Issue | `key`, `number`, `project_id`, `reporter_id`, `created_at`, `rank`, `version` | readers | server-controlled only (rejected if present in input) |
| Issue | `sprint_id` | readers | Members+ (sprint must belong to same project, not closed) |
| Project member | `role` | project members | Project Admin |
| Session | `ip`, `user_agent`, `created_at` | owner, Site Admin | — |

Each resource has separate Pydantic Create/Update/Read schemas with `extra="forbid"`, so unknown or forbidden fields cause a 422.

---

## 6. Input validation rules (V2.1.1, V2.1.2, V2.1.3, V2.2.x, V2.3.x)

All input is validated server-side by Pydantic schemas (positive validation) before reaching services.

| Data item | Rule |
|---|---|
| Email | RFC 5322 syntax via `email-validator` (no DNS lookup); ≤ 254 chars; stored lowercase (citext) |
| Display name | 1–100 chars; Unicode letters, marks, digits, spaces, `.-'_`; no control or bidi-override characters |
| Password | ADR-0013 |
| Project key | `^[A-Z][A-Z0-9]{1,9}$`, unique, immutable after creation |
| Project name | 1–80 chars, trimmed, no control characters |
| Issue summary | 1–255 chars, single line, no control characters |
| Rich text | ADR-0014 schema |
| Label | `^[\p{L}\p{N}_-]{1,50}$`; ≤ 20 labels per issue |
| Story points | decimal 0–1000 in steps of 0.5 |
| Dates | ISO 8601; due date within ±10 years; sprint `end_at > start_at`, duration ≤ 8 weeks |
| Priority, type, status category, role, link type | closed enums |
| IDs | UUID (path/body) or issue key `^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,8}$` |
| Pagination | `limit` 1–100; cursor is an opaque, HMAC-signed value (tampering → 400) |
| JQL | ADR-0018 |
| Files | ADR-0015 |
| Query/body duplicates | Duplicate query parameters for scalar fields → 400 (HTTP parameter pollution, V15.3.7) |

**Combined-data consistency (V2.1.2, V2.2.3):** sub-task parent must be a non-sub-task in the same project; Epic can't have a
parent or sprint; sub-task sprint = parent sprint; status must belong to the issue's project; transition must exist;
assignee must be a member; sprint and issue in the same project; a link can't target the issue itself.

**Business-logic sequences (V2.3.1):** sprint lifecycle `future → active → closed` only; one active sprint per project
(partial unique index + row lock); auth flow steps can't be skipped (session state machine `mfa_pending → active`).
**Transactions (V2.3.3):** every service operation runs in one DB transaction. **Locking (V2.3.4):** issue numbering uses
a row lock on `projects`; sprint start/complete lock the project's sprint rows; optimistic `version` on issues.

**Business limits (V2.1.3, V2.3.2), per user unless stated:**
projects created 10/day; issues per project 100,000; comments per issue 5,000; attachments per issue 100; storage per
project 2 GB; members per project 500; saved filters 100; watchers per issue 500; plus the rate limits in ADR-0024.

---

## 7. Resource-intensive functionality (V15.1.3, V15.2.2)

| Function | Risk | Defense |
|---|---|---|
| Password and recovery-code hashing (Argon2id 64 MiB) | Memory/CPU exhaustion | Per-worker semaphore (max 2 concurrent), auth rate limits |
| JQL and full-text search | Expensive queries | Complexity limits, `statement_timeout`, per-user rate limit |
| Board load with many issues | Large responses | Pagination per column (200 cards, "load more"), indexes |
| Reports (burndown/CFD) | Aggregations | Pre-computed `sprint_snapshots`, date-range cap of 1 year |
| File upload/download | Bandwidth, disk | Size limits, quotas, X-Accel streaming |
| Antivirus scanning (clamd) | CPU/memory, archive bombs | One scan per upload, 30 s timeout, ClamAV `MaxScanSize`/`MaxRecursion`/`MaxFiles` limits, upload rate limits |
| Avatar re-encoding (Pillow) | Decompression bombs | `Image.MAX_IMAGE_PIXELS` = 25 MP, 2 MB input, timeout |
| WebSocket fan-out | Connection exhaustion | Per-session socket cap, message limits, Nginx `limit_conn` |
| Audit-chain verification | Long scan | Admin-only, batched, rate-limited |

---

## 8. File handling policy (V5.1.1)

Specified in ADR-0015: permitted types, extensions, maximum size (25 MB; avatars 2 MB), maximum unpacked size during antivirus
scanning (100 MB total, 25 MB per file, depth 10, 1,000 files), antivirus scanning with fail-closed behavior, behavior on malicious
files (deleted, rejected with a generic 422, `security.upload_rejected` event with the signature name), storage and download handling.

---

## 9. Cryptographic inventory and key management (V11.1.1, V11.1.2, V11.2.2)

### 9.1 Inventory

| Asset | Algorithm / parameters | Location | Purpose | Rotation |
|---|---|---|---|---|
| Public TLS cert/key (`APP_HOST`, `PGADMIN_HOST`) | ECDSA P-256 or RSA ≥ 3072, SHA-256 | `certs/app/` | External HTTPS | Before expiry (≤ 397 days); ACME recommended |
| Internal CA | ECDSA P-256, SHA-256, name-constrained, 5 years | `certs/ca/` (private key kept offline after issuing) | Signs internal certs | 5 years or on compromise |
| Internal leaf certs (`db`, `pgadmin`) | ECDSA P-256, ≤ 397 days | `certs/db/`, `certs/pgadmin/` | Internal TLS | Yearly |
| DB client certs (`jira_owner`, `jira_app`, `jira_readonly`) | ECDSA P-256, 90 days, CN = role | `certs/clients/` (mounted only into the service that uses each) | mTLS DB authentication (V13.2.1) | Every 90 days (`make certs-rotate-clients`) |
| `app_secret_key` | 256-bit random | Compose secret | HMAC for CSRF binding and cursors | Yearly or on compromise (invalidates CSRF tokens and cursors only) |
| `field_encryption_key` | AES-256-GCM key, with key ID | Compose secret (supports multiple IDs) | Encrypts TOTP seeds | Yearly; re-encrypt with `make rotate-field-key` |
| Password hashes | Argon2id m=64 MiB t=3 p=4 | DB `users.password_hash` | Password verification | Rehash on login when parameters change |
| Recovery-code hashes | Argon2id (same parameters) | DB | MFA recovery | On regeneration |
| Session/one-time token hashes | SHA-256 of 256-bit random | DB | Token lookup | Per token lifetime |
| Audit hash chain | SHA-256 | DB `audit_log` | Tamper evidence | n/a |
| DB role passwords | 32+ random characters, SCRAM-SHA-256 | Compose secrets; DB | DB auth | Yearly or on staff change |
| pgAdmin admin password and master password | 32+ random characters | Compose secret / operator | pgAdmin auth | Yearly |
| WebAuthn credentials | Public keys (ES256/RS256/EdDSA as registered) | DB | MFA | User-managed |
| Attachment checksums | SHA-256 | DB | Integrity | n/a |

### 9.2 Key lifecycle (following NIST SP 800-57 principles)
Generation only by `make secrets`/`make certs` using the OS CSPRNG or OpenSSL; distribution only via Compose secrets
and read-only mounts; storage with file mode 600 owned by the consuming service user; use limited to one purpose per key;
rotation as above; on suspected compromise: rotate immediately, revoke all sessions (`make revoke-all-sessions`), rotate
dependent secrets, review the audit log; destruction by `make secrets-destroy` and volume removal. Key IDs allow
algorithm or key replacement without code changes (crypto agility).

---

## 10. Logging inventory and security events (V16.1.1, V16.2.x, V16.3.x)

### 10.1 Log inventory

| Source | Events | Format | Destination | Retention | Access |
|---|---|---|---|---|---|
| Nginx access log | Every request (no query strings for `/api/v1/auth/*`, no cookies or auth headers) | JSON | stdout → Docker logging driver → external collector (operator) | Operator-defined, recommend 90 days | Operators |
| Nginx error log | Proxy/TLS errors | text with JSON escaping | stderr → logging driver | same | Operators |
| Application log | Security events, errors, request summaries | JSON (§10.2 fields) | stdout → logging driver | same | Operators |
| `audit_log` table | Security events + admin actions | DB rows, hash-chained | PostgreSQL (`pgdata` volume) | ≥ 1 year | Site Admins (read-only UI), DBAs |
| PostgreSQL log | Connections, disconnections, auth failures, errors, slow queries (> 1 s, without parameter values) | text | stderr → logging driver | same | Operators |
| pgAdmin log | pgAdmin auth and errors | text | stdout → logging driver | same | Operators |
No other log destinations are permitted (V16.2.3).

### 10.2 Required fields
`ts` (UTC, ISO 8601, ms precision), `level`, `event`, `request_id`, `user_id`, `session` (hash prefix), `ip`, `ua_hash`,
`method`, `route`, `status`, `duration_ms`, `outcome`, `target_type`, `target_id`, `details` (no sensitive values).

### 10.3 Security event catalogue (V16.3.1–V16.3.4)

| Event | Level |
|---|---|
| `auth.login.success` / `auth.login.failure` (reason: bad_credentials, inactive, throttled) | info / warning |
| `auth.mfa.success` / `auth.mfa.failure` / `auth.mfa.enrolled` / `auth.mfa.removed` / `auth.recovery_code.used` | info / warning |
| `auth.password.changed` / `auth.password.reset_link_created` / `auth.password.reset_used` | info |
| `auth.setup.completed` / `auth.setup.token_rejected` / `auth.invite.created` / `auth.invite.accepted` | info / warning |
| `auth.reauth.success` / `auth.reauth.failure` | info / warning |
| `session.created` / `session.rotated` / `session.revoked` (reason) / `session.revoked_all` / `session.expired` | info |
| `authz.denied` (route, permission, target) | warning |
| `security.csrf_failed` / `security.origin_rejected` / `security.ws_origin_rejected` | warning |
| `security.rate_limited` / `security.validation_failed_suspicious` (e.g. forbidden fields, script payloads) | warning |
| `security.upload_rejected` (reason) | warning |
| `admin.user.updated` / `admin.user.deactivated` / `admin.mfa_reset` / `admin.sessions.revoked` / `admin.settings.changed` | notice |
| `project.member.added` / `project.member.role_changed` / `project.member.removed` / `project.deleted` / `project.archived` | info |
| `error.unhandled` (request_id, exception type only) / `error.db_unavailable` / `error.tls` | error |
| `alert.credential_stuffing` / `alert.mfa_bruteforce` / `alert.authz_probe` / `alert.excessive_reads` / `alert.audit_chain_broken` | critical |

---

## 11. Communication inventory and outbound allowlist (V13.1.1, V13.2.4, V13.2.5)

| From | To | Protocol | Auth | Purpose |
|---|---|---|---|---|
| Browser | Nginx (`APP_HOST`) | HTTPS / WSS (TLS 1.2+) | Session cookie | App UI and API |
| Admin browser | Nginx (`PGADMIN_HOST`) | HTTPS | IP allowlist + pgAdmin login | DB administration |
| Nginx | Uvicorn | HTTP over Unix socket | Filesystem permissions | Reverse proxy |
| Nginx | pgAdmin `:8443` | HTTPS (internal CA, verified) | pgAdmin login | Reverse proxy |
| Uvicorn | PostgreSQL `:5432` | PostgreSQL over TLS 1.3, `verify-full` | Client cert + SCRAM (`jira_app`) | Data |
| Entrypoint (Alembic) | PostgreSQL | same | Client cert + SCRAM (`jira_owner`) | Migrations |
| pgAdmin | PostgreSQL | same | Client cert + SCRAM (`jira_readonly`); other roles need explicit credentials | Administration |
| Uvicorn | clamd | ClamAV protocol over Unix socket | Filesystem permissions | Upload scanning |
| freshclam (app container) | `database.clamav.net:443` (ClamAV CDN) | HTTPS; signature files are digitally signed | none | Antivirus signature updates |
| Docker logging driver | External collector | operator-defined (TLS syslog recommended) | operator-defined | Log shipping |
| (optional) Uvicorn | `api.pwnedpasswords.com:443` | HTTPS | none (k-anonymity) | Breached-password check, off by default |

**Outbound allowlist:** the application code makes **no** outbound requests by default. `db` and `pgadmin` are on an
`internal: true` network with no egress. The permitted outbound destinations for the `app` container are the ClamAV signature
mirror (freshclam) and the optional HIBP host above. Operators should enforce this allowlist at the host or network firewall (D9).
The app has no feature that fetches user-supplied URLs (no link previews, no remote avatars, no webhooks), so SSRF has no
entry point (V1.3.6). Any future outbound feature requires an ADR, an allowlist entry, no-redirect HTTP client settings
(V15.3.2), and a threat-model update.

---

## 12. Data classification and protection (V14.1.1, V14.1.2, V14.2.x, V14.3.x)

| Level | Data | Protection requirements |
|---|---|---|
| **Secret** | Passwords (in transit only), session/CSRF/one-time tokens, TOTP seeds, recovery codes, private keys, DB passwords, encryption keys | Never logged; never in URLs; never returned after creation (recovery codes shown once); hashed (passwords, tokens, codes) or AES-256-GCM encrypted (TOTP seeds); keys only as secret files; excluded from `jira_readonly` grants |
| **Confidential** | Issue/comment content, attachments, project names, user emails, audit log, IP addresses, user agents | Access only per §5; TLS in transit; `Cache-Control: no-store` on API responses; not sent to third parties; IPs/user agents kept 90 days in `sessions`/`login_attempts`, then purged; audit log 1 year |
| **Internal** | Display names, avatars, project keys, statuses, labels | Access per §5; TLS |
| **Public** | Static SPA assets, `/healthz` | None beyond integrity (TLS) |

Privacy: the application stores personal data (names, emails, IPs, user agents) for account operation and security only. The operator decides which regulations apply (e.g. GDPR) and may shorten retention periods. Account deletion by a Site Admin anonymizes the user (display name replaced, email removed) while keeping audit records with the user ID.

Browser-side: no Secret or Confidential data in `localStorage`/`sessionStorage`/IndexedDB; the Query cache lives in memory
and is cleared on logout; logout responses send `Clear-Site-Data: "cache", "storage"`. No third-party scripts, analytics,
fonts or CDNs at runtime (CSP `default-src 'self'`).

---

## 13. Session policy (V7.1.1, V7.1.2)

ADR-0006 and ADR-0008: 30-minute inactivity, 12-hour absolute, 10 concurrent sessions (oldest evicted with notice), 5-minute
step-up freshness for sensitive actions. No federated identity (V7.1.3 and V7.6 are N/A).

---

## 14. HTTP security configuration (V3.4.x, V3.3.x, V4.1.x, V13.4.x)

Canonical header and TLS values are in PLAN §8.2. Cookies:

| Cookie | Attributes | Purpose |
|---|---|---|
| `__Host-session` | Secure; HttpOnly; SameSite=Strict; Path=/ | Session reference token |
| `__Host-csrf` | Secure; SameSite=Strict; Path=/ (readable by JS by design) | Double-submit CSRF token |
No other cookies are set by the application.

---

## 15. Third-party components (V15.1.1, V15.1.2, V15.2.1)

ADR-0023 defines sources, SBOM, scanning and remediation time frames.

---

## 16. Operator (deployment) requirements

These cannot be guaranteed by the code alone. The README and the security review list them, and the reference deployment
demonstrates each one.

| # | Requirement | ASVS |
|---|---|---|
| D1 | Use publicly trusted certificates for `APP_HOST` and `PGADMIN_HOST` in production | V12.2.2 |
| D2 | Configure the Docker logging driver to forward logs to a separate collector over TLS | V16.4.3 |
| D3 | Keep the host clock NTP-synchronized | V16.2.2 |
| D4 | Restrict `PGADMIN_ALLOWED_CIDRS` to administrator networks (or VPN) | V13.4.5 |
| D5 | Protect the `secrets/` directory and backups (encrypted at rest, restricted access); prefer a vault/KMS for higher assurance | V13.3.1 |
| D6 | Encrypt volumes/backups at rest (host disk encryption or encrypted backup tooling) | V14.2.4 |
| D7 | Keep images updated per ADR-0023 (weekly rebuild) | V15.2.1 |
| D8 | Run `make audit-verify` on a schedule and alert on failure | V16.4.2 |
| D9 | Restrict the app container's egress to the ClamAV mirror (and HIBP if enabled), or provide signatures offline | V13.2.4, V13.2.5, V5.4.3 |
