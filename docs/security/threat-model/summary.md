# Threat Model — Summary

Short version of `detailed.md`, structured by Shostack's four questions. Version 0.1 (design-time), 2026-10-17.

## 1. What are we working on?

A self-hosted JIRA-style issue tracker: React/TypeScript SPA, FastAPI/Python API, PostgreSQL 18, running as three Docker
containers (app with Nginx + API, database, pgAdmin). Users log in with a password **plus mandatory MFA** and work inside
projects they're members of. Admins manage users; operators manage the host and use pgAdmin.

**Most valuable assets:** project content, credentials and sessions, authorization data, the audit log, and deployment secrets.

**Trust boundaries:** internet ↔ Nginx; Nginx ↔ app (Unix socket); app ↔ database (TLS); operator ↔ pgAdmin (separate
hostname, IP allowlist); containers ↔ host; build pipeline ↔ third-party code.

```
Browser ──TLS──► Nginx ──unix socket──► FastAPI ──mTLS──► PostgreSQL ◄──mTLS── pgAdmin ◄──TLS── Nginx (pgAdmin host, allowlisted)
                                          └─unix socket─► ClamAV (scans uploads)
```

## 2. What can go wrong? (top threats)

| # | Threat | IDs |
|---|---|---|
| 1 | A user reads or changes another project's data by guessing IDs, abusing search, or listening to realtime events (broken access control) | T-013, T-014, T-016 |
| 2 | Accounts taken over through password guessing, credential stuffing, phishing, or the reset flow | T-001–T-004 |
| 3 | Stored XSS through issue text, comments, names or uploaded files, leading to actions as the victim | T-012, T-060 |
| 4 | Privilege escalation: Viewer → Admin, Project Admin → Site Admin, or setting forbidden fields | T-015, T-017 |
| 5 | Session theft or misuse: hijacking, fixation, CSRF, cross-site WebSockets | T-005, T-006, T-010, T-011 |
| 6 | Database or pgAdmin compromise: SQL injection, exposed pgAdmin, sniffed internal traffic, default credentials | T-021–T-023, T-035, T-040–T-043 |
| 7 | Malicious or vulnerable dependencies and CI compromise | T-033, T-034 |
| 8 | Attacks go unnoticed or audit records are altered | T-050–T-053 |
| 9 | Service exhaustion through expensive queries, hashing floods, uploads or sockets | T-070–T-073 |
| 10 | Errors handled unsafely: fail-open authorization, leaked internals | T-025, T-080–T-082 |

## 3. What are we going to do about it?

- **Access control:** one central policy module, every route declares a permission, and a test checks every route against every role. Non-members get 404. Separate input schemas block forbidden fields.
- **Authentication:** 15+ character passwords checked against breached lists; mandatory TOTP or WebAuthn; throttling without hard lockout; admin-issued single-use reset links that still require MFA; no default accounts (a one-time setup token creates the first admin).
- **Sessions:** opaque random tokens in `__Host-` HttpOnly, SameSite=Strict cookies; rotated at login and step-up; 30-minute idle and 12-hour absolute limits; server-side logout. CSRF tokens and Origin checks on top.
- **Injection and XSS:** ORM with bound parameters only; JQL compiled through a grammar; rich text stored as validated JSON (no HTML); strict CSP; risky uploads (SVG/HTML) rejected, every upload virus-scanned before storage (fail closed), and every download forced as an attachment with a sandbox CSP.
- **Transport and crypto:** TLS on every network hop, including to the database and pgAdmin; database logins need a client certificate as well as a password; Argon2id passwords; AES-256-GCM for MFA secrets; no Legacy or Disallowed algorithms.
- **Infrastructure:** non-root, read-only, capability-dropped containers; database and pgAdmin on an internal network with no internet access; least-privilege DB roles; secrets only as files; pgAdmin on its own hostname behind an allowlist.
- **Supply chain:** lockfiles, digest-pinned images, SHA-pinned CI actions, dependency and image scanning with remediation deadlines, an SBOM for every build.
- **Detection:** structured security events, alerts for brute force and probing, and an append-only, hash-chained audit log that the app can't modify.
- **Resilience:** size, depth and rate limits; query timeouts; fail-closed error handling with generic messages.

## 4. Did we do a good enough job?

**Design-time:** yes for the design. Every DFD element has STRIDE coverage, every threat has a mitigation and a planned test,
and accepted risks are written down.

**Not yet proven:** mitigations are only "planned" until their tests pass. White-box review, black-box testing and a red-team
exercise (WP-22–WP-24) will test this model. Anything they find that the model missed gets added along with the reason it
was missed (WP-26), and the final answer goes in `docs/security/security-review.md`.

**Accepted residual risks:**
1. TOTP users remain phishable through real-time relay sites; WebAuthn is offered.
2. Nginx and the API share one container, because of the three-container requirement.
3. A compromise of the Docker host exposes secrets.
4. Antivirus scanning is signature-based, so new malware can get through (downloads are never rendered or executed by the app).
5. Logs can be lost unless operators forward them to an external collector.
