# Security Test Plan

- **Standards:** OWASP Top 10:2025, OWASP ASVS 5.0.0 L1+L2, OWASP WSTG, CVSS v4.0 (ADR-0021).
- **Test types:** continuous automated, white-box, black-box, red team (definitions in ADR-0021).
- **Exit criteria:** PLAN §10.6 security release gates.

---

## 1. Scope and rules of engagement

**In scope:** the three runtime containers (app, db, pgadmin) started from this repository with `make secrets certs up`, their
published ports, the source tree, the CI configuration, and the built images.

**Out of scope:** third-party services (PyPI, npm, Docker Hub, GitHub, HIBP), the tester's own machine, and any host or
network other than the local Docker stack. No social engineering of real people.

**Rules:**
1. Test only the local stack. Never send traffic to public hosts except to download pinned tools.
2. Load/DoS testing is limited to verifying rate limits and size limits (short bursts up to the documented limits ×2). No
   sustained floods.
3. Use dedicated test accounts created by the seed script (`make seed-security`), never real data.
4. Record every command and payload in the report's evidence appendix so it can be reproduced.
5. Report a Critical finding to the orchestrator right away (stop and report); don't keep exploiting it beyond proving impact.
6. After testing: `make down-volumes` to destroy test data and generated test credentials.
7. Tool containers are ephemeral and pinned (ADR-0020); raw output goes to `reports/raw/` (git-ignored).

**Test accounts (seeded):** `sa@test.local` (Site Admin), `pa@test.local` (Project Admin of ALPHA), `member@test.local`
(Member of ALPHA), `viewer@test.local` (Viewer of ALPHA), `outsider@test.local` (no projects), `pb@test.local` (Project Admin
of BRAVO). Each has TOTP enrolled with a seed printed once to `reports/raw/test-accounts.txt` (git-ignored). The black-box
pentester receives only `member` and `outsider`; the red team receives only `outsider` (and must earn the rest).

---

## 2. Test types and when they run

| Type | Trigger | Agent / runner | Output |
|---|---|---|---|
| Continuous automated | Every commit (pre-commit) and every CI run; weekly scheduled run | CI | CI logs, SBOM artifact |
| Security unit/integration tests | `make check` | pytest / vitest | test results |
| Security E2E | `make e2e` | Playwright (`e2e/security/`) | test results |
| White-box assessment | WP-22 | `security-auditor` | `reports/white-box-report.md`, completed ASVS matrix |
| Black-box assessment | WP-23 | `pentester` | `reports/black-box-report.md` |
| Red-team exercise | WP-24 | `red-team` | `reports/red-team-report.md` |
| Retest | after each fix (WP-25) | agent that found the issue | appended "Retest" section in the same report |

---

## 3. OWASP Top 10:2025 test cases

Every case lists how it's verified: **AUT** = automated test in the repo (path given), **WB** = white-box review,
**BB** = black-box manual/tool test, **RT** = red-team objective. A category is "passed" only when all its cases pass.

### A01:2025 — Broken Access Control
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A01-01 | Authorization matrix: every route × {anon, outsider, viewer, member, project admin, other-project admin, site admin} returns the expected status | AUT, WB | `backend/tests/security/test_authz_matrix.py` (route list generated from the app) |
| TC-A01-02 | IDOR: access ALPHA issues, comments, attachments, history, watchers and links using BRAVO credentials, by UUID and by key | AUT, BB | `test_idor.py`; manual ID swapping |
| TC-A01-03 | Mass assignment / BOPLA: send forbidden fields (`reporter_id`, `project_id`, `key`, `is_site_admin`, `role`) on every create/update | AUT, BB | `test_mass_assignment.py`; Schemathesis + manual |
| TC-A01-04 | Non-members get 404 (not 403) and no counts or names leak through search, mentions, user directory or notifications | AUT | `test_existence_disclosure.py` |
| TC-A01-05 | Privilege escalation: member promotes self; project admin sets site-admin flag; last-admin removal; role change through bulk endpoints | AUT, BB, RT | `test_privilege_escalation.py` |
| TC-A01-06 | WebSocket: foreign Origin rejected; subscribe to a non-member project rejected; removed member stops receiving events; revoked session closed ≤ 60 s | AUT | `test_ws_security.py` |
| TC-A01-07 | JQL can't return issues from projects the user can't read (incl. `project in (...)`, `key = BRAVO-1`, text search) | AUT, BB | `test_jql_authz.py` |
| TC-A01-08 | CSRF: unsafe requests without token, with another session's token, and with a foreign Origin are rejected; no state-changing GET exists | AUT, BB | `test_csrf.py`; route scan |
| TC-A01-09 | Forced browsing to admin endpoints and admin UI routes by non-admins | AUT, BB | `test_authz_matrix.py`; ZAP |
| TC-A01-10 | `mfa_pending` session can reach only the allowed endpoints (enumerate all routes) | AUT | `test_mfa_gate.py` |
| TC-A01-11 | Open redirect: `returnTo` with absolute URLs, `//evil`, `/\evil`, encoded variants | AUT, BB | `frontend/tests/security/returnTo.test.ts` |

### A02:2025 — Security Misconfiguration
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A02-01 | Required headers on SPA, API, error (404/500) and attachment responses: HSTS (≥ 1 year, includeSubDomains), CSP (incl. frame-ancestors), nosniff, Referrer-Policy, COOP, CORP, Permissions-Policy, `Cache-Control: no-store` on API | AUT, BB | `tools/security/check_headers.py`; ZAP |
| TC-A02-02 | TLS: only TLS 1.2/1.3, approved suites, no compression/renegotiation issues, HTTP→HTTPS redirect only for pages, API over HTTP gets no redirect | AUT, BB | testssl.sh; `check_headers.py` |
| TC-A02-03 | HTTP methods: TRACE/TRACK/CONNECT → 405; OPTIONS reveals nothing sensitive | AUT, BB | curl script |
| TC-A02-04 | No `.git`, source maps, backups, `.env`, directory listing, server version banners | AUT, BB | `check_exposure.sh`; ffuf with a common wordlist |
| TC-A02-05 | Production mode: no OpenAPI/docs, no debug, app refuses dev settings | AUT, WB | `test_production_config.py` |
| TC-A02-06 | Container hardening: non-root UIDs, read-only rootfs, `CapEff` minimal, no-new-privileges, no Docker socket mounts, resource limits | AUT, WB | `tools/security/check_containers.sh` (`docker inspect`); Trivy config |
| TC-A02-07 | pgAdmin: not reachable on `APP_HOST`; reachable on `PGADMIN_HOST` only from allowlisted IPs; default DB connection is `jira_readonly` | AUT, BB, RT | `check_pgadmin.sh` |
| TC-A02-08 | No default credentials: startup fails with missing/placeholder secrets; common admin/DB/pgAdmin passwords fail | AUT, BB | `test_secrets_validation.py`; Hydra-style small list (≤ 50 attempts) |
| TC-A02-09 | Postgres: non-TLS connections rejected; `jira_app` privilege set exactly as ADR-0012 | AUT | `test_db_hardening.py` |
| TC-A02-10 | Unknown `Host` header → connection closed (444) | AUT, BB | curl |
| TC-A02-11 | Client-supplied `X-Forwarded-For`/`X-Real-IP` doesn't change the logged or rate-limited IP | AUT, BB | `test_forwarded_headers.py` |

### A03:2025 — Software Supply Chain Failures
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A03-01 | No High/Critical vulnerabilities with an available fix in Python, npm or OS packages; Mediums within the ADR-0023 deadline | AUT | pip-audit, pnpm audit, osv-scanner, Trivy (CI) |
| TC-A03-02 | SBOM (CycloneDX) generated for the app image and matches the lockfiles | AUT | Syft (CI) |
| TC-A03-03 | Installs are frozen to lockfiles with integrity hashes | AUT, WB | CI step; Dockerfile review |
| TC-A03-04 | All base images pinned by digest; no `latest` tags | AUT | `check_pins.sh`; Hadolint |
| TC-A03-05 | All GitHub Actions pinned by full SHA; workflow `permissions` minimal; no secrets exposed to pull-request workflows | AUT, WB | `check_pins.sh`; review |
| TC-A03-06 | No secrets in the git history, working tree or images | AUT | gitleaks; Trivy secret scan |

### A04:2025 — Cryptographic Failures
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A04-01 | Argon2id parameters ≥ ADR-0010 values; rehash on parameter change | AUT, WB | `test_password_hashing.py` |
| TC-A04-02 | Session, CSRF, reset, invite and setup tokens are ≥ 128 bits (sessions 256) from `secrets`; only hashes stored | AUT, WB | `test_tokens.py`; DB inspection |
| TC-A04-03 | TOTP seeds stored encrypted with AES-256-GCM, unique nonces, key ID; decrypt fails with tampered ciphertext/AAD | AUT | `test_field_encryption.py` |
| TC-A04-04 | Internal TLS: app↔db and pgAdmin↔db use `verify-full`; connection with a wrong-CA cert fails; Nginx↔pgAdmin verifies | AUT | `test_internal_tls.py`; `check_internal_tls.sh` |
| TC-A04-05 | No Disallowed/Legacy primitives (MD5, SHA-1, ECB, `random` for security, AES-128 for new data) in code | AUT, WB | Semgrep custom rules `tools/security/semgrep/` |
| TC-A04-06 | Cookies: `__Host-` prefix, Secure, HttpOnly (session), SameSite=Strict, no Domain | AUT, BB | `test_cookies.py`; ZAP |
| TC-A04-07 | DB mTLS: connections without a client certificate, with a certificate from another CA, or with a CN that doesn't match the role are rejected even with the right password | AUT | `test_internal_tls.py` |

### A05:2025 — Injection
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A05-01 | SQL injection corpus on every parameter (path, query, body, headers used by the app) | AUT, BB | `test_injection_sql.py`; ZAP active scan; targeted sqlmap at low risk/level |
| TC-A05-02 | XSS corpus (stored, reflected, DOM) in every text field incl. display name, project name, labels, summaries, filenames, JQL errors | AUT, BB | `e2e/security/xss.spec.ts` (asserts no dialog/script execution); ZAP |
| TC-A05-03 | Rich-text schema rejects script nodes, event attributes, `javascript:`/`data:` links, oversize/deep documents | AUT | `test_richtext_schema.py` |
| TC-A05-04 | JQL injection corpus (quotes, comments, unions, function abuse) produces 400 errors, never SQL errors or other data | AUT, BB | `test_jql_injection.py` |
| TC-A05-05 | Header/CRLF injection in `Content-Disposition` filenames and redirects | AUT, BB | `test_header_injection.py` |
| TC-A05-06 | No `subprocess`/`os.system`/`eval`/`exec`/`pickle`/`yaml.load` on untrusted data | AUT, WB | Semgrep + ruff `S` rules |
| TC-A05-07 | Template injection not possible (no server-side templates rendering user input) | WB | review |
| TC-A05-08 | Uploads: HTML, SVG, polyglot (GIF+JS), MIME-spoofed files rejected or served inertly (`attachment`, `nosniff`, sandbox CSP) | AUT, BB | `test_uploads.py`; manual |
| TC-A05-09 | Path traversal via filename (`../`, `..%2f`, absolute paths, NUL, Unicode tricks) has no effect on storage location | AUT, BB | `test_uploads.py` |
| TC-A05-10 | Prototype pollution: `__proto__`/`constructor` keys in JSON responses and URL params don't alter app behavior | AUT | `frontend/tests/security/prototype.test.ts` |
| TC-A05-11 | Antivirus: EICAR test file (plain and inside a zip) rejected; archive exceeding scan limits rejected; uploads return 503 while `clamd` is stopped; weekly re-scan quarantines a newly detected file | AUT | `test_uploads_av.py` |

### A06:2025 — Insecure Design
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A06-01 | Business and rate limits from security-requirements §6/§7 and ADR-0024 enforced (one test per limit) | AUT, BB | `test_limits.py` |
| TC-A06-02 | Workflow: transitions not in the table rejected; status from another project rejected | AUT | `test_workflow_rules.py` |
| TC-A06-03 | Sprint lifecycle and one-active-sprint rule; auth flow steps can't be skipped | AUT | `test_sprint_rules.py`, `test_auth_flow.py` |
| TC-A06-04 | Concurrency: parallel issue creation gives unique sequential keys; parallel sprint start allows one; stale `If-Match` gets 409 | AUT | `test_concurrency.py` |
| TC-A06-05 | Threat model reviewed against the implementation (Q4) | WB | WP-26 |

### A07:2025 — Authentication Failures
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A07-01 | Password policy: < 15 rejected; 128 accepted; 64+ accepted; no composition rules; no truncation; Unicode handled | AUT | `test_password_policy.py` |
| TC-A07-02 | Breached-list and context-word rejection | AUT | `test_password_policy.py` |
| TC-A07-03 | Brute-force backoff per account; stuffing alert per IP; no permanent lockout | AUT, BB | `test_throttling.py` |
| TC-A07-04 | Account enumeration: login, registration, invite, reset responses identical; timing difference < 50 ms median over 50 samples | AUT, BB | `test_enumeration.py` |
| TC-A07-05 | MFA mandatory: no access before enrollment; TOTP and WebAuthn both work; WebAuthn rejects a wrong origin/RP ID | AUT | `test_mfa.py`; `e2e/security/webauthn.spec.ts` (virtual authenticator) |
| TC-A07-06 | TOTP: replay of the same step rejected; a code is accepted only during its single 30-second step (after drift offset); previous/next-step codes rejected; re-sync needs two consecutive codes within ±2 steps | AUT | `test_mfa.py` |
| TC-A07-07 | Recovery codes single-use, hashed, regenerating invalidates old ones | AUT | `test_mfa.py` |
| TC-A07-08 | Session rotation at login, after MFA, after step-up; pre-login token unusable afterwards | AUT | `test_sessions.py` |
| TC-A07-09 | Logout revokes the server session; old cookie gives 401; Clear-Site-Data sent; deactivation revokes all | AUT, BB | `test_sessions.py` |
| TC-A07-10 | Idle (30 min) and absolute (12 h) expiry enforced (time-travel in tests); max 10 sessions | AUT | `test_sessions.py` |
| TC-A07-11 | Reset flow: token single-use, 30-min expiry, MFA still required, all sessions revoked; MFA reset requires another admin + reason | AUT | `test_account_recovery.py` |
| TC-A07-12 | Setup token: required, single use, rejected once an admin exists, never logged | AUT, BB | `test_setup.py` |

### A08:2025 — Software or Data Integrity Failures
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A08-01 | Attachment SHA-256 verified on download; tampered file detected | AUT | `test_uploads.py` |
| TC-A08-02 | Audit hash chain: `make audit-verify` passes; modifying a row (as superuser) is detected | AUT | `test_audit_chain.py` |
| TC-A08-03 | No unsafe deserialization of untrusted data | AUT, WB | Semgrep |
| TC-A08-04 | Signed/HMAC'd cursors: tampered cursor → 400 | AUT | `test_pagination.py` |
| TC-A08-05 | CI integrity: protected workflows, pinned actions (see TC-A03-05) | WB | review |

### A09:2025 — Security Logging and Alerting Failures
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A09-01 | Every event in the security event catalogue (security-requirements §10.3) is emitted with required fields | AUT | `test_security_events.py` (one assertion per event) |
| TC-A09-02 | No passwords, tokens, cookies, TOTP/recovery codes or secrets in any log output during the full E2E suite | AUT | `tools/security/scan_logs.py` over captured logs |
| TC-A09-03 | Alert thresholds fire (`alert.*`) | AUT | `test_alerts.py` |
| TC-A09-04 | `jira_app` can't UPDATE/DELETE/TRUNCATE `audit_log` | AUT | `test_db_hardening.py` |
| TC-A09-05 | Log injection: CRLF/JSON-breaking payloads in username, UA, paths are escaped | AUT | `test_logging.py` |
| TC-A09-06 | Reference deployment forwards logs to an external syslog listener (D2) | AUT | `check_log_forwarding.sh` |
| TC-A09-07 | Red-team detection: each red-team action appears in logs/audit with enough detail to reconstruct the timeline | RT | red-team report §Detection |

### A10:2025 — Mishandling of Exceptional Conditions
| ID | Test | Method | Location / tool |
|---|---|---|---|
| TC-A10-01 | Unexpected errors return a generic body with `request_id` only; no stack traces, SQL or paths | AUT, BB | `test_error_handling.py`; ZAP |
| TC-A10-02 | Fault injection in the policy layer and validators → request denied (fail closed), never allowed | AUT | `test_fail_closed.py` |
| TC-A10-03 | DB unavailable → 503, no session bypass, recovery after DB returns | AUT | `test_db_outage.py` (stop container in integration env) |
| TC-A10-04 | API fuzzing produces no 500s, hangs or crashes | AUT, BB | Schemathesis (`make fuzz`) |
| TC-A10-05 | Failure mid-operation rolls back the whole transaction (no partial state) | AUT | `test_transactions.py` |
| TC-A10-06 | Malformed JSON, wrong content types, invalid UTF-8, huge numbers → 4xx | AUT | `test_malformed_input.py` |

---

## 4. White-box assessment (WP-22)

**Agent:** `security-auditor`. **Knowledge:** full source, configs, docs, CI. **Timebox:** until every ASVS row has a verdict.

Procedure:
1. Run all automated tools (Semgrep with the OWASP + Python + TypeScript rule packs and the custom rules in
   `tools/security/semgrep/`, ruff `S`, eslint-security, gitleaks, pip-audit, pnpm audit, osv-scanner, Trivy fs/image/config,
   Hadolint). Triage every result as true positive (finding) or false positive (with reason).
2. Manual review, in this order: authentication and session code; policy module and every router (permissions match the §5
   matrix); input schemas (`extra="forbid"`, limits); JQL compiler; rich-text validator; upload pipeline; WebSocket manager;
   crypto usage against the inventory (§9); error handling; logging and redaction; Nginx, Postgres, pgAdmin and Compose configs;
   Dockerfile; CI workflows.
3. ASVS verification: for each of the 253 rows in `asvs/verification-matrix.csv` set `status` (Pass / Fail / N/A) with
   `evidence` (test ID, `file:line`, config line, or document section). N/A rows need a justification; the auditor approves or
   rejects the proposed N/A justifications.
4. Check documentation requirements match reality (e.g. the rate limits in code equal ADR-0024).
5. Report findings using the format in §7.

---

## 5. Black-box assessment (WP-23)

**Agent:** `pentester`. **Knowledge:** the base URL `https://APP_HOST:8443`, the pgAdmin hostname, and the `member` and
`outsider` test accounts (with TOTP seeds). **No access to source code, docs other than this section, or containers.**

Methodology: OWASP WSTG categories INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT, APIT, applied to this app.

Procedure:
1. Reconnaissance: map the SPA and API from the browser and responses only (no source). Enumerate endpoints by crawling,
   reading the JS bundle (allowed: it's public), and brute-forcing common paths.
2. Automated: ZAP baseline + full active scan with an authenticated context (both accounts), ZAP API scan if a schema is
   discoverable (it shouldn't be in production; finding one is a finding), Schemathesis against reconstructed requests,
   testssl.sh against both hostnames, nuclei with the default templates restricted to the target.
3. Manual: every A01–A10 case marked **BB** in §3, plus WSTG tests for session management, business logic (sprint/workflow
   abuse), file upload, WebSocket, and client-side tests.
4. Report findings using the format in §7, including tests that **passed** (with evidence), so coverage is visible.

---

## 6. Red-team exercise (WP-24)

**Agent:** `red-team`. **Knowledge:** objectives and the `outsider` account only. The red team may chain any weaknesses and use
any technique within the rules of engagement (§1). It also checks whether the blue side (logs, audit, alerts) would have noticed.

### Objectives (flags)
| ID | Objective | Proof |
|---|---|---|
| RT-1 | Read any issue in project BRAVO as `outsider` | Issue summary of `BRAVO-1` (seeded secret string) |
| RT-2 | Become Project Admin of ALPHA, or Site Admin | Screenshot/API response showing the role |
| RT-3 | Take over `viewer@test.local` without knowing their password and second factor | Authenticated request as viewer |
| RT-4 | Run script in another user's browser session (stored XSS) | Proof-of-concept that sends a marker request from the victim's session |
| RT-5 | Reach pgAdmin's login page from a non-allowlisted source, or reach the database port | Response from pgAdmin/Postgres |
| RT-6 | Extract any secret (DB password, field-encryption key, TOTP seed, session token of another user) | Secret value hash (don't paste the secret itself) |
| RT-7 | Modify or delete an audit-log entry without `make audit-verify` detecting it | Verify output |
| RT-8 | Make the service unavailable to other users for more than 60 s within the rate-limit rules | Timeline |
| RT-9 | Persist access after the victim changes password and terminates sessions | Request succeeding afterwards |

### Procedure
1. Plan attack paths using public knowledge of similar apps (OWASP Top 10, MITRE ATT&CK for enterprise web apps).
2. Execute, chaining partial weaknesses (e.g. info leak → IDOR → escalation).
3. For every action, record time (UTC), technique, request, and result.
4. **Detection review:** after the exercise, read the logs and audit log (now allowed) and score each action: Detected+Alerted,
   Logged-only, or Not visible. Anything "Not visible" that should be logged per §10.3 of the security requirements is a finding (A09).
5. Report: attack narrative, objectives achieved/not achieved, findings (§7), detection matrix.

---

## 7. Findings: format, severity and handling

Each finding is one block in the report:

```
### F-<TYPE>-<NNN>: <title>          (TYPE = WB | BB | RT | CI)
- Severity: Critical | High | Medium | Low | Info   (CVSS v4.0 vector + score)
- OWASP Top 10:2025: A0x      ASVS: Vx.y.z      Threat: T-xxx (or "new")
- Location: URL / endpoint / file:line
- Description:
- Reproduction steps: (exact requests/commands)
- Impact:
- Recommendation:
- Status: Open | Fixed (commit) | Retest passed | Accepted (ADR-NNNN)
```

Handling (WP-25): Critical/High/Medium → must be fixed; Low/Info → fix or accept through an ADR. Every fix includes a regression
test referencing the finding ID. The reporting agent retests and updates the status. Findings that reveal a threat missing from the
threat model are flagged "new" and added in WP-26.

---

## 8. Tooling (pinned versions decided in WP-05, recorded in `tools/security/versions.env`)

| Purpose | Tool |
|---|---|
| SAST | Semgrep (OSS rules + custom), ruff `S` (bandit rules), eslint-plugin-security, eslint-plugin-no-unsanitized |
| Secrets | gitleaks |
| SCA | pip-audit, pnpm audit, osv-scanner |
| Images/IaC | Trivy, Hadolint |
| SBOM | Syft (CycloneDX JSON) |
| DAST | OWASP ZAP (baseline, full, API scan) |
| Fuzzing | Schemathesis |
| TLS | testssl.sh |
| Templates | nuclei (target-restricted) |
| Targeted | sqlmap (low risk/level, specific parameters only), ffuf |
| E2E security | Playwright |
