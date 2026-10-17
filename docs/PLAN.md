# JIRA Clone — Master Plan

> This is the plan the agents follow. The orchestrator (the main Claude session) works through the
> **Work Packages (§11)** in dependency order, following the **Orchestration Protocol (§12)**.
> Progress is tracked in `docs/PROGRESS.md`. Decisions are recorded in `docs/decisions/` (ADRs).
> Security documentation lives in `docs/security/` — start at `docs/security/README.md`.
>
> **Security is a release gate, not a phase.** Every work package has security acceptance criteria,
> and the project is not finished until the gates in §10.6 pass.

---

## 1. Goal and scope

Build a self-hostable clone of Atlassian JIRA (Software), covering the core agile workflow:
creating projects, filing issues, planning sprints from a backlog, and moving work across a board.
The application must meet **OWASP ASVS 5.0.0 Level 1 and Level 2** and be tested against the
**OWASP Top 10:2025** using white-box, black-box, and red-team testing.

### 1.1 In scope (v1)

| Area | Features |
|---|---|
| Accounts | Sign up (can be disabled by admin), log in/out, **mandatory MFA** (TOTP or WebAuthn passkey) with recovery codes, profile (name, avatar upload), change password, view and revoke own sessions |
| Admin | Bootstrap admin created by a one-time setup token (no default accounts); admin manages users (invite, deactivate, reset password, reset MFA after identity check, terminate sessions), toggles open registration, views the security audit log |
| Projects | Create/edit/archive, unique project key (e.g. `PROJ`), lead, members with roles (Admin / Member / Viewer), Scrum or Kanban template |
| Issues | Types: Epic, Story, Task, Bug, Sub-task. Fields: key (`PROJ-123`), summary, description (rich text), status, priority, assignee, reporter, labels, story points, due date, parent (epic/sub-task), sprint |
| Workflow | Per-project statuses grouped into categories (To Do / In Progress / Done), allowed transitions |
| Board | Columns mapped to statuses, drag-and-drop between columns and reorder within a column, quick filters (assignee, type, label, "only my issues"), swimlanes by epic or assignee |
| Backlog | Ranked list, drag to reorder, drag into/out of sprints, create inline |
| Sprints | Create, start (name, goal, dates), complete (move unfinished issues to backlog or next sprint), one active sprint per project |
| Collaboration | Comments (create/edit/delete), @mentions, watchers, attachments, issue links (blocks / is blocked by / relates to / duplicates) |
| History | Per-issue activity log of every field change |
| Search | Full-text quick search; filter view with a JQL subset; saved filters |
| Notifications | In-app notifications (assigned, mentioned, watched issue changed), unread badge |
| Realtime | Board/backlog/issue view update live when other users change data |
| Reports | Burndown chart (per sprint) and a cumulative flow chart (per project) |

### 1.2 Out of scope (v1)

Email delivery (no SMTP; password reset is admin-issued — see ADR-0022), SSO/OAuth/SAML, marketplace/plugins,
custom fields beyond the list above, Confluence-style pages, time tracking, mobile apps, multi-tenant
organizations, public (anonymous) projects. Each should remain possible to add later; adding any of them
requires a threat-model update and re-evaluating the ASVS chapters currently marked N/A (e.g. V10 OAuth).

---

## 2. Technology decisions

Full rationale for each is in `docs/decisions/` (ADR number in brackets).

| Concern | Choice |
|---|---|
| Frontend | **TypeScript** (strict), React 19 + Vite SPA, React Router, TanStack Query, Zustand (UI state only), Tailwind + Radix UI, dnd-kit, TipTap, Recharts [ADR-0002] |
| API client | Types generated from FastAPI OpenAPI (`openapi-typescript` + `openapi-fetch`) |
| Backend | **Python 3.13**, FastAPI, Pydantic v2 (`extra="forbid"` on all input models), SQLAlchemy 2 async + `asyncpg`, Alembic, Uvicorn [ADR-0002] |
| Sessions | **Server-side opaque session tokens** (256-bit CSPRNG, stored as SHA-256 hash) in a `__Host-` cookie: `Secure; HttpOnly; SameSite=Strict; Path=/`. No JWT. [ADR-0006] |
| CSRF | SameSite=Strict + double-submit token (`__Host-csrf` cookie + `X-CSRF-Token` header) + `Origin` check on unsafe methods [ADR-0009] |
| MFA | Mandatory for every account: TOTP (RFC 6238, HMAC-SHA-256 default) or WebAuthn passkey; 10 single-use recovery codes [ADR-0007] |
| Passwords | Argon2id (`argon2-cffi`, m=64 MiB, t=3, p=4), 15–128 chars, no composition rules, breached/common/context-word blocklist (offline) [ADR-0013] |
| Field encryption | AES-256-GCM (`cryptography` lib) for TOTP seeds and other secrets at rest, versioned key IDs [ADR-0010, security-requirements §9] |
| JQL | `lark` grammar → SQLAlchemy expressions with complexity limits [ADR-0018] |
| Realtime | WebSocket (`wss`) at `/api/v1/ws`, session-cookie auth + `Origin` allowlist; fan-out via PostgreSQL `LISTEN/NOTIFY` [ADR-0016] |
| Database | **PostgreSQL 18** (`postgres:18.x`, pinned by digest), `uuidv7()` PKs, TLS-only connections authenticated by client certificate **and** SCRAM password, least-privilege roles [ADR-0012] |
| Antivirus | ClamAV (`clamd` + `freshclam`) inside the app container; every upload scanned before it's stored, fail closed [ADR-0015] |
| DB admin | pgAdmin 4 on its **own hostname**, IP-allowlisted, TLS end-to-end [ADR-0005] |
| Reverse proxy | **Nginx** inside the app container, TLS 1.2/1.3, talks to Uvicorn over a Unix socket [ADR-0003, ADR-0004] |
| Secrets | Docker Compose secrets (files under `/run/secrets`, generated by `make secrets`), never in env vars, images or git [ADR-0011] |
| Quality tooling | `uv`, `ruff` (incl. `S` security rules), `mypy --strict`, `pytest`; `pnpm`, `eslint` (+ security plugin), `prettier`, `tsc --noEmit`, `vitest`; Playwright |
| Security tooling | Semgrep, gitleaks, pip-audit, `pnpm audit`, osv-scanner, Trivy, Hadolint, Syft (SBOM), OWASP ZAP, Schemathesis, testssl.sh — all run as **ephemeral tool containers**, never part of the runtime stack [ADR-0020] |

---

## 3. Architecture

### 3.1 Container topology (exactly 3 runtime containers)

```
 Browser ──HTTPS──►  Host :${APP_HTTPS_PORT:-8443}   (HTTP :${APP_HTTP_PORT:-8080} only redirects browser pages)
                               │
┌──────────────────────────────▼──────────────────────────────────────────────┐
│ app  (non-root, read-only rootfs, cap_drop ALL, no-new-privileges)          │
│                                                                             │
│  supervisord                                                                │
│   ├── nginx :8443 (TLS)                                                     │
│   │     server ${APP_HOST}                                                  │
│   │       /            → static SPA                                         │
│   │       /api/*       → unix:/run/app/uvicorn.sock                         │
│   │       /api/v1/ws   → same, WebSocket upgrade                            │
│   │       internal /protected-media/ → /data/attachments (X-Accel-Redirect) │
│   │     server ${PGADMIN_HOST}  (IP allowlist)                              │
│   │       /            → https://pgadmin:8443  (TLS, verified internal CA)  │
│   │     default server → 444 (drop unknown Host headers)                    │
│   ├── uvicorn  (FastAPI, N workers, Unix socket only — no TCP listener)     │
│   ├── clamd    (ClamAV, Unix socket only; scans every upload)               │
│   └── freshclam (signature updates — the app's only routine egress)         │
│                                                                             │
│  volumes: attachments, clamav-db              secrets: /run/secrets/*        │
└───────┬─────────────────────────────────────────────────────────────────────┘
        │  network "backend" (internal: true → no internet egress)
        │  TLS 1.3, certificates from the project's internal CA
 ┌──────▼─────────────────┐          ┌────────────────────────────┐
 │ db  postgres:18        │◄─────────┤ pgadmin  dpage/pgadmin4    │
 │ hostssl, client cert   │ verify-  │ TLS listener :8443         │
 │ + scram (mTLS)         │ full     │ client cert: jira_readonly │
 │ volume: pgdata         │          │ volume: pgadmin            │
 └────────────────────────┘          └────────────────────────────┘
```

Networks:
- `edge` — only `app`; used for the published ports.
- `backend` — `app`, `db`, `pgadmin`; `internal: true`, so `db` and `pgadmin` have **no route to the internet**
  and no published ports. (Dev override may bind `db` to `127.0.0.1:5432` — never in production.)

### 3.2 Key architectural decisions (summary)

| Decision | Why | ADR |
|---|---|---|
| Nginx in the app container under supervisord | Requirement of exactly 3 containers plus Nginx | 0003 |
| Nginx → Uvicorn over a Unix socket | No network hop to protect; no TCP port for an attacker to reach (V12.3.3) | 0004 |
| pgAdmin on a separate hostname, IP-allowlisted | Separate applications must not share an origin (ASVS V3.5.4); pgAdmin is a high-value admin tool | 0005 |
| TLS on every network connection, internal CA | ASVS V12.3.1/V12.3.3/V12.3.4 | 0010 |
| Opaque server-side sessions, not JWT | Immediate revocation on logout/disable (V7.4.1/V7.4.2), no token-algorithm attack surface | 0006 |
| DB connections need a client certificate + password | Backend auth can't rely on fixed passwords alone (V13.2.1) | 0012 |
| ClamAV in the app container | Uploaded files must be virus-scanned (V5.4.3) | 0015 |

### 3.3 Request flow

1. Browser loads `https://${APP_HOST}/` → Nginx serves `index.html` (no-cache) + hashed assets (immutable).
2. SPA calls `/api/v1/...`. The browser sends the `__Host-session` cookie automatically (same origin);
   unsafe methods also send `X-CSRF-Token`. Nginx overwrites `X-Forwarded-For`/`X-Real-IP` with the real peer address.
3. FastAPI middleware: request ID → size/time limits → session lookup → CSRF/Origin check → rate limit → router.
4. Router → service (authorization + business rules + transaction) → repository → PostgreSQL (TLS, app role).
5. After commit, the service emits a domain event → `pg_notify` → every worker's listener → WebSocket clients
   subscribed to that project **and still authorized** (membership re-checked) → SPA invalidates queries.
6. Attachments: upload via API → validated (type, size) → written to quarantine → scanned by `clamd` (fail closed) → moved to storage under a random UUID name. Download: API checks permission,
   responds with `X-Accel-Redirect`; Nginx streams the file with `Content-Disposition: attachment`,
   `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: sandbox; default-src 'none'`.
7. Security events (auth, authz failures, admin actions, validation bypass attempts) go to the structured log
   **and** the append-only, hash-chained `audit_log` table.

### 3.4 Backend layering

```
api/        FastAPI routers: HTTP concerns only; every route declares a permission (enforced by a test)
schemas/    Pydantic models; separate Create/Update/Read models per resource; extra="forbid"
services/   Business rules, authorization (policy.py), transactions, domain events, audit events
repos/      SQLAlchemy queries; always scoped by project/user passed from the service
models/     SQLAlchemy ORM models
core/       config (pydantic-settings, reads /run/secrets), security (hashing, tokens, crypto),
            db session, middleware (headers, CSRF, rate limit, limits, request ID), errors, logging, audit
jql/        grammar + compiler + limits
realtime/   WebSocket manager + LISTEN/NOTIFY listener
```

Rules: routers never touch the ORM; services own the transaction; **authorization is enforced in services
through a single policy module** and never relies on the client; responses use explicit Read schemas
(never return ORM objects directly).

---

## 4. Repository layout

```
.
├── CLAUDE.md                       # conventions for agents (incl. security rules)
├── README.md
├── docs/
│   ├── PLAN.md  PROGRESS.md
│   ├── decisions/                  # ADRs — the decision log (README.md = index)
│   └── security/                   # security documentation space (README.md = index)
│       ├── security-requirements.md
│       ├── threat-model/ (summary.md, detailed.md)
│       ├── asvs/ (official CSV, verification-matrix.csv, README.md)
│       ├── testing/ (security-test-plan.md, reports/)
│       └── security-review.md      # written at the end (template: security-review-TEMPLATE.md)
├── docker/
│   ├── app.Dockerfile  supervisord.conf  entrypoint.sh
│   ├── nginx/ (nginx.conf, app.conf, pgadmin.conf, tls.conf, security-headers.conf)
│   ├── postgres/ (postgresql.conf, pg_hba.conf, init/ role-setup scripts)
│   └── pgadmin/ (servers.json, config_local.py)
├── compose.yaml  compose.override.yaml  .env.example
├── secrets/                        # git-ignored; created by `make secrets` (only README.md committed)
├── certs/                          # git-ignored; created by `make certs`  (only README.md committed)
├── Makefile
├── tools/security/                 # scripts: asvs_matrix.py, scan wrappers, header checks
├── backend/  (app/, alembic/, scripts/, tests/{unit,integration,security})
├── frontend/ (src/, tests/)
└── e2e/      (functional/ and security/ Playwright specs)
```

---

## 5. Data model (PostgreSQL 18)

Conventions: `id uuid primary key default uuidv7()`, `created_at`/`updated_at timestamptz not null default now()`,
snake_case, FKs indexed, enums as `text` + `CHECK`, all timestamps UTC.

| Table | Key columns | Constraints / indexes |
|---|---|---|
| `users` | email (citext), display_name, password_hash, avatar_attachment_id, is_active, is_site_admin, password_changed_at, failed_login_count, locked_until, last_login_at | unique(email) |
| `sessions` | user_id, token_hash (sha256), created_at, last_seen_at, idle_expires_at, absolute_expires_at, mfa_verified_at, reauth_at, ip, user_agent, revoked_at, revoked_reason | unique(token_hash), index(user_id) |
| `mfa_totp` | user_id, secret_ciphertext, key_id, algorithm, drift_steps, last_used_step, confirmed_at | unique(user_id) |
| `mfa_webauthn` | user_id, credential_id, public_key, sign_count, transports, name, last_used_at | unique(credential_id) |
| `mfa_recovery_codes` | user_id, code_hash (argon2id), used_at | |
| `one_time_tokens` | purpose (`setup`/`invite`/`password_reset`/`mfa_reset`), user_id, token_hash, expires_at, used_at, created_by | unique(token_hash) |
| `login_attempts` | email_hash, ip, succeeded, created_at | index(email_hash, created_at), index(ip, created_at) — throttling |
| `audit_log` | occurred_at, actor_id, actor_ip, session_id_hash, event, target_type, target_id, outcome, details jsonb, prev_hash, row_hash | **append-only** (app role has INSERT only; trigger blocks UPDATE/DELETE); hash chain |
| `projects` | key, name, description, lead_id, template, issue_counter, archived_at | unique(key), key `~ '^[A-Z][A-Z0-9]{1,9}$'` |
| `project_members` | project_id, user_id, role (`admin`/`member`/`viewer`) | pk(project_id, user_id) |
| `statuses`, `transitions`, `boards`, `board_columns`, `board_column_statuses` | as in workflow design | uniqueness per project |
| `sprints` | project_id, name, goal, state, start_at, end_at, completed_at | partial unique: one `active` per project |
| `issues` | project_id, number, key, type, summary, description jsonb, description_text, status_id, priority, assignee_id, reporter_id, parent_id, sprint_id, story_points, due_date, rank, resolved_at, version int, search tsvector (generated, stored) | unique(project_id, number), unique(key), GIN(search), index(project_id, sprint_id, rank) |
| `labels`, `issue_labels`, `issue_links`, `watchers` | | |
| `comments` | issue_id, author_id, body jsonb, body_text, edited_at, deleted_at | |
| `attachments` | issue_id (nullable for avatars), uploader_id, original_filename (display only), stored_name (uuid), content_type (detected), size_bytes, sha256 | |
| `issue_history`, `notifications`, `saved_filters`, `sprint_snapshots` | | |
| `settings` | key, value jsonb (e.g. `registration_open`) | |

Key rules:
- **Issue numbering**: `UPDATE projects SET issue_counter = issue_counter + 1 ... RETURNING` in the create transaction.
- **Ranking**: fractional-index strings; `/move` sends `{before_id, after_id}`, server computes rank.
- **Optimistic concurrency**: `issues.version`, checked via `If-Match`; 409 on conflict.
- **Status change** must match a `transitions` row. Every tracked field change writes `issue_history` in the same transaction.

**Database roles** (ADR-0012): `jira_owner` (owns schema, used only by migrations at startup), `jira_app`
(runtime: DML on app tables, INSERT-only on `audit_log`, no DDL), `jira_readonly` (for pgAdmin day-to-day use),
superuser `postgres` (break-glass only; password in a secret file). Per-role `statement_timeout`
(`jira_app`: 5s) and connection limits.

PostgreSQL 18 notes: the `postgres:18` image keeps data under `/var/lib/postgresql/18/docker`; mount the volume
at **`/var/lib/postgresql`**. `ssl = on`, `ssl_min_protocol_version = 'TLSv1.3'`, `password_encryption = scram-sha-256`,
`pg_hba.conf` allows only `hostssl ... scram-sha-256 clientcert=verify-full` from the backend subnet (break-glass `postgres` via local socket only); `log_connections`, `log_disconnections` on.

---

## 6. API design

- Base `/api/v1`; JSON only (`Content-Type: application/json; charset=utf-8` enforced on requests with bodies).
- OpenAPI/docs exposed **only in development** (V13.4.5).
- Errors: `{"error": {"code", "message", "request_id"}}`; unexpected errors return a generic 500 with `request_id`
  only — never stack traces or SQL (V16.5.1).
- Cursor pagination with `limit` ≤ 100.
- Sensitive operations use POST/PUT/PATCH/DELETE only (V3.5.3); no secrets in URLs (V14.2.1).

```
Auth/session
POST /auth/setup            (one-time bootstrap token → first admin)
POST /auth/register         (only if registration_open)     POST /auth/invite/accept
POST /auth/login            → password step → session in "mfa_pending" state
POST /auth/mfa/totp/verify | /auth/mfa/webauthn/verify | /auth/mfa/recovery/verify  → full session (rotated)
POST /auth/mfa/totp/enroll | /confirm      POST /auth/mfa/webauthn/register/options | /register
POST /auth/mfa/recovery-codes/regenerate   (step-up required)
POST /auth/reauth           (step-up; sets reauth_at)
POST /auth/password/change  (current + new; step-up; offers "sign out other sessions")
POST /auth/password/reset   (admin-issued one-time token; MFA still required afterwards)
POST /auth/logout           GET /auth/me    GET /auth/csrf
GET  /auth/sessions         DELETE /auth/sessions/{id}   DELETE /auth/sessions (all others)
Admin
GET /admin/users  PATCH /admin/users/{id}  POST /admin/users/{id}/password-reset-link | /mfa-reset | /sessions/revoke
POST /admin/invites   GET /admin/audit-log   PATCH /admin/settings
Domain (unchanged from v1 plan)
/projects, /projects/{key}/members|statuses|transitions|boards|labels|backlog|sprints, /boards/{id},
/sprints/{id}/start|complete, /issues, /issues/{key}/transition|move|comments|attachments|links|watchers|history,
/search, /search/quick, /filters, /notifications, /reports/...
WS /ws       GET /healthz (public, returns only {"status":"ok"})
```

Authorization matrix (canonical copy in `docs/security/security-requirements.md` §5):
Viewer = read project data; Member = + create/edit issues, comment, move cards, upload; Project Admin = + members,
workflow, board config, sprints, delete issues; Site Admin = + users, settings, audit log. Non-members get **404**
(not 403) for project resources to avoid existence disclosure.

---

## 7. Frontend design

Routes: `/setup`, `/login`, `/login/mfa`, `/register`, `/invite/:token`, `/reset/:token`, `/mfa/enroll`,
`/projects`, `/projects/:key/{board,backlog,issues,reports,settings}`, `/browse/:issueKey`, `/filters`,
`/notifications`, `/profile`, `/profile/security` (password, MFA, sessions), `/admin/{users,audit,settings}`.

Security rules for the frontend:
- No `dangerouslySetInnerHTML`, `eval`, `new Function`, or string-based timers (lint-enforced).
- Rich text is rendered from validated TipTap JSON; links restricted to `http`, `https`, `mailto`.
- No tokens or sensitive data in `localStorage`/`sessionStorage`/IndexedDB (V14.3.3); on logout clear the Query cache
  and in-memory state; server sends `Clear-Site-Data: "cache", "storage"` on logout (V14.3.1).
- CSP compatible: no inline scripts or styles at runtime (Vite build configured accordingly).
- Visible logout on every authenticated page (V7.4.4).
- Use `Map`/`Set` or `Object.create(null)` for dynamic keys (prototype-pollution, V15.3.6).

---

## 8. Docker and infrastructure

### 8.1 App image (`docker/app.Dockerfile`, multi-stage)
1. `frontend-build` — `node:22-alpine` (digest-pinned), `pnpm install --frozen-lockfile`, `pnpm build`.
2. `backend-build` — `python:3.13-slim`, `uv sync --frozen --no-dev` → `/opt/venv`.
3. `runtime` — `python:3.13-slim` + `nginx` + `supervisor`; non-root user `app` (uid 10001); no compilers, no shell
   tools beyond what the entrypoint needs; no `.git`, tests, docs, or source maps in the image (V13.4.1, V15.2.3);
   `HEALTHCHECK` via the Unix socket.

### 8.2 Nginx
- TLS: `ssl_protocols TLSv1.2 TLSv1.3;` Mozilla "intermediate" cipher list with server preference; OCSP stapling
  when a public cert is used; session tickets off.
- Headers on every response (`security-headers.conf`, with `always`):
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` (deny camera, mic, geolocation, etc.),
  `Cache-Control: no-store` on `/api/` responses.
- `server_tokens off;` `autoindex off;` reject methods other than GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS (TRACE → 405);
  default server returns 444 for unknown `Host`.
- `client_max_body_size` 25m on the upload route, 1m elsewhere; timeouts; `limit_req` zones for `/api/v1/auth/` and global per-IP;
  `limit_conn` per IP.
- `proxy_set_header X-Forwarded-For $remote_addr;` (overwrite, never append) and `X-Forwarded-Proto https`.
- HTTP listener: redirect to HTTPS **only** for browser page routes; `/api/*` over HTTP returns 400 without redirect (V4.1.2).
- pgAdmin server block: `allow ${PGADMIN_ALLOWED_CIDRS}; deny all;`, separate hostname and certificate, `proxy_ssl_verify on`
  with the internal CA.

### 8.3 `compose.yaml` (outline — builder fills in exact values)
```yaml
services:
  app:
    build: { context: ., dockerfile: docker/app.Dockerfile }
    read_only: true
    tmpfs: [/tmp, /run/app, /var/lib/nginx, /var/cache/nginx]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    pids_limit: 512
    mem_limit: 3g        # includes ~1.5 GB for clamd signatures
    ports: ["${APP_HTTPS_PORT:-8443}:8443", "${APP_HTTP_PORT:-8080}:8080"]
    secrets: [db_app_password, db_owner_password, app_secret_key, field_encryption_key, setup_token]
    volumes: [attachments:/data/attachments, clamav-db:/var/lib/clamav, ./certs/app:/certs:ro]
    depends_on: { db: { condition: service_healthy } }
    networks: [edge, backend]
  db:
    image: postgres:18.x@sha256:<digest>
    environment: { POSTGRES_PASSWORD_FILE: /run/secrets/db_superuser_password }
    secrets: [db_superuser_password, db_owner_password, db_app_password, db_readonly_password]
    volumes: [pgdata:/var/lib/postgresql, ./docker/postgres:/etc/jira-postgres:ro, ./certs/db:/certs:ro]
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID]   # verify the minimal set
    security_opt: ["no-new-privileges:true"]
    networks: [backend]
  pgadmin:
    image: dpage/pgadmin4:<version>@sha256:<digest>
    # TLS listener, enhanced cookie protection, master password required; default password via secret file
    networks: [backend]
networks:
  edge: {}
  backend: { internal: true }
volumes: { pgdata: {}, pgadmin: {}, attachments: {}, clamav-db: {} }
secrets: { ...: { file: ./secrets/<name> } }
```
Builder must verify each image's supported `*_FILE` variables and TLS options against the image documentation and
record anything non-obvious in an ADR.

### 8.4 Dev mode (`compose.override.yaml`)
Still 3 containers. Bind-mounts source, `uvicorn --reload` (still on the Unix socket), Vite dev server on
`127.0.0.1:5173` behind Nginx (HMR over `wss`). TLS stays on (internal CA). `APP_ENV=development` enables OpenAPI docs.
**Production builds must refuse to start with `APP_ENV=development` settings** (debug off, docs off; V13.4.2).

### 8.5 Configuration
Non-secret config in `.env` (`APP_ENV, APP_HOST, PGADMIN_HOST, APP_HTTPS_PORT, APP_HTTP_PORT, PGADMIN_ALLOWED_CIDRS,
UVICORN_WORKERS, MAX_UPLOAD_MB, SESSION_IDLE_MINUTES, SESSION_ABSOLUTE_HOURS, MAX_SESSIONS_PER_USER, LOG_LEVEL,
TRUSTED_PROXY_CIDRS`). Secrets only as files in `secrets/` (git-ignored, mode 600) mounted via Compose `secrets:`.
`make secrets` generates them with a CSPRNG; `make certs` creates the internal CA and leaf certs.
The app fails to start if any secret is missing, too short, or equal to a known example value.

### 8.6 Startup
`entrypoint.sh`: verify secrets/certs → wait for DB (TLS) → `alembic upgrade head` as `jira_owner` → drop to `jira_app`
credentials → if no admin exists, log that setup is required (the setup token itself is never logged) → `exec supervisord`.

---

## 9. Quality and functional testing

- Backend unit + integration tests (real PostgreSQL 18 over TLS); ≥ 85% line coverage on `services/`, `core/security/`, `jql/`.
- Frontend: vitest + Testing Library + MSW.
- E2E (Playwright) against the compose stack: setup → MFA enroll → create project → issues → sprint → board drag → comment → complete sprint → burndown.
- Static checks: `ruff check`, `ruff format --check`, `mypy --strict`, `eslint`, `tsc --noEmit`, `prettier --check`.
- API contract: regenerate `frontend/src/api/schema.d.ts` in CI and fail on diff.
- `make check` = all static checks + unit/integration tests (backend and frontend) + security unit tests.

---

## 10. Security program

The documentation space is `docs/security/`. Its index (`docs/security/README.md`) lists every document, owner work
package and status.

### 10.1 Standards baseline (ADR-0021)
- **OWASP ASVS 5.0.0**, Levels 1 and 2 — 253 requirements (70 L1 + 183 L2). Official requirement list is vendored at
  `docs/security/asvs/asvs-5.0.0-en.csv` (SHA-256 `6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5`).
- **OWASP Top 10:2025** (A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures,
  A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data
  Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions).
- **OWASP WSTG** as the black-box test methodology; **CVSS v4.0** for severity.

### 10.2 Threat modeling (Shostack's Four Question Framework)
Two documents, both structured around the four questions — *What are we working on? What can go wrong? What are we
going to do about it? Did we do a good enough job?*:
- `docs/security/threat-model/summary.md` — the short version (1–2 pages) for humans and reviewers.
- `docs/security/threat-model/detailed.md` — DFDs, trust boundaries, assets, actors, STRIDE-per-element threat register
  with IDs, mitigations mapped to ASVS requirements and test IDs, residual risk, and the Q4 review.

The design-time version exists now. **Every work package must check whether it changes the threat model**; if so
the builder updates both documents in the same change. WP-24 performs the final refresh and the Q4 retrospective.

### 10.3 ASVS verification
`docs/security/asvs/verification-matrix.csv` holds one row per L1/L2 requirement with: applicability, status,
implementation reference (`file:line`), verification method (automated test / white-box review / black-box test /
documentation), evidence (test ID or report link), owner WP. Maintained with `tools/security/asvs_matrix.py`.
Rows marked **N/A** need a written justification and the auditor's approval. Requirements that depend on how the
operator deploys (public TLS certificate V12.2.2, remote log sink V16.4.3, secrets backend V13.3.1) are implemented
and documented as deployment requirements, verified in the reference deployment, and listed in the security review.

### 10.4 Security testing (details in `docs/security/testing/security-test-plan.md`)
| Type | Who | Knowledge | What |
|---|---|---|---|
| Continuous automated | CI on every merge | full | SAST (Semgrep, ruff `S`, eslint-security), secrets scan (gitleaks), SCA (pip-audit, pnpm audit, osv-scanner), image/config scan (Trivy, Hadolint), SBOM (Syft), security unit/integration tests (`tests/security`), header and TLS checks |
| **White-box** | `security-auditor` agent | full source + configs | Manual code review of every endpoint and security control, ASVS L1/L2 verification with evidence, config review, crypto inventory check |
| **Black-box** | `pentester` agent | URL + two test accounts only, no source | WSTG-based testing, ZAP active + API scan, Schemathesis fuzzing, testssl.sh, manual OWASP Top 10:2025 tests |
| **Red team** | `red-team` agent | goals only | Objective-driven attack chains (e.g. viewer → site admin, read another project's data, reach pgAdmin/DB, persist access, tamper with audit log undetected) and detection check (was it logged/alerted?) |
| OWASP Top 10 suite | builders, run in CI | — | `backend/tests/security/` and `e2e/security/` contain at least one automated test per Top 10 category and per ASVS requirement marked "automated" |

### 10.5 Additional security measures (beyond the requested baselines)
Mandatory MFA with WebAuthn support; append-only hash-chained audit log; per-account and per-IP throttling; anomaly
alerts written as high-severity log events (credential stuffing patterns, repeated authz failures, MFA brute force);
hardened containers (non-root, read-only rootfs, dropped capabilities, no-new-privileges, resource limits); internal
networks without egress; least-privilege DB roles with statement timeouts; field-level encryption of MFA secrets;
antivirus scanning of uploads; mutual-TLS database authentication; SBOM per build and pinned base images by digest; GitHub Actions pinned by commit SHA with least-privilege
`permissions:`; pre-commit secret scanning; `security.txt`; backup encryption guidance; `make security-scan` for local
runs; a security regression test for every fixed finding.

### 10.6 Security release gates (all must hold to finish)
1. Zero open findings rated Critical, High, or Medium (CVSS v4.0) from any test type. Low/Informational findings are
   fixed or accepted in an ADR with rationale and owner.
2. All 253 ASVS L1+L2 rows are **Pass** or **N/A (approved)**, each with evidence; deployment-dependent rows documented.
3. At least one passing automated test per OWASP Top 10:2025 category, and black-box + red-team reports show no
   exploitable issue in any category.
4. CI security jobs green: no secrets found; no known-exploitable or High/Critical vulnerabilities with an available fix in
   dependencies or images; SBOM published.
5. Threat model final (both versions) with every threat mitigated, transferred, or explicitly accepted.
6. `docs/security/security-review.md` complete and signed off by the orchestrator, with the user informed of residual risks.

Honest limits: these gates show the application meets the stated standards as verified by automated tools and agent
reviews. They are not a third-party certification; an independent human penetration test before production use is
recommended, and the security review says so.

---

## 11. Work packages

Every WP's acceptance criteria (AC) implicitly include: `make check` green; CI security jobs green; relevant ASVS rows
updated in the verification matrix with evidence; threat model updated if the WP changed data flows, trust boundaries,
assets, or entry points; any new decision recorded as an ADR.

### Phase 0 — Foundation and security baseline

**WP-01 Repo scaffolding & tooling** — deps: none
- Layout per §4, `.gitignore` (secrets/, certs/, .env), `.editorconfig`, `Makefile`, `.env.example`, pre-commit (gitleaks,
  ruff, eslint, prettier). Backend skeleton with `/api/v1/healthz`; frontend skeleton (TS strict, Tailwind, lint rules
  banning `dangerouslySetInnerHTML`/`eval`).
- AC: `make check` passes; gitleaks pre-commit blocks a planted fake secret (demonstrated, then removed).

**WP-02 Secrets & internal PKI** — deps: WP-01
- `make secrets` (CSPRNG, mode 600, refuses to overwrite without `FORCE=1`), `make certs` (internal CA with
  name constraints, server certs for `APP_HOST`, `PGADMIN_HOST`, `db`, `pgadmin`; client certs for `jira_owner`, `jira_app`,
  `jira_readonly` (90-day); ECDSA P-256, SHA-256), `make certs-rotate-clients`,
  config loader reading `/run/secrets`, startup validation of secrets. Document key/cert inventory (security-requirements §9).
- AC: no secret appears in any env var, image layer (`docker history`, Trivy secret scan) or git; app refuses weak/missing secrets.

**WP-03 Hardened Docker stack** — deps: WP-01, WP-02
- Dockerfile, supervisord (nginx, uvicorn, clamd, freshclam), Nginx (TLS, headers, limits, pgAdmin host + allowlist),
  Postgres (TLS-only, client cert + scram, hba),
  pgAdmin (TLS, servers.json with `verify-full`), networks (`backend` internal), container hardening, dev override.
- AC: exactly 3 containers healthy; `https://APP_HOST:8443` serves the SPA; testssl.sh shows only TLS 1.2/1.3 and no weak
  ciphers; a header check script confirms every §8.2 header on SPA, API, and error responses; non-TLS DB connections, connections without a client certificate, and certificates whose CN doesn't match the role are
  rejected; `db`/`pgadmin` cannot reach the internet; pgAdmin reachable only on its own host and only from allowlisted CIDRs;
  TRACE → 405; unknown Host → connection closed; Trivy config scan clean; data survives restart.

**WP-04 Database core, migrations & roles** — deps: WP-01 (parallel with WP-03)
- Async engine (TLS `verify-full`), Alembic, base mixins, role setup (§5), initial migration with all §5 tables, audit-log
  append-only trigger + hash chain, per-role `statement_timeout`.
- AC: `jira_app` cannot run DDL, cannot UPDATE/DELETE `audit_log`, cannot read other roles' passwords; upgrade/downgrade work.

**WP-05 CI & supply-chain security** — deps: WP-01, WP-03
- GitHub Actions: lint, typecheck, tests (Postgres 18 service), Semgrep, gitleaks, pip-audit, pnpm audit, osv-scanner,
  Hadolint, Trivy (fs, image, config), Syft SBOM artifact, header/TLS smoke test against the built stack. Actions pinned by
  SHA, `permissions: contents: read` by default, Dependabot for pip/npm/docker/actions. Remediation SLAs per ADR-0023.
- AC: pipeline runs locally (`make ci` or `act`) green; a deliberately vulnerable dependency makes it fail (demonstrated, reverted).

**WP-06 Backend security foundations** — deps: WP-04
- Middleware: request ID, body-size and time limits, security headers for API responses, CSRF + Origin check, rate limiter
  (DB-backed counters per account + Nginx per IP), strict JSON content-type, generic error handler, fail-closed defaults.
- Structured JSON logging (UTC, request ID, user ID, IP, event; log-injection-safe encoding; secret/PII redaction),
  security event catalogue (security-requirements §10), audit log writer.
- Route-permission registry + a test that fails if any route lacks a declared permission (except an explicit public allowlist).
- AC: tests prove CSRF rejection, oversized body rejection, generic 500s without internals, log redaction, and the
  route-permission test catches an undeclared route.

### Phase 1 — Identity

**WP-07 Authentication & sessions backend** — deps: WP-06
- Setup token bootstrap, invites, optional registration, login with throttling/backoff (no user enumeration in responses or
  timing), password policy (ADR-0013), Argon2id, opaque sessions (ADR-0006/0008) with rotation on login and step-up,
  idle/absolute timeouts, max sessions, logout (server-side revoke + `Clear-Site-Data`), list/revoke sessions, revoke all on
  disable/password change, admin-issued password reset (ADR-0022).
- AC: tests for every ASVS V6.2, V6.3.1–2, V6.4.1–3, V7.2, V7.3, V7.4, V7.5 requirement; enumeration test (same response
  and similar timing for unknown email vs wrong password).

**WP-08 MFA** — deps: WP-07
- TOTP (seed via CSPRNG, AES-256-GCM at rest, single 30-second acceptance step with enrollment-time drift offset per ADR-0007,
  replay prevention via `last_used_step`), WebAuthn (py_webauthn),
  recovery codes (argon2id hashed, single use), mandatory enrollment before any other API access, MFA brute-force throttling,
  MFA reset by admin after documented identity check.
- AC: tests for V6.3.3, V6.4.4, V6.5.1–5; no endpoint other than MFA enrollment/verify/logout is reachable with an
  `mfa_pending` session (enumerated test over all routes).

**WP-09 Frontend shell & auth UI** — deps: WP-01, WP-07, WP-08
- Layout, router, generated client (CSRF header), setup/login/MFA/enroll/register/invite/reset pages, profile security page
  (password change, MFA management, sessions), logout everywhere visible.
- AC: full auth flows in the browser; password fields `type=password` with show toggle, paste allowed; no sensitive data in
  web storage (Playwright check).

### Phase 2 — Projects & issues

**WP-10 Projects, membership & authorization policy** — deps: WP-07
- Project CRUD, default workflow seeding, members & roles, central policy module, 404-for-non-members.
- AC: automated **authorization matrix test** — every route × {anonymous, non-member, viewer, member, project admin, site admin}
  with expected outcome; IDOR tests across two projects; field-level rules (e.g. email visibility) tested.

**WP-11 Issues backend** — deps: WP-10
- Issue CRUD, numbering, types/parent rules, transitions, labels, history, watchers, links, `/move`, rich-text JSON schema
  validation (allowlisted nodes/marks, URL protocol allowlist, size limits).
- AC: concurrency test for keys; invalid transitions rejected; mass-assignment attempts (e.g. `reporter_id`, `project_id`,
  `key`) ignored or rejected; rich-text payloads with scripts/`javascript:` links rejected.

**WP-12 Projects & issue UI** — deps: WP-09, WP-10, WP-11
- AC: viewer sees read-only UI **and** the API still rejects writes; XSS payloads in every text field render inertly.

### Phase 3 — Agile

**WP-13 Boards, backlog & sprints backend** — deps: WP-11
**WP-14 Board & backlog UI** — deps: WP-12, WP-13
(Functional AC as in the original plan: one active sprint; carry-over on completion; keyboard-accessible drag-and-drop;
optimistic updates with rollback.) Security AC: all board/sprint endpoints in the authz matrix; drag/move requests for
issues in other projects fail.

### Phase 4 — Collaboration

**WP-15 Comments, mentions, attachments, notifications backend** — deps: WP-11
- Attachments per ADR-0015: allowlisted types (by extension **and** magic bytes), size limit, quarantine + ClamAV scan (fail
  closed, archive limits), random stored name, SVG/HTML never rendered inline, per-project storage quota, weekly re-scan, download
  via X-Accel with sandbox CSP and RFC 6266 filename encoding.
- AC: EICAR test file rejected; uploads rejected with 503 while `clamd` is stopped; path traversal, polyglot, MIME-spoof, oversize,
  and archive-limit uploads rejected; mentions of non-members don't leak data.

**WP-16 Realtime** — deps: WP-11 (parallel with WP-15)
- `wss` only, Origin allowlist, session-cookie auth at handshake, subscriptions re-authorized on each event, socket closed
  within 60 s of session revocation, message size/rate limits.
- AC: cross-origin handshake rejected; revoked session's socket closed; non-member receives no events.

**WP-17 Collaboration UI** — deps: WP-12, WP-15, WP-16

### Phase 5 — Search & reports

**WP-18 Search & JQL** — deps: WP-11
- Fixed field/operator/function set; parameterized SQLAlchemy only; results always filtered to projects the user can read;
  limits: max 50 clauses, max depth 10, max 2 KB query, `statement_timeout`.
- AC: grammar tests incl. error positions; injection corpus; JQL cannot return issues from non-member projects; ReDoS/DoS corpus.

**WP-19 Search, filters & reports UI** — deps: WP-12, WP-13, WP-18

### Phase 6 — Completion

**WP-20 Admin UI, audit log viewer, seed data & polish** — deps: WP-14, WP-17, WP-19
- Seed data creates no default credentials (seed users get random passwords printed once, dev only; seeding disabled in production).

**WP-21 Functional E2E suite** — deps: WP-20

### Phase 7 — Security verification and sign-off

**WP-22 White-box assessment** — deps: WP-21. Agent: `security-auditor`.
- Full code and configuration review against ASVS L1/L2; complete the verification matrix with evidence; crypto inventory
  and key-management review; SAST triage. Output: `docs/security/testing/reports/white-box-report.md`.

**WP-23 Black-box assessment** — deps: WP-21 (parallel with WP-22). Agent: `pentester`.
- Fresh stack, no source access. WSTG + OWASP Top 10:2025 test cases from the test plan, ZAP, Schemathesis, testssl.sh.
  Output: `docs/security/testing/reports/black-box-report.md`.

**WP-24 Red-team exercise** — deps: WP-22, WP-23 findings remediated. Agent: `red-team`.
- Objectives from the test plan §6; tests detection (audit log, alerts). Output: `docs/security/testing/reports/red-team-report.md`.

**WP-25 Remediation & retest loop** — runs whenever WP-22/23/24 produce findings.
- Each finding → fix by `builder` + regression test + retest by the agent that found it. Repeat until gates §10.6.1–4 hold.

**WP-26 Threat model finalization** — deps: WP-25.
- Refresh both threat-model documents against the built system; answer Q4 ("did we do a good enough job?") with the test results.

**WP-27 Security review document** — deps: WP-26.
- Write `docs/security/security-review.md` from the template: scope, methodology, results of each test type, ASVS summary,
  Top 10 summary, threat-model summary, findings and their resolution, accepted risks, deployment requirements, recommendation.

**WP-28 Documentation & release** — deps: WP-27.
- README (quick start incl. `make secrets certs up`, trusting the internal CA, setup token flow), operations guide (backups with
  encryption, key rotation, upgrading, log shipping), final run from a clean clone.

### Dependency graph

```
WP-01 ─┬─ WP-02 ── WP-03 ── WP-05
       └─ WP-04 ── WP-06 ── WP-07 ─┬─ WP-08 ── WP-09 (needs 01,07,08)
                                   └─ WP-10 ── WP-11 ─┬─ WP-12 (needs 09,10,11)
                                                      ├─ WP-13 ── WP-14 (needs 12)
                                                      ├─ WP-15 ┐
                                                      ├─ WP-16 ┴─ WP-17 (needs 12)
                                                      └─ WP-18 ── WP-19 (needs 12,13)
WP-14, WP-17, WP-19 ── WP-20 ── WP-21 ─┬─ WP-22 ┐
                                       └─ WP-23 ┴─ (WP-25 loop) ── WP-24 ── (WP-25 loop) ── WP-26 ── WP-27 ── WP-28
```

---

## 12. Orchestration protocol (for the agents)

The **main session is the orchestrator**; subagents cannot spawn further subagents, so the orchestrator does all spawning.

Agents: `builder` (implements), `checker` (functional + security review per WP, read-only), `security-auditor`
(white-box, read-only on code), `pentester` (black-box), `red-team` (adversary emulation).

1. Read this plan, `CLAUDE.md`, `docs/PROGRESS.md`, `docs/decisions/README.md`, `docs/security/README.md`.
2. Pick all WPs whose dependencies are `done`; run independent ones concurrently (each builder in its own git worktree,
   branch `wp-XX-<slug>`), max ~3 at a time.
3. For each WP: `builder` gets the WP text + the relevant plan sections + the relevant ASVS rows (filter the matrix by
   `owner_wp`). Then `checker` gets the same plus the builder's report.
4. NEEDS CHANGES → back to the builder (SendMessage if available); max 3 rounds, then ask the user.
5. PASS → merge to `main` (`WP-XX: <title>`), run `make check` on `main`, update `PROGRESS.md`.
6. New decisions → ADR in `docs/decisions/` (next free number) and a line in its index. Security-relevant decisions also
   get an entry in the threat model if they change a mitigation.
7. Changing architecture (container count, stack, data model shape, auth design) or relaxing any security requirement or gate
   needs the user's approval. **Never mark an ASVS row N/A, accept a finding, or skip a gate without an ADR.**
8. Phase 7 agents work on a fresh stack; the black-box pentester is given only the URL and test accounts.
9. Finish only when §10.6 and §13 hold; then report residual risks to the user.

---

## 13. Definition of done (whole project)

- From a clean clone: `cp .env.example .env && make secrets certs && docker compose up --build` → exactly three healthy
  containers (app, db, pgadmin); app at `https://${APP_HOST}:8443`; pgAdmin at `https://${PGADMIN_HOST}:8443` (allowlisted IPs only).
- Every feature in §1.1 works and is covered by tests; `make check`, `make e2e`, and `make security-scan` pass.
- All security release gates in §10.6 hold.
- Decision log complete; threat models, verification matrix, test reports and security review are in `docs/security/`.

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Nginx + Uvicorn in one container hides crashes | supervisord autorestart; healthcheck through Nginx to the API |
| Internal CA trust is fiddly for users | `make certs` prints trust instructions; production uses public certs for external hosts (V12.2.2) |
| Mandatory MFA adds friction | WebAuthn passkeys for one-tap login; recovery codes; admin-assisted reset |
| TOTP HMAC-SHA-256 unsupported by some authenticator apps | Setup screen lists verified compatible apps and won't complete until a code is confirmed; passkey alternative. SHA-1 is not offered (user decision, ADR-0007) |
| Agents over-claim verification | Evidence required per ASVS row; independent checker; black-box agent has no source access |
| Deployment-dependent ASVS requirements | Implemented, documented as operator requirements, verified in the reference deployment |
| ClamAV memory use (~1.5 GB) and signature download size | `mem_limit: 3g`; signatures on a persistent volume; offline update option |
| Rank strings grow | Rebalance when > 64 chars |
| Realtime events lost on reconnect | Refetch active queries on reconnect |
| PG18 image volume path change | Mount at `/var/lib/postgresql` |
