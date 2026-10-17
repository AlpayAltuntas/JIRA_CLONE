# JIRA Clone

Self-hosted clone of Atlassian JIRA Software that must meet **OWASP ASVS 5.0.0 L1+L2** and pass **OWASP Top 10:2025**
white-box, black-box and red-team testing.

Read before any work:
- `docs/PLAN.md` — master plan (architecture, work packages, orchestration protocol, security gates)
- `docs/PROGRESS.md` — work-package status
- `docs/decisions/README.md` — decision log (ADRs); decisions there are binding
- `docs/security/README.md` — security documentation space (requirements, threat model, ASVS matrix, test plan)

## Stack
- Frontend: TypeScript (strict), React + Vite SPA, TanStack Query, Tailwind + Radix, dnd-kit, TipTap — `frontend/`
- Backend: Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2 async (asyncpg), Alembic — `backend/`
- Database: PostgreSQL 18 (`uuidv7()` PKs), TLS + client-certificate + SCRAM auth, least-privilege roles. Volume at `/var/lib/postgresql`.
- Docker: exactly 3 runtime containers — `app` (Nginx + Uvicorn + ClamAV under supervisord), `db`, `pgadmin` (own hostname, IP-allowlisted).

## Conventions
- Backend layering: `api/` → `services/` → `repos/` → `models/`. Routers never use the ORM; services own transactions and
  authorization (single policy module). Every route declares a permission.
- API under `/api/v1`; error shape `{"error": {"code", "message", "request_id"}}`; cursor pagination.
- Frontend API types are generated from OpenAPI (`make api-types`); never hand-write them.
- Schema changes only via Alembic migrations (with grants for `jira_app`/`jira_readonly`); never edit an applied migration.
- Python: ruff (incl. `S`) + mypy --strict. TS: eslint (+ security plugins) + prettier + tsc --noEmit. Tests: pytest, vitest, Playwright.
- `make check` must pass before a work package is done.

## Security rules (non-negotiable)
- No secrets in code, env vars, images, logs, URLs or git. Secrets are files in `secrets/` (git-ignored), mounted as Compose secrets.
- Sessions are opaque server-side tokens in `__Host-` cookies (no JWT). MFA is mandatory. CSRF token + Origin check on unsafe methods.
- Input: strict Pydantic schemas with `extra="forbid"`. Output: explicit Read schemas only.
- Never: string-built SQL, `eval`/`exec`, `pickle`/`yaml.load` on untrusted data, `subprocess` with user input, `dangerouslySetInnerHTML`,
  raw HTML from users, UUIDs or `random` as secrets (use `secrets`, ≥ 128 bits), MD5/SHA-1/AES-128/ECB for new crypto.
- Errors fail closed and return generic messages with a `request_id`.
- Emit the security events in `docs/security/security-requirements.md` §10.3; never log secrets or tokens.
- Any change to a security value, any ASVS N/A, any accepted risk, any deviation from the plan → ADR in `docs/decisions/`.
- Changes to entry points, data flows, trust boundaries or assets → update `docs/security/threat-model/` in the same change.
- Update your rows in `docs/security/asvs/verification-matrix.csv` (`python3 -I tools/security/asvs_matrix.py --wp WP-XX`).

## Agents
`builder` implements a WP; `checker` verifies it (functional + security, read-only); `security-auditor` (white-box), `pentester`
(black-box, no source access), `red-team` (objective-based) run in Phase 7. The main session orchestrates per `docs/PLAN.md` §12.
