# ADR-0002: Technology stack

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** user (TypeScript, Python, PostgreSQL 18+, Nginx, Docker), orchestrator (frameworks)
- **Related:** PLAN §2

## Context
The user required TypeScript, Python, PostgreSQL 18+, Nginx and Docker. Framework choices remain.

## Options considered
1. **FastAPI** vs Django vs Flask — FastAPI gives async, Pydantic validation, and OpenAPI generation (used for typed client and for black-box API fuzzing). Django brings a template/admin stack we don't need.
2. **React + Vite** vs Next.js vs Vue — a static SPA keeps the runtime to Nginx + Python (no Node server in production) and suits the strict CSP.
3. **SQLAlchemy 2 async + asyncpg + Alembic** — mature, parameterized by construction.

## Decision
Frontend: TypeScript (strict), React 19, Vite, React Router, TanStack Query, Zustand, Tailwind, Radix UI, dnd-kit, TipTap, Recharts. Backend: Python 3.13, FastAPI, Pydantic v2, SQLAlchemy 2 async, asyncpg, Alembic, Uvicorn. Database: PostgreSQL 18 with `uuidv7()` primary keys. Exact versions are pinned in lockfiles; base images are pinned by digest.

## Security impact
Memory-safe languages (ASVS V1.4 met by language choice). ORM gives parameterized queries (V1.2.4). Pydantic gives schema validation at the trusted layer (V2.2.1, V2.2.2). No server-side templates (V1.3.7).

## Scope confirmation
User confirmed on 2026-10-17: no external login providers (no "Log in with Microsoft/Google", SSO, SAML or OAuth/OIDC). Authentication is local accounts only (security-requirements §2). ASVS V6.8, V7.1.3, V7.6 and V10 therefore stay proposed N/A.

## Consequences
Two ecosystems to keep patched (see ADR-0023).
