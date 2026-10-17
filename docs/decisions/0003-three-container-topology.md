# ADR-0003: Three-container topology with Nginx inside the app container

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** user (3 containers: application, database, pgAdmin; Nginx reverse proxy), orchestrator
- **Related:** PLAN §3.1, ADR-0004, ADR-0020

## Context
The user requires exactly three containers and Nginx as reverse proxy. A dedicated Nginx container would make four.

## Options considered
1. **Separate Nginx container** — conventional, but violates the 3-container requirement.
2. **Nginx inside the app container, managed by supervisord** — meets the requirement; one image to harden.
3. **Serve static files from FastAPI, no Nginx** — violates the Nginx requirement.

## Decision
The `app` image contains the built SPA, the Python backend and Nginx; `supervisord` runs and restarts both. Nginx is the only process with a network listener. The container runs as a non-root user with a read-only root filesystem. The 3-container limit applies to the **runtime** stack; short-lived tool containers for builds and security scans (ADR-0020) are not part of it.

## Security impact
One container holds the TLS key and the app secrets, so an RCE in either process exposes both. Mitigations: non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, Uvicorn has no TCP listener, secrets readable only by the app user. Recorded as threat T-030 in the detailed threat model.

## Consequences
Process supervision and health checks must cover both processes; logs from both go to stdout as JSON.
