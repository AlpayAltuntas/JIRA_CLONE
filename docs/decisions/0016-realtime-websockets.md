# ADR-0016: Realtime over WebSockets with LISTEN/NOTIFY

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V4.4.1–V4.4.4; threats T-011, T-013

## Decision
- Endpoint `wss://APP_HOST/api/v1/ws`; plain `ws` is never offered (V4.4.1).
- Handshake checks `Origin` against the allowlist (V4.4.2) and authenticates with the existing `__Host-session` cookie (V4.4.3/V4.4.4: the standard session is reused, so no separate WS token).
- Clients subscribe to `project:<id>` or `issue:<key>`; authorization is checked on subscribe **and** before delivering each event (membership may have changed). Event payloads carry IDs and change types only; clients refetch data through the authorized REST API.
- Session validity is re-checked every 60 s and on revocation events; revoked or expired sessions are closed with code 4401.
- Limits: 64 KB max inbound message, 20 subscriptions per socket, 5 sockets per session, inbound rate limit.
- Fan-out: services call `pg_notify('jira_events', <json ≤ 7 KB>)` after commit; each Uvicorn worker holds one LISTEN connection. NOTIFY payloads never contain sensitive data.

## Security impact
Prevents cross-site WebSocket hijacking and data leakage to removed members.

## Consequences
No Redis needed; NOTIFY's 8 KB payload limit is respected by sending IDs only.
