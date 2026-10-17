# ADR-0005: pgAdmin on a separate hostname behind an IP allowlist

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V3.5.4, V12.3.1, V13.4.5, threats T-040..T-043

## Context
The first draft of the plan served pgAdmin under `/pgadmin/` on the app's origin. ASVS V3.5.4 (L2) requires separate applications to be hosted on different hostnames, so that a script running in one cannot read the other's cookies or DOM. pgAdmin gives full database access, so it is the most valuable target in the system.

## Options considered
1. **Path under the app origin** — fails V3.5.4.
2. **Separate port on the same host** — a different origin, but cookies are not isolated by port.
3. **Separate hostname (`PGADMIN_HOST`, e.g. `pgadmin.localhost`)** served by a dedicated Nginx server block.

## Decision
Option 3. Nginx has a separate `server` block for `PGADMIN_HOST` with its own certificate, `allow ${PGADMIN_ALLOWED_CIDRS}; deny all;` (default: loopback and private ranges, which operators should narrow), and TLS proxying to pgAdmin's own TLS listener with certificate verification. pgAdmin is configured with a master password, enhanced cookie protection, the default admin password from a secret file, and a server definition that connects as `jira_readonly` with `sslmode=verify-full`. Elevated DB work needs credentials for a higher role entered explicitly. The app's cookies use the `__Host-` prefix, so they are never sent to the pgAdmin host.

## Security impact
Removes cross-application script and cookie exposure; reduces reachable attack surface for pgAdmin vulnerabilities; makes accidental production writes through pgAdmin less likely.

## Consequences
Users need a second hostname; `*.localhost` resolves to loopback in current browsers, so local use needs no DNS changes. Production needs a DNS record and a public certificate for both hosts.
