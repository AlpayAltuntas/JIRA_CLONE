# ADR-0011: Secrets management with Compose secrets

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V13.3.1, V13.3.2, V13.2.3, V6.3.2

## Context
ASVS V13.3.1 (L2) requires a secrets management solution to create, store, control access to, and destroy secrets, with none in source code or build artifacts. The project is a self-hosted Docker Compose stack without a vault service, and adding one would exceed three containers.

## Options considered
1. **Environment variables** — leak through `docker inspect`, process listings and crash dumps; rejected.
2. **Compose file-based secrets** mounted at `/run/secrets` — files never in images or git; per-service access.
3. **External vault (HashiCorp Vault, cloud KMS)** — strongest, but needs infrastructure outside the stack.

## Decision
Option 2 is the reference implementation, with a pluggable loader so option 3 can be added without code changes elsewhere:
- `make secrets` creates each secret (≥ 256-bit random; DB passwords 32+ random characters) in `secrets/` with mode 600, and refuses to overwrite existing files unless `FORCE=1`. It covers create; rotation is a documented procedure in the operations guide; destroy is `make secrets-destroy` (deletes the files after confirmation).
- Each service mounts only the secrets it needs (least privilege, V13.3.2).
- Secrets are read from files (`*_FILE` variables where images support them). Settings refuse missing secrets, secrets shorter than the minimum, and values equal to any example placeholder.
- No default credentials anywhere: no default app admin (a one-time setup token is used instead), no default DB or pgAdmin passwords.
- gitleaks runs in pre-commit and CI; Trivy scans images for embedded secrets.

## Security impact
Meets V13.3.1 at the reference-deployment level. The security review must state that file-based secrets on the Docker host are protected by host access control only, and recommend a vault or KMS for higher-assurance deployments. Residual risk: host compromise exposes secrets (T-031, accepted for L2 scope).

## Consequences
Operators must back up `secrets/` securely; losing `field_encryption_key` makes MFA seeds unreadable (users would need an MFA reset).
