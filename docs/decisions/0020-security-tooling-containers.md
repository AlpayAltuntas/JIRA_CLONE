# ADR-0020: Security tools run as ephemeral containers

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ADR-0003, PLAN §10.4

## Context
Scanning needs tools (ZAP, Trivy, Semgrep, testssl.sh, Schemathesis, gitleaks, Syft) that should not run inside the production stack. The user's 3-container rule describes the application runtime.

## Decision
All security and build tools run as short-lived containers (`docker run --rm`) or CI jobs, invoked through `make security-scan` and `tools/security/*.sh`. Their images are pinned by version and digest. They attach to the stack only through the published HTTPS port (black-box tools) or the source tree mounted read-only (white-box tools). Results go to `docs/security/testing/reports/raw/` (git-ignored except for summaries).

## Security impact
Keeps attack tooling out of production images (V15.2.3) and makes scans reproducible.

## Consequences
Contributors need Docker to run scans locally; CI provides the same jobs.
