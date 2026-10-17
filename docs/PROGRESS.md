# Progress

Maintained by the orchestrator. Status: `todo` | `in-progress` | `review` | `done` | `blocked`.
Security gate status (PLAN §10.6) is tracked at the bottom.

| WP | Title | Phase | Status | Notes |
|---|---|---|---|---|
| WP-01 | Repo scaffolding & tooling | 0 | todo | |
| WP-02 | Secrets & internal PKI | 0 | todo | |
| WP-03 | Hardened Docker stack | 0 | todo | |
| WP-04 | Database core, migrations & roles | 0 | todo | |
| WP-05 | CI & supply-chain security | 0 | todo | |
| WP-06 | Backend security foundations | 0 | todo | |
| WP-07 | Authentication & sessions backend | 1 | todo | |
| WP-08 | MFA | 1 | todo | |
| WP-09 | Frontend shell & auth UI | 1 | todo | |
| WP-10 | Projects, membership & authorization policy | 2 | todo | |
| WP-11 | Issues backend | 2 | todo | |
| WP-12 | Projects & issue UI | 2 | todo | |
| WP-13 | Boards, backlog & sprints backend | 3 | todo | |
| WP-14 | Board & backlog UI | 3 | todo | |
| WP-15 | Comments, mentions, attachments (incl. antivirus), notifications backend | 4 | todo | |
| WP-16 | Realtime | 4 | todo | |
| WP-17 | Collaboration UI | 4 | todo | |
| WP-18 | Search & JQL | 5 | todo | |
| WP-19 | Search, filters & reports UI | 5 | todo | |
| WP-20 | Admin UI, audit log viewer, seed data & polish | 6 | todo | |
| WP-21 | Functional E2E suite | 6 | todo | |
| WP-22 | White-box assessment | 7 | todo | security-auditor |
| WP-23 | Black-box assessment | 7 | todo | pentester |
| WP-24 | Red-team exercise | 7 | todo | red-team |
| WP-25 | Remediation & retest loop | 7 | todo | runs as needed |
| WP-26 | Threat model finalization | 7 | todo | |
| WP-27 | Security review document | 7 | todo | |
| WP-28 | Documentation & release | 7 | todo | |

## Security release gates (PLAN §10.6)

| # | Gate | Status |
|---|---|---|
| 1 | No open Critical/High/Medium findings; Lows fixed or accepted by ADR | not started |
| 2 | ASVS 5.0.0 L1+L2: 253/253 Pass or approved N/A (`asvs_matrix.py --gate`) | 0 / 253 |
| 3 | OWASP Top 10:2025: every category has passing automated tests; no exploitable issue in BB/RT reports | not started |
| 4 | CI security jobs green; SBOM published | not started |
| 5 | Threat model final; every threat mitigated, transferred or accepted | design-time v0.1 |
| 6 | Security review complete and signed off | not started |
