# ADR-0001: Record decisions as ADRs

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** user, orchestrator
- **Related:** PLAN §12

## Context
Many agents work on this project in parallel and across sessions. Without a written record, decisions get re-litigated or silently changed, and security reviewers cannot trace why a control exists.

## Options considered
1. **Decisions inside PLAN.md only** — simple, but loses history when the plan changes.
2. **ADRs in `docs/decisions/`** — one immutable file per decision, with an index.

## Decision
Use lightweight ADRs (`template.md`) in `docs/decisions/`, numbered sequentially, indexed in `README.md`. Accepted ADRs are immutable; changes happen through superseding ADRs. The README lists decisions that always require an ADR.

## Security impact
Gives auditors traceability for every control, N/A justification and accepted risk (supports ASVS documentation requirements such as V6.1.1, V7.1.1, V8.1.1, V15.1.1).

## Consequences
Every builder must write an ADR for non-trivial choices; the checker flags undocumented decisions.
