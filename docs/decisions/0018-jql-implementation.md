# ADR-0018: JQL subset via a lark grammar with limits

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V1.2.4, V2.4.1, V15.1.3, V15.2.2; threat T-014, T-070

## Decision
- A `lark` LALR grammar parses the JQL subset defined in PLAN WP-18. The AST compiles to SQLAlchemy Core expressions using bound parameters only; field names map through a fixed dictionary (unknown field → 400 with position). No string-built SQL.
- Every compiled query is ANDed with `project_id IN (<projects the user can read>)` before execution.
- Limits: query ≤ 2,048 characters, ≤ 50 clauses, nesting depth ≤ 10, `IN` lists ≤ 100 values, text search terms ≤ 200 characters, page size ≤ 100, `statement_timeout` 5 s. The `~` operator uses full-text search (`websearch_to_tsquery`), never `LIKE` with user-controlled wildcards or regular expressions.
- Search is rate-limited per user (ADR-0024).

## Security impact
Prevents injection and authorization bypass through search, and limits resource exhaustion.

## Consequences
Unsupported JQL features produce clear errors rather than partial results.
