# ADR-0017: Fractional-index ranking

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** PLAN §5

## Decision
Issue order uses fractional-index strings (base-62 midpoint between neighbours). Clients send `{before_id, after_id}`; the server computes the rank inside the transaction, verifying both neighbours belong to the same project and to a container (backlog/sprint/column) the user can modify. When a rank exceeds 64 characters, the affected list is rebalanced in one transaction.

## Security impact
The server never accepts a client-supplied rank, which prevents unbounded strings (DoS) and cross-project manipulation.

## Consequences
The same algorithm is needed in TypeScript only for optimistic UI display; the server value always wins.
