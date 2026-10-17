# ADR-0014: Rich text stored as validated JSON, never raw HTML

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V1.2.1, V1.2.2, V1.3.1, V1.3.5, V3.2.2; threat T-012

## Context
Issue descriptions and comments are rich text: the main stored-XSS vector in a JIRA-like app.

## Decision
- The editor (TipTap) produces ProseMirror JSON. The API accepts **only** this JSON, never HTML or Markdown.
- The server validates it against an allowlist schema: node types (doc, paragraph, heading 1–3, bulletList, orderedList, listItem, codeBlock, blockquote, hardBreak, horizontalRule, text, mention), marks (bold, italic, strike, code, link), and attributes. Link `href` must parse as an absolute URL with scheme `http`, `https` or `mailto`. Mentions must reference a user who is a member of the issue's project. Limits: depth ≤ 20, ≤ 50,000 characters of text, ≤ 200 KB JSON.
- Rendering uses TipTap/React components that output text nodes; no `innerHTML`. Links get `rel="noopener noreferrer nofollow"` and `target="_blank"`.
- Pasted HTML is converted client-side by the editor; the server schema is the security boundary. If an HTML path is ever needed (e.g. export), it must use DOMPurify or `nh3` with an allowlist (V1.3.1), recorded in a new ADR.
- `description_text`/`body_text` (plain text extracted server-side) is used for search and notifications.

## Security impact
Removes HTML injection as a class at the API boundary; the CSP (`script-src 'self'`) is the second layer.

## Consequences
Rich-text features beyond the allowlist need a schema change and a security review.
