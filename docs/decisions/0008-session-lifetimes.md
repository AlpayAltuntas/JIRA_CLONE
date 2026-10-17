# ADR-0008: Session timeouts and concurrency limits

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V7.1.1, V7.1.2, V7.3.1, V7.3.2, V7.5.1, V7.5.2

## Context
ASVS requires documented inactivity and absolute session lifetimes with justification (V7.1.1), a documented concurrent-session policy (V7.1.2), and re-authentication for sensitive changes (V7.5.1).

## Decision
| Setting | Default | Config | Justification |
|---|---|---|---|
| Inactivity timeout | 30 minutes | `SESSION_IDLE_MINUTES` (allowed 5–60) | Project data is internal and sensitive; mandatory MFA keeps re-login cheap with passkeys |
| Absolute lifetime | 12 hours | `SESSION_ABSOLUTE_HOURS` (allowed 1–24) | Covers a working day; forces a daily re-login |
| `mfa_pending` session lifetime | 5 minutes | fixed | Limits the window for the second step |
| Step-up freshness | 5 minutes | fixed | Needed for password change, MFA changes, email change, regenerating recovery codes, revoking other sessions, and admin security actions |
| Max concurrent sessions per user | 10 | `MAX_SESSIONS_PER_USER` | When exceeded, the oldest session is revoked and the user notified in-app |

**Comparison with NIST SP 800-63B (V7.1.1):** the defaults equal the AAL2 re-authentication values of SP 800-63B revision 3 (re-authenticate at least every 12 hours; 30-minute inactivity limit) and aren't looser than later revisions. There is therefore no deviation to justify. The white-box auditor confirms this against the current revision of SP 800-63B and records it in the verification matrix. Configuring values outside the allowed ranges is impossible; values looser than the AAL2 limits require a new ADR with justification.

Sessions are revoked on: logout, expiry, password change (others revoked on user choice, defaulting to yes), MFA reset, account deactivation (all sessions), and admin "terminate sessions" (one user or all users). Users can list and revoke their sessions after step-up (V7.5.2).

## Security impact
Limits session hijack windows (T-005); meets V7.3 and V7.4.

## Consequences
The frontend shows a warning 2 minutes before idle expiry and re-checks session state on window focus.
