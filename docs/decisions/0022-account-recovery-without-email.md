# ADR-0022: Password reset and MFA recovery without email

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** orchestrator
- **Related:** ASVS V6.4.1, V6.4.3, V6.4.4, V6.3.2, V7.4.3; threat T-004

## Context
v1 has no email delivery. ASVS requires a secure forgotten-password process that doesn't bypass MFA (V6.4.3), identity proofing on MFA loss (V6.4.4), and short-lived, single-use initial codes (V6.4.1).

## Decision
- **Bootstrap:** on first start with no admin, the app reads a one-time setup token from the `setup_token` secret file. `POST /auth/setup` with that token creates the first admin (who must then enroll MFA). The token is consumed and refused afterwards. Never logged.
- **Invites:** admins create invite links (256-bit token, 72-hour expiry, single use, bound to an email). Delivered out-of-band by the admin.
- **Forgotten password:** the user asks an admin; the admin, after step-up, generates a reset link (256-bit token, 30-minute expiry, single use). Using it sets a new password but **does not** remove MFA: the user must still pass their second factor, and all sessions are revoked. All of this is audited.
- **Lost MFA:** the user uses a recovery code. If all codes are lost, an admin performs an MFA reset after verifying identity through a documented out-of-band procedure (e.g. a video call against the employee record). The procedure is written in `docs/security/security-requirements.md` §4 and the admin must record the verification method in a mandatory reason field. The reset revokes all of the user's sessions and forces re-enrollment.
- Admins can't reset their own MFA through this path; another admin must do it. If only one admin exists, recovery goes through break-glass DB access (documented).

## Security impact
Prevents account takeover via the reset flow (T-004). The residual social-engineering risk of admin-assisted resets is accepted, mitigated by audit logging and the required reason field.

## Consequences
Adding email later needs a new ADR (V1.3.11 then becomes applicable).
