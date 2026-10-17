# ASVS 5.0.0 Verification

- **Standard:** OWASP Application Security Verification Standard 5.0.0, release tag `v5.0.0_release`
  (https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release).
- **Target:** Level 1 + Level 2: 253 requirements (70 L1 + 183 L2). L3 is out of scope.
- **Source file:** `asvs-5.0.0-en.csv`, the official CSV export, SHA-256
  `6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5`. Never edit it; the tool verifies the checksum.

## The matrix (`verification-matrix.csv`)

| Column | Meaning |
|---|---|
| `req_id`, `level`, `chapter`, `section`, `requirement` | From the official CSV |
| `applicability` | `Applicable`, `N/A (proposed)`, `N/A (approved)` |
| `na_justification` | Required for any N/A: why the technology or feature doesn't exist in this system |
| `owner_wp` | Work package that implements the control (initial assignment; the orchestrator may reassign) |
| `verification_method` | `AUT` (automated test), `WB` (white-box review), `BB` (black-box test), `Doc review (WB)`, or a combination |
| `status` | `Not started`, `In progress`, `Pass`, `Fail`, `N/A` |
| `implementation_ref` | Where the control lives: `file:line`, config file, or document section |
| `evidence` | What proves it: test ID (e.g. `TC-A07-06`, `backend/tests/security/test_mfa.py::test_totp_replay`), report section, or document section |
| `verified_by` | Who confirmed it: `builder WP-xx` while building, then `security-auditor WP-22` for the final verdict |
| `notes` | Deployment dependencies, ADR references, caveats |

## Workflow
1. **Builders** update the rows of their WP (`--wp WP-XX`) to `In progress`/`Pass`, with implementation reference and evidence.
2. **Checker** confirms the rows a WP touched are backed by evidence.
3. **Security auditor (WP-22)** independently re-verifies **every** row. Only the auditor may approve N/A
   (`N/A (approved)`, status `N/A`, ADR reference in notes) and set the final `verified_by`.
4. `--gate` must pass for release (PLAN §10.6.2).

## Proposed N/A (62 rows): auditor must approve or reject
| Rows | Reason |
|---|---|
| V4.3.x (2) | No GraphQL |
| V6.6.x (3) | No out-of-band authenticators |
| V6.8.x (4), V7.1.3, V7.6.x (2) | No external IdP or federation |
| V9.x (7) | No self-contained tokens (ADR-0006) |
| V10.x (29) | No OAuth/OIDC |
| V17.x (7) | No WebRTC |
| V1.2.6, V1.2.7, V1.2.8, V1.3.8, V1.3.9, V1.3.11 | No LDAP, XPath, LaTeX, JNDI, memcache, or mail |
| V3.5.5 | No postMessage usage (lint-enforced) |

If a feature in one of these areas is added later, its rows become applicable and the feature can't ship until they pass.

## Deployment-dependent rows
V12.2.2 (public certificates), V16.4.3 (external log collector), V16.2.2 (NTP), V13.3.1 (secrets backend), V13.2.4 (egress
allowlist). These pass when the control is implemented and documented and the reference deployment demonstrates it; the
security review lists them as operator requirements (security-requirements §16).

## Commands
```
python3 -I tools/security/asvs_matrix.py             # refresh the matrix (keeps progress)
python3 -I tools/security/asvs_matrix.py --summary   # counts by applicability, status, owner
python3 -I tools/security/asvs_matrix.py --wp WP-07  # rows for one work package
python3 -I tools/security/asvs_matrix.py --gate      # release gate; exit 1 if anything is unverified
```
