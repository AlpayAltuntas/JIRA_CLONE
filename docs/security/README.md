# Security Documentation Space

Start here. Every security document for the project is listed below with its owner and status.
Decisions live in the decision log, `docs/decisions/` (ADRs); this space holds requirements, models, verification and results.

| Document | Purpose | Owner WP | Status |
|---|---|---|---|
| [security-requirements.md](security-requirements.md) | Control specification and every policy ASVS requires us to document | all (changes need an ADR) | v1 — design |
| [threat-model/summary.md](threat-model/summary.md) | Short threat model (Shostack's four questions) | every WP; final in WP-26 | v0.1 — design |
| [threat-model/detailed.md](threat-model/detailed.md) | Detailed threat model: DFDs, trust boundaries, STRIDE register, mitigations, Q4 review | every WP; final in WP-26 | v0.1 — design |
| [asvs/README.md](asvs/README.md) | How ASVS 5.0.0 L1+L2 verification works | WP-22 | ready |
| [asvs/verification-matrix.csv](asvs/verification-matrix.csv) | One row per L1/L2 requirement with status and evidence | every WP; completed in WP-22 | 0 / 253 verified |
| [asvs/asvs-5.0.0-en.csv](asvs/asvs-5.0.0-en.csv) | Official ASVS 5.0.0 requirement list (vendored, checksummed) | — | reference |
| [testing/security-test-plan.md](testing/security-test-plan.md) | OWASP Top 10:2025 test cases, white-box, black-box and red-team procedures, findings handling | WP-05, WP-22–WP-25 | v1 — design |
| `testing/reports/white-box-report.md` | White-box assessment results | WP-22 | not started |
| `testing/reports/black-box-report.md` | Black-box assessment results | WP-23 | not started |
| `testing/reports/red-team-report.md` | Red-team exercise results and detection matrix | WP-24 | not started |
| [security-review-TEMPLATE.md](security-review-TEMPLATE.md) | Structure of the final security review | — | template |
| `security-review.md` | Final security review: application, verification and threat model | WP-27 | not started |

## Quick facts
- Baselines: OWASP ASVS 5.0.0 L1+L2 (253 requirements), OWASP Top 10:2025, OWASP WSTG, CVSS v4.0 (ADR-0021).
- Release gates: PLAN §10.6.
- Tools: `python3 -I tools/security/asvs_matrix.py --summary | --gate | --wp WP-XX`, `make security-scan` (from WP-05).

## Rules
1. Documents here describe **what is true**. If code and document disagree, that is a finding — fix whichever is wrong and record why.
2. Never mark an ASVS row Pass without evidence a reviewer can check (test ID, `file:line`, config line, report section).
3. Never mark an ASVS row N/A, accept a finding, or relax a value in `security-requirements.md` without an ADR.
4. Reports keep raw tool output out of git (`testing/reports/raw/` is ignored); summaries and findings go in the report files.
