# Security Review — JIRA Clone <version>

> Written in WP-27 after the application, the security verification (white-box, black-box, red team, ASVS) and the final
> threat model are complete. Copy this template to `security-review.md` and fill in every section. Every claim must link to
> evidence (report section, test ID, matrix row, ADR).

- **Date:**
- **Commit reviewed:** `<sha>`  **Image digests:** app `<sha256>`, postgres `<sha256>`, pgadmin `<sha256>`
- **Authors:** orchestrator (compiled from security-auditor, pentester and red-team reports)
- **Recommendation:** Ready for production / Ready with conditions / Not ready

## 1. Executive summary
Half a page: what was reviewed, how, the overall result, residual risks, and the conditions for production use.

## 2. Scope
- System and version; the 3-container architecture; what was out of scope.
- Assumptions (threat model §1.7) and operator requirements (security-requirements §16).

## 3. Methodology
| Activity | Standard | Agent | Dates | Report |
|---|---|---|---|---|
| Threat modeling | Shostack 4Q + STRIDE | orchestrator | | threat-model/ |
| Continuous automated testing | — | CI | | CI run links |
| White-box assessment | ASVS 5.0.0 L1+L2 | security-auditor | | testing/reports/white-box-report.md |
| Black-box assessment | OWASP WSTG, Top 10:2025 | pentester | | testing/reports/black-box-report.md |
| Red-team exercise | Objective-based | red-team | | testing/reports/red-team-report.md |

## 4. Results

### 4.1 Findings overview
| Severity | Found | Fixed & retested | Accepted (ADR) | Open |
|---|---|---|---|---|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |
| Info | | | | |

### 4.2 OWASP Top 10:2025
| Category | Test cases | Passed | Findings (IDs) | Verdict |
|---|---|---|---|---|
| A01 Broken Access Control | | | | |
| A02 Security Misconfiguration | | | | |
| A03 Software Supply Chain Failures | | | | |
| A04 Cryptographic Failures | | | | |
| A05 Injection | | | | |
| A06 Insecure Design | | | | |
| A07 Authentication Failures | | | | |
| A08 Software or Data Integrity Failures | | | | |
| A09 Security Logging and Alerting Failures | | | | |
| A10 Mishandling of Exceptional Conditions | | | | |

### 4.3 ASVS 5.0.0 L1+L2
Output of `asvs_matrix.py --summary` and `--gate`; table per chapter (Pass / N/A approved / Fail); list of approved N/A rows with
ADR references; deployment-dependent rows and how the reference deployment demonstrated them.

### 4.4 Red-team objectives and detection
| Objective | Achieved? | Path / blocking control | Detected? |
|---|---|---|---|

### 4.5 Automated scanning
SAST, SCA, secrets, image and IaC scan results at the reviewed commit; SBOM location.

## 5. Threat model outcome
- Threats by status (Mitigated / Accepted / Transferred / Retired).
- Threats found during testing that the model missed, and why (Q4).
- Final answer to "Did we do a good enough job?"

## 6. Accepted risks
| ID | Description | Severity | Rationale | ADR | Owner | Review date |
|---|---|---|---|---|---|---|

## 7. Operator requirements for a secure deployment
D1–D9 from security-requirements §16, each with how to meet it.

## 8. Limitations of this review
- These results come from automated tools and AI agents, not an independent third-party assessment.
- State any tests that couldn't be run, and why.
- Recommendation for an independent human penetration test before production use with sensitive data.

## 9. Sign-off
| Role | Name/agent | Date | Decision |
|---|---|---|---|
| Orchestrator | | | |
| Project owner (user) | | | |
