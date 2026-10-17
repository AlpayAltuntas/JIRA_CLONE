# ADR-0021: Security standards baseline

- **Status:** Accepted
- **Date:** 2026-10-17
- **Deciders:** user (OWASP Top 10, ASVS L1+L2, white/black/red-team testing, Shostack threat model), orchestrator (versions)
- **Related:** PLAN §10

## Decision
- **OWASP ASVS 5.0.0** (release tag `v5.0.0_release`), Levels 1 and 2: 253 requirements (70 L1 + 183 L2). The official CSV is vendored at `docs/security/asvs/asvs-5.0.0-en.csv`, SHA-256 `6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5`.
- **OWASP Top 10:2025**: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions.
- **OWASP WSTG** (latest stable) as the manual black-box methodology.
- **Threat modeling:** Shostack's Four Question Framework, with STRIDE per element for Q2.
- **Severity:** CVSS v4.0 base score (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9).
- **Testing terminology:** "white-box" = full knowledge (source, configs); "black-box" = no internal knowledge, only the URL and test accounts; "red team" = goal-oriented adversary emulation that chains weaknesses and also tests detection.

## Security impact
Defines what "secure" means for this project and how it is measured.

## Consequences
When a new ASVS or Top 10 version is released, a new ADR decides whether to adopt it.
