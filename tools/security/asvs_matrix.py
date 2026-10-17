#!/usr/bin/env python3
"""Build and check the ASVS 5.0.0 L1+L2 verification matrix.

Usage:
  python3 -I tools/security/asvs_matrix.py            # create/refresh the matrix, keeping existing progress
  python3 -I tools/security/asvs_matrix.py --summary  # print counts
  python3 -I tools/security/asvs_matrix.py --gate     # exit 1 unless every row is Pass or approved N/A with evidence
  python3 -I tools/security/asvs_matrix.py --wp WP-07 # list the rows owned by a work package
"""

from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "docs/security/asvs/asvs-5.0.0-en.csv"
MATRIX = ROOT / "docs/security/asvs/verification-matrix.csv"
SOURCE_SHA256 = "6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5"
LEVELS = {"1", "2"}

COLUMNS = [
    "req_id", "level", "chapter", "section", "requirement",
    "applicability", "na_justification", "owner_wp", "verification_method",
    "status", "implementation_ref", "evidence", "verified_by", "notes",
]
# Fields that hold progress and must survive a refresh.
PRESERVED = [
    "applicability", "na_justification", "owner_wp", "verification_method",
    "status", "implementation_ref", "evidence", "verified_by", "notes",
]
APPLICABILITY = {"Applicable", "N/A (proposed)", "N/A (approved)"}
STATUSES = {"Not started", "In progress", "Pass", "Fail", "N/A"}

# Proposed N/A: only where the technology or feature does not exist in the system at all.
# The white-box auditor approves or rejects each one (WP-22); approval needs an ADR reference in notes.
NA_BY_PREFIX = {
    "V4.3.": "No GraphQL or data-layer query language is exposed; the API is REST only (PLAN §6).",
    "V6.6.": "No out-of-band authenticators (SMS, phone, email, push) exist; MFA is TOTP/WebAuthn only (ADR-0007).",
    "V6.8.": "No external identity provider, SSO, SAML or OIDC login (PLAN §1.2).",
    "V7.6.": "No federated identity; sessions are local only (ADR-0006).",
    "V9.": "No self-contained tokens (JWT etc.) are used; sessions and one-time tokens are opaque reference tokens (ADR-0006).",
    "V10.": "No OAuth 2.0 or OpenID Connect client, resource server or authorization server (PLAN §1.2).",
    "V17.": "No WebRTC functionality.",
}
NA_BY_ID = {
    "V1.2.6": "No LDAP directory integration.",
    "V1.2.7": "No XPath or XML querying of untrusted data.",
    "V1.2.8": "No LaTeX processing.",
    "V1.3.8": "No JNDI (Java-specific); the stack is Python/TypeScript.",
    "V1.3.9": "No memcache or similar cache receives user input.",
    "V1.3.11": "No mail system integration in v1 (ADR-0022); becomes applicable if email is added.",
    "V3.5.5": "The application doesn't use the postMessage interface; an ESLint rule bans 'message' event listeners and postMessage calls.",
    "V7.1.3": "No federated identity or SSO systems create or manage sessions.",
}

OWNER_BY_SECTION = {
    "V1.1": "WP-06", "V1.2": "WP-11", "V1.3": "WP-11", "V1.4": "WP-22", "V1.5": "WP-06",
    "V2.1": "WP-06", "V2.2": "WP-06", "V2.3": "WP-13", "V2.4": "WP-06",
    "V3.2": "WP-12", "V3.3": "WP-07", "V3.4": "WP-03", "V3.5": "WP-06", "V3.7": "WP-09",
    "V4.1": "WP-03", "V4.2": "WP-03", "V4.3": "WP-22", "V4.4": "WP-16",
    "V5.1": "WP-15", "V5.2": "WP-15", "V5.3": "WP-15", "V5.4": "WP-15",
    "V6.1": "WP-07", "V6.2": "WP-07", "V6.3": "WP-07", "V6.4": "WP-07", "V6.5": "WP-08",
    "V6.6": "WP-22", "V6.8": "WP-22",
    "V7.1": "WP-07", "V7.2": "WP-07", "V7.3": "WP-07", "V7.4": "WP-07", "V7.5": "WP-07", "V7.6": "WP-22",
    "V8.1": "WP-10", "V8.2": "WP-10", "V8.3": "WP-10", "V8.4": "WP-10",
    "V11.1": "WP-02", "V11.2": "WP-02", "V11.3": "WP-08", "V11.4": "WP-07", "V11.5": "WP-07", "V11.6": "WP-02",
    "V12.1": "WP-03", "V12.2": "WP-03", "V12.3": "WP-03",
    "V13.1": "WP-03", "V13.2": "WP-04", "V13.3": "WP-02", "V13.4": "WP-03",
    "V14.1": "WP-06", "V14.2": "WP-06", "V14.3": "WP-09",
    "V15.1": "WP-05", "V15.2": "WP-05", "V15.3": "WP-06",
    "V16.1": "WP-06", "V16.2": "WP-06", "V16.3": "WP-06", "V16.4": "WP-06", "V16.5": "WP-06",
}
OWNER_BY_ID = {
    "V1.2.4": "WP-04", "V1.2.9": "WP-18", "V1.3.6": "WP-06",
    "V2.3.1": "WP-07", "V3.5.4": "WP-03",
    "V6.3.3": "WP-08", "V6.4.4": "WP-08",
    "V8.2.3": "WP-10", "V12.1.3": "WP-03", "V13.2.1": "WP-03", "V13.2.4": "WP-03", "V13.2.5": "WP-03",
    "V15.2.2": "WP-06", "V15.3.6": "WP-09",
}
# Requirements that depend on how the operator deploys (security-requirements §16).
DEPLOYMENT_NOTES = {
    "V12.2.2": "Deployment requirement D1 (public certificates).",
    "V16.4.3": "Deployment requirement D2 (external log collector).",
    "V16.2.2": "Deployment requirement D3 (NTP).",
    "V13.3.1": "Reference implementation: Compose secrets (ADR-0011); vault/KMS recommended (D5).",
    "V13.2.4": "Deployment requirement D9 (egress allowlist) complements the app-level allowlist.",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_source() -> list[dict[str, str]]:
    digest = sha256(SOURCE)
    if digest != SOURCE_SHA256:
        sys.exit(f"ASVS source checksum mismatch: {digest} (expected {SOURCE_SHA256})")
    with SOURCE.open(encoding="utf-8-sig", newline="") as f:
        return [r for r in csv.DictReader(f) if r["L"] in LEVELS]


def load_matrix() -> dict[str, dict[str, str]]:
    if not MATRIX.exists():
        return {}
    with MATRIX.open(encoding="utf-8", newline="") as f:
        return {r["req_id"]: r for r in csv.DictReader(f)}


def proposed_na(req_id: str) -> str | None:
    if req_id in NA_BY_ID:
        return NA_BY_ID[req_id]
    for prefix, reason in NA_BY_PREFIX.items():
        if req_id.startswith(prefix):
            return reason
    return None


def default_method(section_name: str) -> str:
    if "Documentation" in section_name:
        return "Doc review (WB)"
    return "AUT + WB"


def build() -> list[dict[str, str]]:
    existing = load_matrix()
    rows = []
    for src in load_source():
        rid = src["req_id"]
        na = proposed_na(rid)
        row = {
            "req_id": rid,
            "level": src["L"],
            "chapter": f'{src["chapter_id"]} {src["chapter_name"]}',
            "section": f'{src["section_id"]} {src["section_name"]}',
            "requirement": src["req_description"],
            "applicability": "N/A (proposed)" if na else "Applicable",
            "na_justification": na or "",
            "owner_wp": OWNER_BY_ID.get(rid, OWNER_BY_SECTION.get(src["section_id"], "WP-22")),
            "verification_method": "Auditor review of N/A" if na else default_method(src["section_name"]),
            "status": "Not started",
            "implementation_ref": "",
            "evidence": "",
            "verified_by": "",
            "notes": DEPLOYMENT_NOTES.get(rid, ""),
        }
        if rid in existing:
            for field in PRESERVED:
                if existing[rid].get(field, ""):
                    row[field] = existing[rid][field]
        rows.append(row)
    extra = set(existing) - {r["req_id"] for r in rows}
    if extra:
        sys.exit(f"Matrix contains unknown requirement IDs: {sorted(extra)}")
    return rows


def write(rows: list[dict[str, str]]) -> None:
    with MATRIX.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        w.writerows(rows)


def validate(rows: list[dict[str, str]]) -> list[str]:
    problems = []
    for r in rows:
        if r["applicability"] not in APPLICABILITY:
            problems.append(f'{r["req_id"]}: invalid applicability {r["applicability"]!r}')
        if r["status"] not in STATUSES:
            problems.append(f'{r["req_id"]}: invalid status {r["status"]!r}')
        if r["applicability"].startswith("N/A") and not r["na_justification"]:
            problems.append(f'{r["req_id"]}: N/A without justification')
    return problems


def gate(rows: list[dict[str, str]]) -> list[str]:
    failures = []
    for r in rows:
        rid = r["req_id"]
        if r["applicability"] == "N/A (approved)":
            if r["status"] != "N/A" or not r["verified_by"]:
                failures.append(f"{rid}: approved N/A needs status 'N/A' and verified_by")
        elif r["applicability"] == "N/A (proposed)":
            failures.append(f"{rid}: N/A not yet approved by the auditor")
        elif r["status"] != "Pass":
            failures.append(f'{rid}: status is {r["status"]!r}')
        elif not r["evidence"] or not r["verified_by"]:
            failures.append(f"{rid}: Pass without evidence or verified_by")
    return failures


def summary(rows: list[dict[str, str]]) -> None:
    print(f"Requirements (L1+L2): {len(rows)}  "
          f"L1={sum(r['level'] == '1' for r in rows)} L2={sum(r['level'] == '2' for r in rows)}")
    for key in ("applicability", "status"):
        print(f"\nBy {key}:")
        for value, n in sorted(collections.Counter(r[key] for r in rows).items()):
            print(f"  {value:<16} {n}")
    print("\nBy owner WP (applicable only):")
    owners = collections.Counter(r["owner_wp"] for r in rows if r["applicability"] == "Applicable")
    for wp, n in sorted(owners.items()):
        print(f"  {wp:<6} {n}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--gate", action="store_true")
    ap.add_argument("--wp")
    args = ap.parse_args()

    rows = build()
    problems = validate(rows)
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1

    if args.wp:
        for r in rows:
            if r["owner_wp"] == args.wp:
                print(f'{r["req_id"]} (L{r["level"]}) [{r["status"]}] {r["requirement"]}')
        return 0
    if args.gate:
        failures = gate(rows)
        print(f"{len(rows) - len(failures)}/{len(rows)} requirements satisfied")
        if failures:
            print("\n".join(failures[:50]))
            if len(failures) > 50:
                print(f"... and {len(failures) - 50} more")
            return 1
        return 0

    write(rows)
    if args.summary:
        summary(rows)
    else:
        print(f"Wrote {MATRIX.relative_to(ROOT)} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
