#!/usr/bin/env python3
"""
consolidate_reports.py
──────────────────────
Parses Bandit, Trivy FS, Trivy Image, and Grype JSON reports.
Normalises, deduplicates, and emits two LLM-agent-friendly outputs:

  consolidated-report.json
    └─ Fully self-describing JSON with schema_version, metadata,
       severity counts, and a flat findings array. Every field is
       explicit and labeled so an LLM agent needs no external context.

  consolidated-report.md
    └─ Structured Markdown with a natural-language executive summary,
       severity breakdown, per-finding blocks, and a remediation section.
       Optimised for direct inclusion in an LLM prompt.

Deduplication key: (rule_id.upper(), package.lower(), file.lower(), severity)
When multiple tools report the same issue the record is merged and all
source tools are listed in the `detected_by` array.
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0.0"

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "UNKNOWN":  0,
    "INFO":     0,
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "UNKNOWN":  "⚪",
    "INFO":     "⚪",
}

TOOL_DESCRIPTIONS = {
    "bandit":       "Python static analysis (SAST) — detects insecure code patterns",
    "trivy-fs":     "Trivy filesystem scan — detects vulnerable dependencies and misconfigurations",
    "trivy-image":  "Trivy container image scan — detects OS and library CVEs inside Docker image",
    "grype":        "Grype software composition analysis (SCA) — detects CVEs in dependencies",
}

FINDING_TYPE_DESCRIPTIONS = {
    "SAST":     "Static Application Security Testing — insecure code pattern found in source",
    "SCA":      "Software Composition Analysis — known CVE in a dependency package",
    "MISCONFIG":"Misconfiguration — insecure infrastructure or container configuration",
    "SECRET":   "Secret detected — credential, token, or key exposed in code or image",
}


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_bandit(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Bandit parse error: {e}", file=sys.stderr)
        return findings

    for r in data.get("results", []):
        sev = r.get("issue_severity", "UNKNOWN").upper()
        findings.append({
            "tool":        "bandit",
            "finding_type": "SAST",
            "rule_id":     r.get("test_id", ""),
            "title":       r.get("test_name", ""),
            "severity":    sev,
            "confidence":  r.get("issue_confidence", ""),
            "description": r.get("issue_text", ""),
            "file":        r.get("filename", ""),
            "line":        str(r.get("line_number", "")),
            "code_snippet":r.get("code", "").strip(),
            "package":     "",
            "installed_version": "",
            "fixed_version":     "",
            "cve_id":      "",
            "cvss_score":  "",
            "reference_url": r.get("more_info", ""),
        })
    return findings


def parse_trivy(path: Path, scan_type: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Trivy ({scan_type}) parse error: {e}", file=sys.stderr)
        return findings

    tool_key = f"trivy-{scan_type}"

    for result in data.get("Results", []):
        target = result.get("Target", "")

        for v in result.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            cvss = ""
            cvss_data = v.get("CVSS", {})
            # Try to get CVSS score from nvd or redhat source
            for source in ("nvd", "redhat"):
                score = cvss_data.get(source, {}).get("V3Score") or \
                        cvss_data.get(source, {}).get("V2Score")
                if score:
                    cvss = str(score)
                    break

            fix = v.get("FixedVersion", "")
            findings.append({
                "tool":              tool_key,
                "finding_type":      "SCA",
                "rule_id":           v.get("VulnerabilityID", ""),
                "title":             v.get("Title", v.get("VulnerabilityID", "")),
                "severity":          sev,
                "confidence":        "HIGH",
                "description":       v.get("Description", ""),
                "file":              target,
                "line":              "",
                "code_snippet":      "",
                "package":           v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version":     fix,
                "cve_id":            v.get("VulnerabilityID", ""),
                "cvss_score":        cvss,
                "reference_url":     (v.get("References") or [""])[0],
            })

        for m in result.get("Misconfigurations", []) or []:
            sev = m.get("Severity", "UNKNOWN").upper()
            findings.append({
                "tool":              tool_key,
                "finding_type":      "MISCONFIG",
                "rule_id":           m.get("ID", ""),
                "title":             m.get("Title", ""),
                "severity":          sev,
                "confidence":        "HIGH",
                "description":       m.get("Description", ""),
                "file":              target,
                "line":              "",
                "code_snippet":      "",
                "package":           "",
                "installed_version": "",
                "fixed_version":     "",
                "cve_id":            "",
                "cvss_score":        "",
                "reference_url":     m.get("PrimaryURL", ""),
            })

        for s in result.get("Secrets", []) or []:
            findings.append({
                "tool":              tool_key,
                "finding_type":      "SECRET",
                "rule_id":           s.get("RuleID", ""),
                "title":             s.get("Title", ""),
                "severity":          s.get("Severity", "HIGH").upper(),
                "confidence":        "HIGH",
                "description":       f"Secret detected — category: {s.get('Category', 'unknown')}",
                "file":              target,
                "line":              str(s.get("StartLine", "")),
                "code_snippet":      "",
                "package":           "",
                "installed_version": "",
                "fixed_version":     "",
                "cve_id":            "",
                "cvss_score":        "",
                "reference_url":     "",
            })

    return findings


def parse_grype(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Grype parse error: {e}", file=sys.stderr)
        return findings

    for m in data.get("matches", []):
        vuln = m.get("vulnerability", {})
        art  = m.get("artifact", {})
        sev  = vuln.get("severity", "UNKNOWN").upper()

        fix_ver = ""
        fix = vuln.get("fix", {})
        if fix.get("state") == "fixed":
            fix_ver = ", ".join(fix.get("versions", []))

        cvss = ""
        for c in vuln.get("cvss", []):
            score = c.get("metrics", {}).get("baseScore")
            if score:
                cvss = str(score)
                break

        loc_path = ""
        locs = art.get("locations", [])
        if locs:
            loc_path = locs[0].get("path", "")

        findings.append({
            "tool":              "grype",
            "finding_type":      "SCA",
            "rule_id":           vuln.get("id", ""),
            "title":             (vuln.get("description", "") or vuln.get("id", ""))[:120],
            "severity":          sev,
            "confidence":        "HIGH",
            "description":       vuln.get("description", ""),
            "file":              loc_path,
            "line":              "",
            "code_snippet":      "",
            "package":           art.get("name", ""),
            "installed_version": art.get("version", ""),
            "fixed_version":     fix_ver,
            "cve_id":            vuln.get("id", ""),
            "cvss_score":        cvss,
            "reference_url":     (vuln.get("urls") or [""])[0],
        })
    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────

def deduplicate(findings: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for f in findings:
        key = (
            f["rule_id"].upper(),
            f["package"].lower(),
            f["file"].lower(),
            f["severity"],
        )
        if key not in groups:
            groups[key] = {**f, "detected_by": [f["tool"]], "occurrence_count": 1}
        else:
            g = groups[key]
            if f["tool"] not in g["detected_by"]:
                g["detected_by"].append(f["tool"])
            g["occurrence_count"] += 1
            if len(f["description"]) > len(g["description"]):
                g["description"] = f["description"]
            if not g["fixed_version"] and f["fixed_version"]:
                g["fixed_version"] = f["fixed_version"]
            if not g["cvss_score"] and f["cvss_score"]:
                g["cvss_score"] = f["cvss_score"]
            if not g["reference_url"] and f["reference_url"]:
                g["reference_url"] = f["reference_url"]

    deduped = list(groups.values())
    deduped.sort(key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), x["rule_id"]))

    # Assign stable numeric IDs after sort
    for idx, f in enumerate(deduped, 1):
        f["id"] = idx

    return deduped


# ── LLM-friendly JSON output ──────────────────────────────────────────────────

def build_json_report(
    findings: list[dict],
    raw_counts: dict[str, int],
    repo: str,
    commit: str,
) -> dict:
    by_sev: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    fixable = 0
    multi_tool = 0

    for f in findings:
        by_sev[f["severity"]] += 1
        by_type[f["finding_type"]] += 1
        if f.get("fixed_version"):
            fixable += 1
        if len(f.get("detected_by", [])) > 1:
            multi_tool += 1

    total_raw = sum(raw_counts.values())

    return {
        # ── Schema metadata (lets the agent understand what it's reading) ──
        "schema_version": SCHEMA_VERSION,
        "report_type": "consolidated_security_scan",
        "description": (
            "Deduplicated security findings from multiple scanners "
            "(Bandit SAST, Trivy filesystem, Trivy container image, Grype SCA). "
            "Each finding is a unique issue identified by rule_id + package + file + severity. "
            "findings_detected_by_multiple_tools indicates cross-tool confirmation."
        ),

        # ── Scan context ──
        "scan_context": {
            "generated_at_utc":  datetime.now(timezone.utc).isoformat(),
            "repository":        repo or "unknown",
            "commit_sha":        commit or "unknown",
            "tools_run": [
                {
                    "tool_name":   tool,
                    "description": TOOL_DESCRIPTIONS.get(tool, ""),
                    "raw_findings_before_dedup": count,
                }
                for tool, count in sorted(raw_counts.items())
            ],
        },

        # ── Deduplication stats ──
        "deduplication_summary": {
            "total_raw_findings":          total_raw,
            "total_unique_findings":       len(findings),
            "duplicates_removed":          total_raw - len(findings),
            "findings_confirmed_by_multiple_tools": multi_tool,
            "deduplication_key_fields":    ["rule_id", "package", "file", "severity"],
        },

        # ── Severity counts (quick triage for the agent) ──
        "severity_counts": {
            sev: by_sev.get(sev, 0)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        },

        # ── Finding type counts ──
        "finding_type_counts": {
            ftype: {
                "count":       by_type.get(ftype, 0),
                "description": FINDING_TYPE_DESCRIPTIONS.get(ftype, ""),
            }
            for ftype in ["SAST", "SCA", "MISCONFIG", "SECRET"]
            if by_type.get(ftype, 0) > 0
        },

        # ── Remediation hint ──
        "remediation_summary": {
            "fixable_findings":     fixable,
            "unfixable_findings":   len(findings) - fixable,
            "note": (
                "fixable_findings have a known fixed_version available. "
                "Upgrade the listed package to fixed_version to resolve. "
                "unfixable_findings require code changes or have no patch yet."
            ),
        },

        # ── Field glossary (self-documenting for the LLM) ──
        "field_glossary": {
            "id":                "Unique sequential finding ID within this report",
            "finding_type":      "SAST | SCA | MISCONFIG | SECRET",
            "rule_id":           "Scanner rule or CVE identifier (e.g. B105, CVE-2023-1234)",
            "cve_id":            "CVE identifier if applicable, else empty string",
            "cvss_score":        "CVSS base score (0.0-10.0) if available, else empty string",
            "severity":          "CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN",
            "confidence":        "Scanner confidence in the finding: HIGH | MEDIUM | LOW",
            "title":             "Short human-readable finding title",
            "description":       "Full description of the vulnerability or issue",
            "package":           "Affected dependency package name (SCA findings)",
            "installed_version": "Currently installed version of the affected package",
            "fixed_version":     "Version that fixes the issue; empty if no patch exists",
            "file":              "Source file, dependency manifest, or container layer path",
            "line":              "Line number in source file; empty for dependency findings",
            "code_snippet":      "Relevant source code excerpt (SAST only)",
            "reference_url":     "Primary reference URL for more details",
            "detected_by":       "List of tools that independently detected this finding",
            "occurrence_count":  "How many times this finding appeared across all tools before dedup",
        },

        # ── The findings (sorted: CRITICAL first, then by rule_id) ──
        "findings": findings,
    }


# ── LLM-friendly Markdown output ─────────────────────────────────────────────

def write_markdown(report: dict, path: Path):
    findings  = report["findings"]
    sev_counts = report["severity_counts"]
    dedup      = report["deduplication_summary"]
    ctx        = report["scan_context"]
    rem        = report["remediation_summary"]

    total    = dedup["total_unique_findings"]
    critical = sev_counts.get("CRITICAL", 0)
    high     = sev_counts.get("HIGH", 0)
    medium   = sev_counts.get("MEDIUM", 0)
    low      = sev_counts.get("LOW", 0)

    # Natural-language executive summary for the LLM
    if critical > 0:
        risk_level = "CRITICAL — immediate action required"
    elif high > 0:
        risk_level = "HIGH — action required before merge"
    elif medium > 0:
        risk_level = "MEDIUM — action recommended"
    else:
        risk_level = "LOW — no urgent issues"

    lines = [
        "# 🔐 Consolidated Security Scan Report",
        "",
        "<!--",
        "  LLM AGENT INSTRUCTIONS:",
        "  This report is the deduplicated output of four security scanners.",
        "  Each finding block is self-contained. Use the SEVERITY, FINDING_TYPE,",
        "  CVE_ID, PACKAGE, INSTALLED_VERSION, and FIXED_VERSION fields to",
        "  prioritise and suggest remediations. Findings confirmed by multiple",
        "  tools (DETECTED_BY contains >1 entry) are higher confidence.",
        "  The machine-readable version of this report is consolidated-report.json.",
        "-->",
        "",
        "---",
        "",
        "## 📋 Executive Summary",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Generated (UTC)** | {ctx['generated_at_utc']} |",
        f"| **Repository** | {ctx['repository']} |",
        f"| **Commit** | {ctx['commit_sha']} |",
        f"| **Overall Risk Level** | **{risk_level}** |",
        f"| **Total Unique Findings** | {total} |",
        f"| **Duplicates Removed** | {dedup['duplicates_removed']} (from {dedup['total_raw_findings']} raw) |",
        f"| **Cross-Tool Confirmed** | {dedup['findings_confirmed_by_multiple_tools']} findings |",
        f"| **Fixable Now** | {rem['fixable_findings']} of {total} have a known fix |",
        "",
        "---",
        "",
        "## 📊 Severity Breakdown",
        "",
        "| Severity | Count | Meaning |",
        "|----------|-------|---------|",
        f"| 🔴 CRITICAL | {critical} | Actively exploitable, patch immediately |",
        f"| 🟠 HIGH     | {high} | High risk, fix before merging |",
        f"| 🟡 MEDIUM   | {medium} | Moderate risk, fix in next sprint |",
        f"| 🔵 LOW      | {low} | Low risk, fix when convenient |",
        "",
        "---",
        "",
        "## 🛠️ Tools Used",
        "",
        "| Tool | Description | Raw Findings |",
        "|------|-------------|--------------|",
    ]

    for t in ctx["tools_run"]:
        lines.append(
            f"| `{t['tool_name']}` | {t['description']} | {t['raw_findings_before_dedup']} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 🔍 Findings",
        "",
        "> Sorted by severity (CRITICAL → LOW). Each block is self-contained.",
        "> `DETECTED_BY` lists all tools that independently reported the finding.",
        "> Findings with multiple tools in `DETECTED_BY` are higher confidence.",
        "",
    ]

    # Group findings by severity for readable sections
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue

        emoji = SEVERITY_EMOJI.get(sev, "")
        lines += [
            f"### {emoji} {sev} ({len(group)} findings)",
            "",
        ]

        for f in group:
            detected_by_str = ", ".join(f.get("detected_by", [f.get("tool","")]))
            confirmed = " ✅ **Cross-tool confirmed**" if len(f.get("detected_by", [])) > 1 else ""

            lines += [
                f"#### Finding #{f['id']} — {f['title'] or f['rule_id']}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **ID** | {f['id']} |",
                f"| **Severity** | {emoji} {sev} |",
                f"| **Finding Type** | {f['finding_type']} — {FINDING_TYPE_DESCRIPTIONS.get(f['finding_type'],'')} |",
                f"| **Rule / CVE** | `{f['rule_id']}` |",
            ]

            if f.get("cve_id"):
                lines.append(f"| **CVE ID** | `{f['cve_id']}` |")
            if f.get("cvss_score"):
                lines.append(f"| **CVSS Score** | {f['cvss_score']} / 10.0 |")
            if f.get("package"):
                lines.append(f"| **Affected Package** | `{f['package']}` |")
            if f.get("installed_version"):
                lines.append(f"| **Installed Version** | `{f['installed_version']}` |")
            if f.get("fixed_version"):
                lines.append(f"| **Fix Available** | Upgrade to `{f['fixed_version']}` |")
            else:
                lines.append(f"| **Fix Available** | ⚠️ No patch available yet |")
            if f.get("file"):
                loc = f['file']
                if f.get("line"):
                    loc += f":{f['line']}"
                lines.append(f"| **Location** | `{loc}` |")

            lines += [
                f"| **Confidence** | {f.get('confidence','HIGH')} |",
                f"| **Detected By** | {detected_by_str}{confirmed} |",
                f"| **Occurrences Before Dedup** | {f.get('occurrence_count', 1)} |",
            ]

            if f.get("reference_url"):
                lines.append(f"| **Reference** | {f['reference_url']} |")

            lines.append("")

            if f.get("description"):
                lines += [
                    "**Description:**",
                    "",
                    f"> {f['description'][:500].replace(chr(10), ' ')}",
                    "",
                ]

            if f.get("code_snippet"):
                lines += [
                    "**Code Snippet:**",
                    "",
                    "```python",
                    f.get("code_snippet", ""),
                    "```",
                    "",
                ]

            lines.append("---")
            lines.append("")

    # Remediation section
    lines += [
        "## 🩹 Remediation Guidance",
        "",
        "| Priority | Action |",
        "|----------|--------|",
        "| 1 — CRITICAL | Patch immediately. Do not merge. |",
        "| 2 — HIGH | Patch before merging this PR. |",
        "| 3 — MEDIUM | Schedule fix in next sprint. |",
        "| 4 — LOW | Fix when convenient or suppress with justification. |",
        "",
        "### Dependency Upgrades (SCA/CVE findings with known fixes)",
        "",
    ]

    upgrades = [
        f for f in findings
        if f.get("package") and f.get("fixed_version")
    ]
    if upgrades:
        lines += [
            "| Package | Installed | Fix Version | Severity | CVE |",
            "|---------|-----------|-------------|----------|-----|",
        ]
        for u in sorted(upgrades, key=lambda x: -SEVERITY_RANK.get(x["severity"], 0)):
            lines.append(
                f"| `{u['package']}` | `{u['installed_version']}` "
                f"| `{u['fixed_version']}` | {u['severity']} | {u.get('cve_id','—')} |"
            )
    else:
        lines.append("_No dependency findings with known fixes._")

    lines += [
        "",
        "---",
        "",
        "## 🤖 Machine-Readable Output",
        "",
        "The full deduplicated report is also available as `consolidated-report.json`.",
        "That file contains the same findings plus a `field_glossary` and `schema_version`",
        "for programmatic consumption by LLM agents or automation pipelines.",
        "",
        "---",
        f"*Generated by `consolidate_reports.py` v{SCHEMA_VERSION}*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Consolidate & deduplicate security scan reports into LLM-friendly output"
    )
    ap.add_argument("--bandit",       type=Path, help="Bandit JSON report")
    ap.add_argument("--trivy-fs",     type=Path, help="Trivy filesystem JSON report")
    ap.add_argument("--trivy-image",  type=Path, help="Trivy image JSON report")
    ap.add_argument("--grype",        type=Path, help="Grype JSON report")
    ap.add_argument("--output-json",  type=Path, default=Path("consolidated-report.json"))
    ap.add_argument("--output-md",    type=Path, default=Path("consolidated-report.md"))
    ap.add_argument("--repo",         type=str,  default="",  help="Repository name for context")
    ap.add_argument("--commit",       type=str,  default="",  help="Commit SHA for context")
    args = ap.parse_args()

    all_findings: list[dict] = []
    raw_counts:   dict[str, int] = {}

    parsers = [
        ("bandit",      args.bandit,      parse_bandit),
        ("trivy-fs",    args.trivy_fs,    lambda p: parse_trivy(p, "fs")),
        ("trivy-image", args.trivy_image, lambda p: parse_trivy(p, "image")),
        ("grype",       args.grype,       parse_grype),
    ]

    for tool_name, path, parser in parsers:
        if path and path.exists():
            findings = parser(path)
            raw_counts[tool_name] = len(findings)
            all_findings.extend(findings)
            print(f"[INFO] {tool_name:<15} {len(findings):>5} raw findings")
        else:
            raw_counts[tool_name] = 0
            print(f"[INFO] {tool_name:<15}     0 (report not found, skipping)")

    total_raw = len(all_findings)
    deduped   = deduplicate(all_findings)
    saved     = total_raw - len(deduped)

    print(f"[INFO] {'Raw total':<15} {total_raw:>5}")
    print(f"[INFO] {'After dedup':<15} {len(deduped):>5}  ({saved} duplicates removed)")

    report = build_json_report(deduped, raw_counts, args.repo, args.commit)

    args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[INFO] JSON → {args.output_json}")

    write_markdown(report, args.output_md)
    print(f"[INFO] MD   → {args.output_md}")

    # Exit code for the pipeline gate
    critical_high = [f for f in deduped if f["severity"] in ("CRITICAL", "HIGH")]
    if critical_high:
        print(
            f"\n[GATE] ❌ {len(critical_high)} CRITICAL/HIGH findings remain after deduplication.",
            file=sys.stderr,
        )
        sys.exit(1)
    else:
        print("\n[GATE] ✅ No CRITICAL/HIGH findings after deduplication.")
        sys.exit(0)


if __name__ == "__main__":
    main()