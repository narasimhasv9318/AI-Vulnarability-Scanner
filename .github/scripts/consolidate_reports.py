#!/usr/bin/env python3
"""
consolidate_reports.py
──────────────────────
Parses Bandit (JSON), Trivy FS (JSON), Trivy Image (JSON), and Grype (JSON)
reports, normalises every finding into a unified schema, deduplicates across
tools, and writes:
  - consolidated-report.json   (machine-readable, deduplicated)
  - consolidated-report.md     (human-readable summary table)

Deduplication key: (severity, rule_id, package_or_file, location)
If two tools report the same CVE on the same package/file they are merged
into one record that lists both tools as sources.

Usage:
  python consolidate_reports.py \
    --bandit   bandit-report.json \
    --trivy-fs trivy-fs-results.json \
    --trivy-image trivy-image-results.json \
    --grype    grype-results.json \
    --output-json consolidated-report.json \
    --output-md   consolidated-report.md
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Severity ordering (higher = worse) ────────────────────────────────────────
SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH":     3,
    "MEDIUM":   2,
    "LOW":      1,
    "UNKNOWN":  0,
    "INFO":     0,
}


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.get(s.upper(), 0)


# ── Normalise Bandit ───────────────────────────────────────────────────────────
def parse_bandit(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Could not parse Bandit report: {e}", file=sys.stderr)
        return findings

    for r in data.get("results", []):
        sev = r.get("issue_severity", "UNKNOWN").upper()
        findings.append({
            "tool":        "bandit",
            "type":        "SAST",
            "rule_id":     r.get("test_id", ""),
            "title":       r.get("test_name", ""),
            "severity":    sev,
            "description": r.get("issue_text", ""),
            "file":        r.get("filename", ""),
            "line":        str(r.get("line_number", "")),
            "package":     "",
            "version":     "",
            "fixed_in":    "",
            "cve":         "",
            "url":         r.get("more_info", ""),
        })
    return findings


# ── Normalise Trivy (fs or image) ─────────────────────────────────────────────
def parse_trivy(path: Path, scan_type: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Could not parse Trivy report ({scan_type}): {e}", file=sys.stderr)
        return findings

    for result in data.get("Results", []):
        target = result.get("Target", "")

        # Vulnerability findings
        for v in result.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            findings.append({
                "tool":        f"trivy-{scan_type}",
                "type":        "SCA",
                "rule_id":     v.get("VulnerabilityID", ""),
                "title":       v.get("Title", v.get("VulnerabilityID", "")),
                "severity":    sev,
                "description": v.get("Description", ""),
                "file":        target,
                "line":        "",
                "package":     v.get("PkgName", ""),
                "version":     v.get("InstalledVersion", ""),
                "fixed_in":    v.get("FixedVersion", ""),
                "cve":         v.get("VulnerabilityID", ""),
                "url":         (v.get("References") or [""])[0],
            })

        # Secret / misconfiguration findings
        for m in result.get("Misconfigurations", []) or []:
            sev = m.get("Severity", "UNKNOWN").upper()
            findings.append({
                "tool":        f"trivy-{scan_type}",
                "type":        "MISCONFIG",
                "rule_id":     m.get("ID", ""),
                "title":       m.get("Title", ""),
                "severity":    sev,
                "description": m.get("Description", ""),
                "file":        target,
                "line":        "",
                "package":     "",
                "version":     "",
                "fixed_in":    "",
                "cve":         "",
                "url":         m.get("PrimaryURL", ""),
            })

        for s in result.get("Secrets", []) or []:
            findings.append({
                "tool":        f"trivy-{scan_type}",
                "type":        "SECRET",
                "rule_id":     s.get("RuleID", ""),
                "title":       s.get("Title", ""),
                "severity":    s.get("Severity", "HIGH").upper(),
                "description": f"Secret detected: {s.get('Category', '')}",
                "file":        target,
                "line":        str(s.get("StartLine", "")),
                "package":     "",
                "version":     "",
                "fixed_in":    "",
                "cve":         "",
                "url":         "",
            })

    return findings


# ── Normalise Grype ────────────────────────────────────────────────────────────
def parse_grype(path: Path) -> list[dict]:
    findings = []
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"[WARN] Could not parse Grype report: {e}", file=sys.stderr)
        return findings

    for m in data.get("matches", []):
        vuln    = m.get("vulnerability", {})
        art     = m.get("artifact", {})
        sev     = vuln.get("severity", "UNKNOWN").upper()
        fix_ver = ""
        fix     = vuln.get("fix", {})
        if fix.get("state") == "fixed":
            fix_ver = ", ".join(fix.get("versions", []))

        findings.append({
            "tool":        "grype",
            "type":        "SCA",
            "rule_id":     vuln.get("id", ""),
            "title":       vuln.get("description", vuln.get("id", ""))[:120],
            "severity":    sev,
            "description": vuln.get("description", ""),
            "file":        art.get("locations", [{}])[0].get("path", "") if art.get("locations") else "",
            "line":        "",
            "package":     art.get("name", ""),
            "version":     art.get("version", ""),
            "fixed_in":    fix_ver,
            "cve":         vuln.get("id", ""),
            "url":         (vuln.get("urls") or [""])[0],
        })
    return findings


# ── Deduplication ─────────────────────────────────────────────────────────────
def deduplicate(findings: list[dict]) -> list[dict]:
    """
    Merge findings with the same (rule_id, package, file, severity).
    The merged record carries all source tools in a 'sources' list.
    """
    groups: dict[tuple, dict] = {}

    for f in findings:
        key = (
            f["rule_id"].upper(),
            f["package"].lower(),
            f["file"].lower(),
            f["severity"],
        )
        if key not in groups:
            groups[key] = {**f, "sources": [f["tool"]]}
        else:
            existing = groups[key]
            if f["tool"] not in existing["sources"]:
                existing["sources"].append(f["tool"])
            # Prefer richer description
            if len(f["description"]) > len(existing["description"]):
                existing["description"] = f["description"]
            # Prefer non-empty fix version
            if not existing["fixed_in"] and f["fixed_in"]:
                existing["fixed_in"] = f["fixed_in"]

    deduped = list(groups.values())
    # Sort: severity desc, then rule_id asc
    deduped.sort(key=lambda x: (-severity_rank(x["severity"]), x["rule_id"]))
    return deduped


# ── Markdown report ───────────────────────────────────────────────────────────
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "UNKNOWN":  "⚪",
    "INFO":     "⚪",
}

def write_markdown(findings: list[dict], path: Path, counts_by_tool: dict):
    total = len(findings)
    by_sev = defaultdict(int)
    for f in findings:
        by_sev[f["severity"]] += 1

    lines = [
        "# 🔐 Consolidated Security Scan Report",
        "",
        f"> Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"> Total unique findings: **{total}**",
        "",
        "---",
        "",
        "## 📊 Summary",
        "",
        "### By Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        c = by_sev.get(sev, 0)
        if c:
            lines.append(f"| {SEVERITY_EMOJI.get(sev,'')} {sev} | {c} |")

    lines += [
        "",
        "### By Tool (before deduplication)",
        "",
        "| Tool | Findings |",
        "|------|----------|",
    ]
    for tool, cnt in sorted(counts_by_tool.items()):
        lines.append(f"| {tool} | {cnt} |")

    lines += [
        "",
        "---",
        "",
        "## 🔍 Findings",
        "",
        "| # | Severity | Type | Rule / CVE | Package / File | Version | Fixed In | Sources | Description |",
        "|---|----------|------|-----------|----------------|---------|----------|---------|-------------|",
    ]

    for i, f in enumerate(findings, 1):
        sev_icon = SEVERITY_EMOJI.get(f["severity"], "")
        rule     = f["cve"] or f["rule_id"]
        pkg_file = f["package"] or f["file"] or "—"
        ver      = f["version"] or "—"
        fix      = f["fixed_in"] or "—"
        sources  = ", ".join(f.get("sources", [f["tool"]]))
        desc     = (f["description"] or f["title"] or "—")[:120].replace("|", "\\|").replace("\n", " ")
        url      = f.get("url", "")
        rule_md  = f"[{rule}]({url})" if url and rule else rule or "—"

        lines.append(
            f"| {i} | {sev_icon} {f['severity']} | {f['type']} | {rule_md} "
            f"| {pkg_file} | {ver} | {fix} | {sources} | {desc} |"
        )

    lines += [
        "",
        "---",
        "",
        "## 🗝️ Deduplication Logic",
        "",
        "Findings are deduplicated on the composite key: `(rule_id, package, file, severity)`.",
        "When multiple tools report the same issue, the record is merged and all tools",
        "are listed in the **Sources** column.",
        "",
        "---",
        "*Report generated by `consolidate_reports.py`*",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="Consolidate & deduplicate security scan reports")
    ap.add_argument("--bandit",       type=Path, help="Bandit JSON report")
    ap.add_argument("--trivy-fs",     type=Path, help="Trivy filesystem JSON report")
    ap.add_argument("--trivy-image",  type=Path, help="Trivy image JSON report")
    ap.add_argument("--grype",        type=Path, help="Grype JSON report")
    ap.add_argument("--output-json",  type=Path, default=Path("consolidated-report.json"))
    ap.add_argument("--output-md",    type=Path, default=Path("consolidated-report.md"))
    args = ap.parse_args()

    all_findings: list[dict] = []
    counts_by_tool: dict[str, int] = {}

    if args.bandit and args.bandit.exists():
        f = parse_bandit(args.bandit)
        counts_by_tool["bandit"] = len(f)
        all_findings.extend(f)
        print(f"[INFO] Bandit:       {len(f):>5} findings")

    if args.trivy_fs and args.trivy_fs.exists():
        f = parse_trivy(args.trivy_fs, "fs")
        counts_by_tool["trivy-fs"] = len(f)
        all_findings.extend(f)
        print(f"[INFO] Trivy FS:     {len(f):>5} findings")

    if args.trivy_image and args.trivy_image.exists():
        f = parse_trivy(args.trivy_image, "image")
        counts_by_tool["trivy-image"] = len(f)
        all_findings.extend(f)
        print(f"[INFO] Trivy Image:  {len(f):>5} findings")

    if args.grype and args.grype.exists():
        f = parse_grype(args.grype)
        counts_by_tool["grype"] = len(f)
        all_findings.extend(f)
        print(f"[INFO] Grype:        {len(f):>5} findings")

    total_raw = len(all_findings)
    deduped   = deduplicate(all_findings)
    saved     = total_raw - len(deduped)
    print(f"[INFO] Raw total:    {total_raw:>5}")
    print(f"[INFO] After dedup:  {len(deduped):>5}  ({saved} duplicates removed)")

    # JSON output
    output = {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "total_raw":          total_raw,
        "total_deduplicated": len(deduped),
        "duplicates_removed": saved,
        "counts_by_tool":     counts_by_tool,
        "findings":           deduped,
    }
    args.output_json.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"[INFO] JSON → {args.output_json}")

    # Markdown output
    write_markdown(deduped, args.output_md, counts_by_tool)
    print(f"[INFO] MD   → {args.output_md}")

    # Exit 1 if any CRITICAL or HIGH findings remain after dedup
    critical_high = [f for f in deduped if f["severity"] in ("CRITICAL", "HIGH")]
    if critical_high:
        print(f"\n[GATE] ❌ {len(critical_high)} CRITICAL/HIGH findings after deduplication.", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[GATE] ✅ No CRITICAL/HIGH findings after deduplication.")
        sys.exit(0)


if __name__ == "__main__":
    main()