"""
risk_engine.py — PyShield Threat Intelligence Engine
Scores all findings and produces a structured risk assessment.

Input:  list of ports with CVEs attached (output from nvd.lookup_all)
Output: risk report dict with total score, level, and per-service findings

Scoring logic:
  - Each CVE contributes its CVSS weight to the total score
  - Critical ports with CVEs get a 1.5x multiplier
  - Services with no version detected get a penalty (unknown risk)
  - Multiple HIGH/CRITICAL CVEs on same service stack up
"""

import logging
from datetime import datetime

from config import RISK_WEIGHTS, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM

logger = logging.getLogger("threatintel.risk_engine")


# ── Public API ────────────────────────────────────────────────────────────────
def assess(target: str, nvd_results: list[dict]) -> dict:
    """
    Produce a full risk assessment from NVD results.

    Args:
        target     : scanned IP/hostname
        nvd_results: output from nvd.lookup_all()

    Returns:
        {
            "target":       "192.168.1.1",
            "timestamp":    "2026-06-27 10:00:00",
            "total_score":  87,
            "risk_level":   "CRITICAL",
            "summary":      [...],
            "findings":     [...],
            "statistics":   {...},
        }
    """
    findings    = []
    total_score = 0

    for entry in nvd_results:
        finding = _score_entry(entry)
        findings.append(finding)
        total_score += finding["score"]

    # Sort findings: highest score first
    findings.sort(key=lambda x: x["score"], reverse=True)

    risk_level = _get_risk_level(total_score)
    stats      = _build_statistics(findings)
    summary    = _build_summary(target, total_score, risk_level, findings, stats)

    report = {
        "target":      target,
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_score": total_score,
        "risk_level":  risk_level,
        "summary":     summary,
        "findings":    findings,
        "statistics":  stats,
    }

    logger.info(
        "Risk assessment complete: score=%d level=%s findings=%d",
        total_score, risk_level, len(findings)
    )
    return report


# ── Scoring ───────────────────────────────────────────────────────────────────
def _score_entry(entry: dict) -> dict:
    """
    Score a single port/service entry.

    Scoring breakdown:
      Base score    : sum of RISK_WEIGHTS for each CVE found
      Critical port : 1.5x multiplier if port is in CRITICAL_PORTS
      No version    : +5 penalty (unknown version = unknown risk)
      No CVEs found : +2 (open port still has some risk even without CVEs)
    """
    port     = entry.get("port", 0)
    service  = entry.get("detected_service", entry.get("service", "unknown"))
    version  = entry.get("detected_version", "")
    cves     = entry.get("cves", [])
    critical = entry.get("critical", False)
    banner   = entry.get("banner", "")

    score = 0

    # Score each CVE by severity weight
    for cve in cves:
        severity = cve.get("severity", "NONE")
        score   += RISK_WEIGHTS.get(severity, 0)

    # Critical port multiplier
    if critical and score > 0:
        score = int(score * 1.5)

    # Unknown version penalty
    if not version and not cves:
        score += 5 if critical else 2

    # Open port with no CVEs still carries minimal risk
    if not cves and score == 0:
        score = 2 if critical else 1

    worst_cve = cves[0] if cves else None

    return {
        "port":           port,
        "service":        service,
        "version":        version or "unknown",
        "banner":         banner,
        "cve_count":      len(cves),
        "score":          score,
        "critical_port":  critical,
        "worst_cve_id":   worst_cve["id"] if worst_cve else None,
        "worst_cvss":     worst_cve["cvss_score"] if worst_cve else 0.0,
        "worst_severity": worst_cve["severity"] if worst_cve else "NONE",
        "cves":           cves,
    }


# ── Risk level ────────────────────────────────────────────────────────────────
def _get_risk_level(score: int) -> str:
    if score == 0:  return "CLEAN"
    if score < 10:  return "LOW"
    if score < 30:  return "MEDIUM"
    if score < 60:  return "HIGH"
    return "CRITICAL"


# ── Statistics ────────────────────────────────────────────────────────────────
def _build_statistics(findings: list[dict]) -> dict:
    total_cves         = sum(f["cve_count"] for f in findings)
    critical_cves      = sum(1 for f in findings for cve in f["cves"] if cve["severity"] == "CRITICAL")
    high_cves          = sum(1 for f in findings for cve in f["cves"] if cve["severity"] == "HIGH")
    critical_ports_open = sum(1 for f in findings if f["critical_port"])
    services_no_version = sum(1 for f in findings if f["version"] == "unknown")

    return {
        "total_ports_scanned":  len(findings),
        "total_cves_found":     total_cves,
        "critical_cves":        critical_cves,
        "high_cves":            high_cves,
        "critical_ports_open":  critical_ports_open,
        "services_no_version":  services_no_version,
    }


# ── Summary ───────────────────────────────────────────────────────────────────
def _build_summary(target: str, score: int, level: str,
                   findings: list[dict], stats: dict) -> list[str]:
    summary = []

    summary.append(
        f"• Target: {target} | Risk Score: {score} | Level: {level}"
    )
    summary.append(
        f"• {stats['total_ports_scanned']} open port(s) found, "
        f"{stats['total_cves_found']} CVE(s) identified."
    )

    if stats["critical_cves"] > 0:
        summary.append(
            f"• CRITICAL: {stats['critical_cves']} critical CVE(s) — "
            f"immediate action required."
        )

    if stats["high_cves"] > 0:
        summary.append(f"• {stats['high_cves']} HIGH severity CVE(s) detected.")

    if stats["critical_ports_open"] > 0:
        ports = [str(f["port"]) for f in findings if f["critical_port"]]
        summary.append(f"• Critical ports exposed: {', '.join(ports)}")

    if stats["services_no_version"] > 0:
        summary.append(
            f"• {stats['services_no_version']} service(s) with unknown version "
            f"— manual verification recommended."
        )

    # Top 3 worst findings
    for f in [f for f in findings if f["worst_cve_id"]][:3]:
        summary.append(
            f"• Port {f['port']} ({f['service']} {f['version']}) → "
            f"{f['worst_cve_id']} CVSS {f['worst_cvss']} {f['worst_severity']}"
        )

    return summary
