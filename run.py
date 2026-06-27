"""
run.py — PyShield Threat Intelligence Engine
Entry point. Runs the full pipeline end to end.

Usage:
    python run.py <target> [start_port] [end_port]

Examples:
    python run.py 127.0.0.1
    python run.py 192.168.1.1 1 1024
    python run.py scanme.nmap.org 1 512

Pipeline:
    1. Port scan     → find open ports
    2. Banner grab   → read service banners
    3. Detection     → parse service name + version
    4. CPE build     → convert to NVD-compatible format
    5. NVD lookup    → fetch CVEs + CVSS scores
    6. Risk engine   → score findings
    7. Report        → write threat_intel_report.json
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("threatintel.run")

# ── Imports ───────────────────────────────────────────────────────────────────
import scanner
import banner
import detector
import cpe
import nvd
import risk_engine
from config import SCAN_START_PORT, SCAN_END_PORT, REPORT_FILE, NVD_API_KEY


# ── Pipeline ──────────────────────────────────────────────────────────────────
def run(target: str, start_port: int = SCAN_START_PORT,
        end_port: int = SCAN_END_PORT) -> dict:
    """
    Run the full threat intelligence pipeline against a target.

    Args:
        target    : IP address or hostname
        start_port: first port to scan
        end_port  : last port to scan

    Returns:
        Final risk assessment dict
    """
    logger.info("=" * 55)
    logger.info("  PyShield Threat Intelligence Engine")
    logger.info("  Target : %s", target)
    logger.info("  Ports  : %d - %d", start_port, end_port)
    logger.info("  NVD key: %s", "set" if NVD_API_KEY else "NOT SET")
    logger.info("=" * 55)

    # ── Step 1: Port scan ─────────────────────────────────────────────────────
    logger.info("[1/6] Port scanning...")
    scan_results = scanner.scan(target, start_port, end_port)

    if not scan_results:
        logger.warning("No open ports found — stopping pipeline.")
        return _empty_report(target)

    # ── Step 2: Banner grabbing ───────────────────────────────────────────────
    logger.info("[2/6] Grabbing banners...")
    banner_results = banner.grab_all(target, scan_results)

    # ── Step 3: Service detection ─────────────────────────────────────────────
    logger.info("[3/6] Detecting services and versions...")
    detected_results = detector.detect_all(banner_results)

    # ── Step 4: CPE generation ────────────────────────────────────────────────
    logger.info("[4/6] Building CPE strings...")
    cpe_results = cpe.build_all(detected_results)

    # ── Step 5: NVD CVE lookup ────────────────────────────────────────────────
    logger.info("[5/6] Querying NVD API for CVEs...")
    nvd_results = nvd.lookup_all(cpe_results)

    # ── Step 6: Risk assessment ───────────────────────────────────────────────
    logger.info("[6/6] Calculating risk scores...")
    report = risk_engine.assess(target, nvd_results)

    # ── Write report ──────────────────────────────────────────────────────────
    _write_report(report)
    _print_summary(report)

    return report


# ── Output ────────────────────────────────────────────────────────────────────
def _write_report(report: dict) -> None:
    """Write the final report to JSON file."""
    try:
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)
        logger.info("Report saved to %s", REPORT_FILE)
    except Exception as e:
        logger.error("Failed to write report: %s", e)


def _print_summary(report: dict) -> None:
    """Print a clean summary to terminal."""
    print("\n" + "=" * 55)
    print(f"  THREAT INTELLIGENCE REPORT")
    print(f"  Target     : {report['target']}")
    print(f"  Timestamp  : {report['timestamp']}")
    print(f"  Risk Score : {report['total_score']}")
    print(f"  Risk Level : {report['risk_level']}")
    print("=" * 55)

    stats = report.get("statistics", {})
    print(f"  Open Ports : {stats.get('total_ports_scanned', 0)}")
    print(f"  CVEs Found : {stats.get('total_cves_found', 0)}")
    print(f"  Critical   : {stats.get('critical_cves', 0)}")
    print(f"  High       : {stats.get('high_cves', 0)}")
    print("-" * 55)

    print("  SUMMARY:")
    for line in report.get("summary", []):
        print(f"  {line}")

    print("-" * 55)
    print("  TOP FINDINGS:")
    for f in report.get("findings", [])[:5]:
        cve_info = (
            f"{f['worst_cve_id']} (CVSS {f['worst_cvss']})"
            if f["worst_cve_id"] else "no CVEs found"
        )
        print(
            f"  Port {f['port']:5} | {f['service']:20} "
            f"v{f['version']:15} | {cve_info}"
        )
    print("=" * 55)
    print(f"  Full report: {REPORT_FILE}\n")


def _empty_report(target: str) -> dict:
    """Return a clean empty report when no ports are found."""
    return {
        "target":      target,
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_score": 0,
        "risk_level":  "CLEAN",
        "summary":     [f"• No open ports found on {target}."],
        "findings":    [],
        "statistics":  {
            "total_ports_scanned":  0,
            "total_cves_found":     0,
            "critical_cves":        0,
            "high_cves":            0,
            "critical_ports_open":  0,
            "services_no_version":  0,
        },
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py <target> [start_port] [end_port]")
        print("Examples:")
        print("  python run.py 127.0.0.1")
        print("  python run.py 192.168.1.1 1 1024")
        sys.exit(1)

    target     = sys.argv[1]
    start_port = int(sys.argv[2]) if len(sys.argv) > 2 else SCAN_START_PORT
    end_port   = int(sys.argv[3]) if len(sys.argv) > 3 else SCAN_END_PORT

    run(target, start_port, end_port)
