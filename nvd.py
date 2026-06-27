"""
nvd.py — PyShield Threat Intelligence Engine
Queries the NVD (National Vulnerability Database) API
to find CVEs for each detected service.

NVD API v2 docs: https://nvd.nist.gov/developers/vulnerabilities

Flow:
  CPE string → NVD API → list of CVEs with CVSS scores
  "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
  → CVE-2023-38408 (CVSS 9.8 CRITICAL)
  → CVE-2021-41617 (CVSS 7.0 HIGH)
"""

import logging
import time

import requests

from config import (
    NVD_API_KEY, NVD_BASE_URL, NVD_RATE_LIMIT_DELAY,
    NVD_TIMEOUT, NVD_MAX_CVES, CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, CVSS_LOW,
)

logger = logging.getLogger("threatintel.nvd")


# ── Public API ────────────────────────────────────────────────────────────────
def lookup_all(cpe_results: list[dict]) -> list[dict]:
    """
    Look up CVEs for all entries that have a CPE string.

    Args:
        cpe_results: output from cpe.build_all()

    Returns:
        Same list with "cves" key added to each entry:
        [
            {
                "port":             22,
                "detected_service": "openssh",
                "detected_version": "8.2p1",
                "cpe":              "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
                "cves": [
                    {
                        "id":          "CVE-2023-38408",
                        "description": "...",
                        "cvss_score":  9.8,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "severity":    "CRITICAL",
                        "published":   "2023-07-20",
                        "references":  ["https://..."],
                    },
                    ...
                ],
            },
            ...
        ]
    """
    if not NVD_API_KEY:
        logger.warning(
            "NVD_API_KEY not set — rate limit is 5 req/30s. "
            "Add your key to .env for better performance."
        )

    for entry in cpe_results:
        cpe = entry.get("cpe", "")

        if not cpe:
            entry["cves"] = []
            logger.info(
                "Port %d: no CPE — skipping NVD lookup",
                entry["port"]
            )
            continue

        logger.info(
            "Querying NVD for port %d (%s)...",
            entry["port"],
            entry.get("detected_service", "unknown")
        )

        cves = lookup_cpe(cpe)
        entry["cves"] = cves

        if cves:
            logger.info(
                "Port %d → %d CVE(s) found (worst: %s %s)",
                entry["port"],
                len(cves),
                cves[0]["severity"],
                cves[0]["id"],
            )
        else:
            logger.info("Port %d → no CVEs found", entry["port"])

        # Rate limit delay between requests
        time.sleep(NVD_RATE_LIMIT_DELAY)

    return cpe_results


def lookup_cpe(cpe: str) -> list[dict]:
    """
    Query NVD API for CVEs matching a CPE string.

    Args:
        cpe: CPE 2.3 string e.g. "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"

    Returns:
        List of CVE dicts sorted by CVSS score descending (worst first).
        Empty list if no CVEs found or request fails.
    """
    params = {
        "cpeName":        cpe,
        "resultsPerPage": NVD_MAX_CVES,
        "startIndex":     0,
    }

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        response = requests.get(
            NVD_BASE_URL,
            params=params,
            headers=headers,
            timeout=NVD_TIMEOUT,
        )

        if response.status_code == 403:
            logger.error("NVD API: 403 Forbidden — check your API key")
            return []

        if response.status_code == 429:
            logger.warning("NVD API: rate limited — waiting 35s...")
            time.sleep(35)
            return lookup_cpe(cpe)   # retry once

        if response.status_code != 200:
            logger.error(
                "NVD API: unexpected status %d for CPE %s",
                response.status_code, cpe
            )
            return []

        data = response.json()
        return _parse_response(data)

    except requests.exceptions.Timeout:
        logger.error("NVD API: request timed out for CPE %s", cpe)
        return []
    except requests.exceptions.ConnectionError:
        logger.error("NVD API: connection error — check internet connection")
        return []
    except Exception as e:
        logger.exception("NVD API: unexpected error: %s", e)
        return []


# ── Response parsing ──────────────────────────────────────────────────────────
def _parse_response(data: dict) -> list[dict]:
    """
    Parse the NVD API JSON response into clean CVE dicts.

    NVD API v2 response structure:
    {
      "totalResults": 5,
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2023-38408",
            "descriptions": [{"lang": "en", "value": "..."}],
            "published": "2023-07-20T...",
            "metrics": {
              "cvssMetricV31": [{
                "cvssData": {
                  "baseScore": 9.8,
                  "vectorString": "CVSS:3.1/...",
                  "baseSeverity": "CRITICAL"
                }
              }]
            },
            "references": [{"url": "..."}]
          }
        }
      ]
    }
    """
    cves = []
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        cve_data = vuln.get("cve", {})

        cve_id = cve_data.get("id", "")
        if not cve_id:
            continue

        # Extract English description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS score — prefer v3.1, fall back to v3.0, then v2
        cvss_score, cvss_vector, severity = _extract_cvss(
            cve_data.get("metrics", {})
        )

        # Published date — trim to YYYY-MM-DD
        published_raw = cve_data.get("published", "")
        published = published_raw[:10] if published_raw else ""

        # References — first 3 URLs
        references = [
            ref["url"]
            for ref in cve_data.get("references", [])[:3]
            if ref.get("url")
        ]

        cves.append({
            "id":          cve_id,
            "description": description[:300],   # truncate long descriptions
            "cvss_score":  cvss_score,
            "cvss_vector": cvss_vector,
            "severity":    severity,
            "published":   published,
            "references":  references,
        })

    # Sort by CVSS score descending — worst vulnerabilities first
    cves.sort(key=lambda x: x["cvss_score"], reverse=True)
    return cves


def _extract_cvss(metrics: dict) -> tuple[float, str, str]:
    """
    Extract CVSS base score, vector string, and severity.
    Tries v3.1 first, then v3.0, then v2.0.

    Returns: (score, vector, severity)
    """
    # Try CVSS v3.1
    for metric in metrics.get("cvssMetricV31", []):
        cvss = metric.get("cvssData", {})
        score    = float(cvss.get("baseScore", 0.0))
        vector   = cvss.get("vectorString", "")
        severity = _score_to_severity(score)
        return score, vector, severity

    # Try CVSS v3.0
    for metric in metrics.get("cvssMetricV30", []):
        cvss = metric.get("cvssData", {})
        score    = float(cvss.get("baseScore", 0.0))
        vector   = cvss.get("vectorString", "")
        severity = _score_to_severity(score)
        return score, vector, severity

    # Fall back to CVSS v2
    for metric in metrics.get("cvssMetricV2", []):
        cvss = metric.get("cvssData", {})
        score    = float(cvss.get("baseScore", 0.0))
        vector   = cvss.get("vectorString", "")
        severity = _score_to_severity(score)
        return score, vector, severity

    return 0.0, "", "NONE"


def _score_to_severity(score: float) -> str:
    """Convert CVSS numeric score to severity label."""
    if score >= CVSS_CRITICAL:
        return "CRITICAL"
    elif score >= CVSS_HIGH:
        return "HIGH"
    elif score >= CVSS_MEDIUM:
        return "MEDIUM"
    elif score >= CVSS_LOW:
        return "LOW"
    return "NONE"
