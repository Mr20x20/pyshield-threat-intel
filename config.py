"""
config.py — PyShield Threat Intelligence Engine
Central configuration. All other modules import from here.
API key is read from .env file — never hardcoded.
"""

import os
from pathlib import Path

# ── Project root ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()

# ── Directories ───────────────────────────────────────────────────────────────
DATA_DIR    = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ── Load .env file manually ───────────────────────────────────────────────────
# We don't use python-dotenv to keep dependencies minimal.
# Reads KEY=VALUE lines from .env and puts them in os.environ.
_env_file = BASE_DIR / ".env"
if _env_file.exists():
    with open(_env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

# ── NVD API ───────────────────────────────────────────────────────────────────
NVD_API_KEY     = os.environ.get("NVD_API_KEY", "")
NVD_BASE_URL    = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# With API key: 50 requests per 30s
# Without:       5 requests per 30s
# We always use the key — but handle rate limit gracefully if hit
NVD_RATE_LIMIT_DELAY = 0.7   # seconds between requests (safe with key)
NVD_TIMEOUT          = 10    # seconds per request
NVD_MAX_CVES         = 10    # max CVEs to fetch per service

# ── Port Scanner ──────────────────────────────────────────────────────────────
# Default port range for the scanner
SCAN_START_PORT  = 1
SCAN_END_PORT    = 1024
SCAN_THREADS     = 100
SCAN_TIMEOUT     = 1       # seconds per port connection attempt

# Well-known ports we care most about for threat intel
CRITICAL_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                  3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

# ── Banner Grabbing ───────────────────────────────────────────────────────────
BANNER_TIMEOUT    = 3      # seconds to wait for banner response
BANNER_MAX_BYTES  = 1024   # max bytes to read from banner
BANNER_ENCODING   = "utf-8"

# HTTP probe request — sent to HTTP/HTTPS ports to get Server header
HTTP_PROBE = "HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n"

# ── Service Detection ─────────────────────────────────────────────────────────
# Maps port numbers to service names when banner parsing fails
# Used as fallback — banner grabbing is always attempted first
DEFAULT_PORT_SERVICES = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    143:   "imap",
    443:   "https",
    445:   "smb",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    6379:  "redis",
    8080:  "http-alt",
    8443:  "https-alt",
    27017: "mongodb",
}

# ── Risk Engine ───────────────────────────────────────────────────────────────
# CVSS v3 score thresholds
CVSS_CRITICAL  = 9.0
CVSS_HIGH      = 7.0
CVSS_MEDIUM    = 4.0
CVSS_LOW       = 0.1

# Risk score weights per CVE severity
RISK_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    7,
    "LOW":       2,
    "NONE":      0,
}

# ── Output ────────────────────────────────────────────────────────────────────
REPORT_FILE = REPORTS_DIR / "threat_intel_report.json"
