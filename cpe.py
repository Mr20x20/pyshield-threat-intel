"""
cpe.py — PyShield Threat Intelligence Engine
Converts detected service name + version into CPE 2.3 format strings.

What is CPE?
  CPE = Common Platform Enumeration
  It's a standardized naming scheme for software, maintained by NIST.
  The NVD API uses CPE strings to identify vulnerable products.

CPE 2.3 format:
  cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

  part:    'a' = application, 'o' = OS, 'h' = hardware
  vendor:  company that makes it (e.g. 'openbsd' for OpenSSH)
  product: product name (e.g. 'openssh')
  version: version string (e.g. '8.2p1')
  *:       wildcard — means "any value" for fields we don't know

Example:
  service="openssh", version="8.2p1"
  → cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*

Why vendor matters:
  The NVD distinguishes between products by vendor.
  "mysql" alone is ambiguous — MySQL was owned by Sun, then Oracle.
  The correct CPE vendor for MySQL is "oracle" not "mysql".
  Getting the vendor wrong = no CVE results from the API.
"""

import logging
import re

logger = logging.getLogger("threatintel.cpe")


# ── CPE vendor+product mapping ────────────────────────────────────────────────
# Maps our detected_service name → (vendor, product) for CPE generation.
# These are the official NVD CPE vendor/product names.
# Getting these right is critical — wrong vendor = no CVE matches.

_CPE_MAP = {
    # SSH
    "openssh":          ("openbsd",       "openssh"),
    "dropbear_ssh":     ("matt_johnston",  "dropbear_ssh"),
    "ssh":              ("openbsd",        "openssh"),      # safe default

    # FTP
    "proftpd":          ("proftpd",        "proftpd"),
    "vsftpd":           ("beasts",         "vsftpd"),
    "filezilla_server": ("filezilla-project", "filezilla_server"),
    "ftp":              ("*",              "ftp"),

    # SMTP
    "postfix":          ("postfix",        "postfix"),
    "exim":             ("exim",           "exim"),
    "microsoft_smtp":   ("microsoft",      "exchange_server"),

    # Web servers
    "nginx":            ("nginx",          "nginx"),
    "apache_http_server": ("apache",       "http_server"),
    "microsoft_iis":    ("microsoft",      "internet_information_services"),
    "lighttpd":         ("lighttpd",       "lighttpd"),
    "openresty":        ("openresty",      "openresty"),

    # Databases
    "mysql":            ("oracle",         "mysql"),
    "mariadb":          ("mariadb",        "mariadb"),
    "postgresql":       ("postgresql",     "postgresql"),
    "redis":            ("redis",          "redis"),
    "mongodb":          ("mongodb",        "mongodb"),

    # Remote access
    "rdp":              ("microsoft",      "remote_desktop_protocol"),
    "vnc":              ("realvnc",        "vnc"),
    "telnet":           ("mit",            "telnet"),

    # Other
    "http":             ("apache",         "http_server"),  # common default
    "https":            ("apache",         "http_server"),
    "smb":              ("microsoft",      "windows"),
    "pop3":             ("*",              "pop3"),
    "imap":             ("*",              "imap"),
    "dns":              ("isc",            "bind"),
    "smtp":             ("*",              "smtp"),
}


# ── Public API ────────────────────────────────────────────────────────────────
def build_all(detected_results: list[dict]) -> list[dict]:
    """
    Build CPE strings for all detected services.

    Args:
        detected_results: output from detector.detect_all()

    Returns:
        Same list with "cpe" key added:
        [
            {
                "port":             22,
                "detected_service": "openssh",
                "detected_version": "8.2p1",
                "cpe":              "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
            },
            ...
        ]
    """
    for entry in detected_results:
        service = entry.get("detected_service", "")
        version = entry.get("detected_version", "")

        cpe = build_one(service, version)
        entry["cpe"] = cpe

        if cpe:
            logger.info("Port %d → CPE: %s", entry["port"], cpe)
        else:
            logger.info(
                "Port %d → no CPE (service=%s version=%s)",
                entry["port"], service, version
            )

    return detected_results


def build_one(service: str, version: str) -> str:
    """
    Build a single CPE 2.3 string.

    Args:
        service: detected service name e.g. "openssh", "nginx"
        version: detected version e.g. "8.2p1", "1.18.0"

    Returns:
        CPE string e.g. "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
        Empty string "" if service is unknown or unmappable.

    Logic:
        1. Look up (vendor, product) in _CPE_MAP
        2. Clean the version string
        3. Assemble CPE 2.3 format
        4. If no version → use wildcard (*) so NVD returns all versions
    """
    if not service:
        return ""

    service = service.lower().strip()

    if service not in _CPE_MAP:
        logger.debug("No CPE mapping for service: %s", service)
        return ""

    vendor, product = _CPE_MAP[service]

    # Skip entries with wildcard vendor — too generic to be useful
    if vendor == "*":
        return ""

    # Clean version — remove spaces, parentheses, OS suffixes
    # "8.2p1 Ubuntu" → "8.2p1"
    # "2.4.54 (Debian)" → "2.4.54"
    clean_version = _clean_version(version) if version else "*"

    # CPE 2.3 format — wildcards (*) for unknown fields
    cpe = f"cpe:2.3:a:{vendor}:{product}:{clean_version}:*:*:*:*:*:*:*"
    return cpe


# ── Helpers ───────────────────────────────────────────────────────────────────
def _clean_version(version: str) -> str:
    """
    Normalize a version string for use in a CPE.

    Examples:
      "8.2p1 Ubuntu-4ubuntu0.5"  → "8.2p1"
      "2.4.54 (Debian)"          → "2.4.54"
      "1.18.0"                   → "1.18.0"
      "1.3.5e"                   → "1.3.5e"
      ""                         → "*"
    """
    if not version:
        return "*"

    # Take only the first token — stops at space or parenthesis
    version = version.split()[0]
    version = version.split("(")[0]

    # Remove any trailing non-alphanumeric except dots and letters
    version = re.sub(r"[^\w.]", "", version)

    return version.strip() or "*"
