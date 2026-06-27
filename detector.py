"""
detector.py — PyShield Threat Intelligence Engine
Parses raw banner strings into structured service name + version.

This is the bridge between raw network data and threat intelligence.
Without this step we have: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
After this step we have:   service="openssh", version="8.2p1"
That structured data is what cpe.py needs to build a CPE string,
and what the NVD API needs to find CVEs.

Approach: regex pattern matching per protocol.
Each service has a known banner format — we write a pattern for each.
"""

import logging
import re

from config import DEFAULT_PORT_SERVICES

logger = logging.getLogger("threatintel.detector")


# ── Banner patterns ───────────────────────────────────────────────────────────
# Each entry: (compiled_regex, service_name, version_group_index)
# We try patterns in order — first match wins.
# version_group_index: which regex group contains the version string.

_PATTERNS = [

    # ── SSH ───────────────────────────────────────────────────────────────────
    # "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    # "SSH-2.0-OpenSSH_7.4"
    (re.compile(r"SSH-[\d.]+-OpenSSH[_\s]([\d.p]+)", re.I),
     "openssh", 1),

    # "SSH-2.0-dropbear_2020.81"
    (re.compile(r"SSH-[\d.]+-[Dd]ropbear[_\s]?([\d.]+)?", re.I),
     "dropbear_ssh", 1),

    # Generic SSH fallback
    (re.compile(r"SSH-([\d.]+)", re.I),
     "ssh", 1),

    # ── FTP ───────────────────────────────────────────────────────────────────
    # "220 ProFTPD 1.3.5e Server"
    (re.compile(r"220.*ProFTPD\s+([\d.a-z]+)", re.I),
     "proftpd", 1),

    # "220 vsFTPd 3.0.3"
    (re.compile(r"220.*vsFTPd\s+([\d.]+)", re.I),
     "vsftpd", 1),

    # "220 FileZilla Server 0.9.60"
    (re.compile(r"220.*FileZilla\s+Server\s+([\d.]+)", re.I),
     "filezilla_server", 1),

    # Generic FTP
    (re.compile(r"^220[- ](.{3,60})", re.I),
     "ftp", 1),

    # ── SMTP ──────────────────────────────────────────────────────────────────
    # "220 mail.example.com ESMTP Postfix (2.11.0)"
    (re.compile(r"220.*Postfix\s*\(?([\d.]+)\)?", re.I),
     "postfix", 1),

    # "220 mail.example.com ESMTP Exim 4.94.2"
    (re.compile(r"220.*Exim\s+([\d.]+)", re.I),
     "exim", 1),

    # "220 mail.example.com Microsoft ESMTP MAIL Service"
    (re.compile(r"220.*Microsoft.*ESMTP", re.I),
     "microsoft_smtp", None),

    # ── HTTP / Web servers ────────────────────────────────────────────────────
    # "nginx/1.24.0"  "nginx/1.18.0 (Ubuntu)"
    (re.compile(r"nginx/([\d.]+)", re.I),
     "nginx", 1),

    # "Apache/2.4.54 (Ubuntu)"  "Apache/2.2.34"
    (re.compile(r"Apache/([\d.]+)", re.I),
     "apache_http_server", 1),

    # "Microsoft-IIS/10.0"
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I),
     "microsoft_iis", 1),

    # "lighttpd/1.4.59"
    (re.compile(r"lighttpd/([\d.]+)", re.I),
     "lighttpd", 1),

    # "openresty/1.21.4.1"
    (re.compile(r"[Oo]penresty/([\d.]+)",),
     "openresty", 1),

    # ── Database servers ──────────────────────────────────────────────────────
    # MySQL: first bytes of handshake contain version string
    # Raw banner often starts with null bytes then "8.0.32\x00..."
    (re.compile(r"([\d]+\.[\d]+\.[\d]+)-[Mm]y[Ss][Qq][Ll]", re.I),
     "mysql", 1),

    (re.compile(r"([\d]+\.[\d]+\.[\d]+).*[Mm]aria[Dd][Bb]", re.I),
     "mariadb", 1),

    # PostgreSQL: "SFATAL" or version in startup
    (re.compile(r"PostgreSQL\s+([\d.]+)", re.I),
     "postgresql", 1),

    # Redis: "+PONG" or "-ERR" — no version in default banner
    (re.compile(r"^\+PONG", re.I),
     "redis", None),

    # MongoDB: no banner by default, but sometimes version in error
    (re.compile(r"MongoDB\s+([\d.]+)", re.I),
     "mongodb", 1),

    # ── Other services ────────────────────────────────────────────────────────
    # Telnet
    (re.compile(r"telnet", re.I),
     "telnet", None),

    # VNC: "RFB 003.008"
    (re.compile(r"RFB\s+([\d.]+)", re.I),
     "vnc", 1),

    # RDP — usually no readable banner, detected by port
    # Handled by fallback below

]


# ── Public API ────────────────────────────────────────────────────────────────
def detect_all(banner_results: list[dict]) -> list[dict]:
    """
    Detect service name and version for each port.

    Args:
        banner_results: output from banner.grab_all()

    Returns:
        Same list with "detected_service" and "detected_version" added:
        [
            {
                "port":              22,
                "service":           "ssh",
                "critical":          True,
                "banner":            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "detected_service":  "openssh",
                "detected_version":  "8.2p1",
            },
            ...
        ]
    """
    for entry in banner_results:
        service, version = detect_one(
            entry.get("banner", ""),
            entry.get("port", 0),
            entry.get("service", "unknown"),
        )
        entry["detected_service"] = service
        entry["detected_version"] = version

        logger.info(
            "Port %d → service=%s version=%s",
            entry["port"],
            service,
            version or "unknown",
        )

    return banner_results


def detect_one(banner: str, port: int, fallback_service: str) -> tuple[str, str]:
    """
    Parse one banner string into (service_name, version).

    Args:
        banner          : raw banner string from banner.py
        port            : port number (used as fallback)
        fallback_service: service name from config (used if banner empty)

    Returns:
        (service_name, version)
        version is empty string "" if we can't determine it.

    Examples:
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu" → ("openssh", "8.2p1")
        "nginx/1.18.0 (Ubuntu)"        → ("nginx", "1.18.0")
        "Apache/2.4.54"                → ("apache_http_server", "2.4.54")
        "+PONG"                        → ("redis", "")
        ""                             → ("rdp", "")  ← port 3389 fallback
    """
    if banner:
        for pattern, service_name, version_group in _PATTERNS:
            match = pattern.search(banner)
            if match:
                version = ""
                if version_group is not None:
                    try:
                        version = match.group(version_group) or ""
                    except IndexError:
                        version = ""
                return service_name, version.strip()

    # No banner matched — fall back to port-based service name
    service = DEFAULT_PORT_SERVICES.get(port, fallback_service)
    return service, ""
