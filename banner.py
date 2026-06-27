"""
banner.py — PyShield Threat Intelligence Engine
Banner grabbing — connects to each open port and reads the
service's self-identification string.

Why this matters:
  Port 22 open → we know SSH is running
  Banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" → we know exact version
  That version string is what the NVD API needs to find CVEs.

Each service speaks differently:
  SSH    → sends banner immediately on connect (no prompt needed)
  FTP    → sends "220 FTP server ready" immediately
  SMTP   → sends "220 mail.example.com ESMTP" immediately
  HTTP   → needs a request sent first, then returns headers
  Others → we try a generic read, fall back to empty string
"""

import logging
import socket
import ssl
import time

from config import (
    BANNER_TIMEOUT, BANNER_MAX_BYTES, BANNER_ENCODING, HTTP_PROBE,
)

logger = logging.getLogger("threatintel.banner")


# ── Public API ────────────────────────────────────────────────────────────────
def grab_all(target: str, scan_results: list[dict]) -> list[dict]:
    """
    Grab banners for all open ports found by scanner.py.

    Args:
        target      : IP address
        scan_results: output from scanner.scan()

    Returns:
        Same list with "banner" key added to each dict:
        [
            {
                "port":     22,
                "service":  "ssh",
                "critical": True,
                "banner":   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            },
            ...
        ]
    """
    logger.info("Starting banner grab for %d open ports...", len(scan_results))

    results = []
    for entry in scan_results:
        port    = entry["port"]
        service = entry["service"]

        banner = grab_one(target, port, service)
        entry["banner"] = banner

        if banner:
            logger.info("Port %d (%s): %s", port, service, banner[:80])
        else:
            logger.info("Port %d (%s): no banner", port, service)

        results.append(entry)
        time.sleep(0.1)   # small delay — avoids overwhelming the target

    return results


def grab_one(target: str, port: int, service: str) -> str:
    """
    Grab banner from a single port.
    Chooses the right strategy based on service type.
    Returns the raw banner string, or empty string if nothing received.
    """
    try:
        if service in ("http", "http-alt") or port in (80, 8080, 8000):
            return _grab_http(target, port, use_ssl=False)

        elif service in ("https", "https-alt") or port in (443, 8443):
            return _grab_http(target, port, use_ssl=True)

        else:
            # SSH, FTP, SMTP, Telnet, Redis, MySQL etc.
            # all send a banner immediately on connect
            return _grab_generic(target, port)

    except Exception as e:
        logger.debug("Banner grab failed for %s:%d — %s", target, port, e)
        return ""


# ── Grabbing strategies ───────────────────────────────────────────────────────
def _grab_generic(target: str, port: int) -> str:
    """
    Connect and immediately read whatever the service sends.
    Works for: SSH, FTP, SMTP, POP3, IMAP, Telnet, Redis, VNC, MySQL.

    These protocols announce themselves on connect without needing
    a request from the client first — called an "eager banner."

    Examples:
      SSH   → "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
      FTP   → "220 ProFTPD 1.3.5e Server (ProFTPD)"
      Redis → "+PONG"
      MySQL → random bytes starting with server version
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(BANNER_TIMEOUT)
        s.connect((target, port))
        raw = s.recv(BANNER_MAX_BYTES)
        return _clean(raw)


def _grab_http(target: str, port: int, use_ssl: bool = False) -> str:
    """
    HTTP/HTTPS banner grabbing.
    HTTP doesn't send anything on connect — we send a HEAD request first.
    HEAD asks for headers only (no body) — fast and lightweight.

    What we look for in the response:
      Server: nginx/1.24.0        ← web server + version
      Server: Apache/2.4.54       ← Apache version
      X-Powered-By: PHP/8.1.0    ← backend tech

    Example:
      HTTP/1.1 200 OK
      Server: nginx/1.18.0 (Ubuntu)   ← this becomes our banner
    """
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.settimeout(BANNER_TIMEOUT)

    try:
        raw_socket.connect((target, port))

        if use_ssl:
            # Wrap in SSL — ignore cert errors, we just want the banner
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode    = ssl.CERT_NONE
            sock = context.wrap_socket(raw_socket, server_hostname=target)
        else:
            sock = raw_socket

        # Send HTTP HEAD request
        probe = HTTP_PROBE.format(host=target).encode()
        sock.sendall(probe)

        # Read response headers
        response = b""
        while True:
            chunk = sock.recv(512)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:   # end of HTTP headers
                break
            if len(response) > BANNER_MAX_BYTES:
                break

        return _extract_http_banner(response)

    finally:
        raw_socket.close()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _extract_http_banner(raw: bytes) -> str:
    """
    Extract the most useful version string from HTTP response headers.
    Priority: Server header > X-Powered-By > status line only.
    """
    try:
        text    = raw.decode(BANNER_ENCODING, errors="replace")
        lines   = text.split("\r\n")
        server  = ""
        powered = ""

        for line in lines:
            lower = line.lower()
            if lower.startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif lower.startswith("x-powered-by:"):
                powered = line.split(":", 1)[1].strip()

        if server:
            return f"{server} {powered}".strip()
        elif lines:
            return lines[0].strip()
        return ""

    except Exception:
        return ""


def _clean(raw: bytes) -> str:
    """
    Decode raw bytes, strip control characters.
    Returns first non-empty line — usually the most useful part.

    SSH example raw:  b"SSH-2.0-OpenSSH_8.2p1 Ubuntu\r\n..."
    After clean:      "SSH-2.0-OpenSSH_8.2p1 Ubuntu"
    """
    try:
        text  = raw.decode(BANNER_ENCODING, errors="replace")
        text  = text.replace("\x00", "").replace("\r", "")
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        return lines[0] if lines else ""
    except Exception:
        return ""
