"""
scanner.py — PyShield Threat Intelligence Engine
Multithreaded TCP port scanner.

Differences from project6 port_scanner.py:
  - Returns structured dicts instead of just port numbers
  - Prioritizes critical ports in results
  - Accepts target as argument (not sys.argv)
  - Designed to feed directly into banner.py
"""

import logging
import socket
import threading
from queue import Queue, Empty
import time

from config import (
    SCAN_START_PORT, SCAN_END_PORT, SCAN_THREADS,
    SCAN_TIMEOUT, CRITICAL_PORTS, DEFAULT_PORT_SERVICES,
)

logger = logging.getLogger("threatintel.scanner")


# ── Public API ────────────────────────────────────────────────────────────────
def scan(target: str,
         start_port: int = SCAN_START_PORT,
         end_port: int = SCAN_END_PORT) -> list[dict]:
    """
    Scan target for open TCP ports.

    Args:
        target    : IP address or hostname
        start_port: first port to scan
        end_port  : last port to scan

    Returns:
        List of dicts, one per open port:
        [
            {
                "port":     22,
                "service":  "ssh",       # from DEFAULT_PORT_SERVICES
                "critical": True,        # True if in CRITICAL_PORTS list
            },
            ...
        ]
        Sorted: critical ports first, then by port number.
    """
    # Resolve hostname to IP once — avoids repeated DNS lookups
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        logger.error("Cannot resolve host: %s", target)
        return []

    if target_ip != target:
        logger.info("Resolved %s → %s", target, target_ip)

    logger.info(
        "Scanning %s (ports %d-%d) with %d threads...",
        target_ip, start_port, end_port, SCAN_THREADS
    )

    start_time  = time.time()
    port_queue  = Queue()
    open_ports  = []
    lock        = threading.Lock()

    # Fill queue with all ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    def worker():
        while True:
            try:
                port = port_queue.get_nowait()
            except Empty:
                break
            if _is_open(target_ip, port):
                with lock:
                    open_ports.append(port)
            port_queue.task_done()

    # Launch threads
    threads = []
    for _ in range(min(SCAN_THREADS, end_port - start_port + 1)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    duration = round(time.time() - start_time, 2)
    open_ports.sort()

    logger.info(
        "Scan complete: %d open ports found in %.2fs",
        len(open_ports), duration
    )

    # Build structured result
    results = []
    for port in open_ports:
        results.append({
            "port":     port,
            "service":  DEFAULT_PORT_SERVICES.get(port, "unknown"),
            "critical": port in CRITICAL_PORTS,
        })

    # Sort: critical ports first, then ascending port number
    results.sort(key=lambda x: (not x["critical"], x["port"]))

    if results:
        critical_count = sum(1 for r in results if r["critical"])
        logger.info(
            "Open ports: %s (%d critical)",
            [r["port"] for r in results],
            critical_count,
        )
    else:
        logger.info("No open ports found on %s", target_ip)

    return results


# ── Internal ──────────────────────────────────────────────────────────────────
def _is_open(ip: str, port: int) -> bool:
    """Attempt TCP connect to ip:port. Returns True if connection succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SCAN_TIMEOUT)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
