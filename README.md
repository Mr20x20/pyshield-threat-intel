# 🔍 PyShield Threat Intelligence Engine

A fully automated vulnerability scanner that takes a target IP, discovers open ports, identifies running services and their versions via banner grabbing, and queries the NIST National Vulnerability Database (NVD) API to find known CVEs — producing a structured risk report.

Part of the **PyShield** security portfolio, designed to feed into the PyShield SIEM Dashboard.

---

## 🏗️ Pipeline Architecture

```
Target IP
    │
    ▼
┌─────────────┐
│ scanner.py  │  Multithreaded TCP port scan (100 threads)
└──────┬──────┘
       │ open ports
       ▼
┌─────────────┐
│  banner.py  │  Banner grabbing — reads service self-identification
└──────┬──────┘  SSH/FTP/SMTP: reads immediately
       │         HTTP/HTTPS: sends HEAD request first
       │ raw banners
       ▼
┌──────────────┐
│ detector.py  │  Regex parsing → service name + version
└──────┬───────┘  "SSH-2.0-OpenSSH_8.2p1" → ("openssh", "8.2p1")
       │
       ▼
┌──────────┐
│  cpe.py  │  CPE 2.3 string generation
└──────┬───┘  ("openssh","8.2p1") → "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"
       │
       ▼
┌──────────┐
│  nvd.py  │  NVD API v2 → CVEs + CVSS scores + references
└──────┬───┘
       │
       ▼
┌──────────────────┐
│ risk_engine.py   │  Weighted scoring → risk level + ranked findings
└──────┬───────────┘
       │
       ▼
┌──────────────────────────┐
│ threat_intel_report.json │  Structured output → PyShield SIEM
└──────────────────────────┘
```

---

## 📋 Example Output

```
=======================================================
  THREAT INTELLIGENCE REPORT
  Target     : 192.168.1.1
  Timestamp  : 2026-06-27 10:00:00
  Risk Score : 87
  Risk Level : CRITICAL
=======================================================
  Open Ports : 4
  CVEs Found : 12
  Critical   : 3
  High       : 5
-------------------------------------------------------
  SUMMARY:
  • Target: 192.168.1.1 | Risk Score: 87 | Level: CRITICAL
  • 4 open port(s) found, 12 CVE(s) identified.
  • CRITICAL: 3 critical CVE(s) — immediate action required.
  • Critical ports exposed: 22, 3389
  • Port 22 (openssh 8.2p1) → CVE-2023-38408 CVSS 9.8 CRITICAL
-------------------------------------------------------
```

---

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Mr20x20/pyshield-threat-intel.git
cd pyshield-threat-intel
```

### 2. Create virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up NVD API key

Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key

Create a `.env` file in the project root:
```
NVD_API_KEY=your-api-key-here
```

Without the key the tool still works but is rate-limited to 5 requests/30s.

### 5. Run a scan

```bash
# Scan localhost
python run.py 127.0.0.1

# Scan a specific host with custom port range
python run.py 192.168.1.1 1 1024

# Scan first 512 ports
python run.py 192.168.1.1 1 512
```

---

## 📁 Project Structure

```
pyshield-threat-intel/
├── run.py              # Entry point — orchestrates full pipeline
├── scanner.py          # Multithreaded TCP port scanner
├── banner.py           # Banner grabbing per service protocol
├── detector.py         # Regex-based service/version detection
├── cpe.py              # CPE 2.3 string generator
├── nvd.py              # NVD API v2 client
├── risk_engine.py      # Scoring engine + risk assessment
├── config.py           # All settings in one place
├── requirements.txt
└── reports/            # Auto-created — output JSON reports
    └── threat_intel_report.json
```

---

## 🔎 Supported Services

| Service | Banner Detection | CPE Generation |
|---|---|---|
| OpenSSH | ✅ version from banner | ✅ |
| Dropbear SSH | ✅ version from banner | ✅ |
| nginx | ✅ from Server header | ✅ |
| Apache HTTP | ✅ from Server header | ✅ |
| Microsoft IIS | ✅ from Server header | ✅ |
| ProFTPD | ✅ version from banner | ✅ |
| vsftpd | ✅ version from banner | ✅ |
| Postfix SMTP | ✅ version from banner | ✅ |
| MySQL / MariaDB | ✅ version from handshake | ✅ |
| PostgreSQL | ✅ | ✅ |
| Redis | ✅ detected via PONG | ✅ |
| MongoDB | ✅ | ✅ |
| VNC | ✅ RFB version | ✅ |
| RDP | port-based fallback | ✅ |
| Telnet | ✅ | ✅ |

---

## ⚙️ Configuration

All settings in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `SCAN_START_PORT` | 1 | First port to scan |
| `SCAN_END_PORT` | 1024 | Last port to scan |
| `SCAN_THREADS` | 100 | Parallel scan threads |
| `BANNER_TIMEOUT` | 3s | Per-banner timeout |
| `NVD_MAX_CVES` | 10 | Max CVEs per service |
| `NVD_RATE_LIMIT_DELAY` | 0.7s | Delay between NVD requests |

---

## 📊 Risk Scoring

| CVE Severity | CVSS Score | Points Added |
|---|---|---|
| CRITICAL | ≥ 9.0 | +25 |
| HIGH | ≥ 7.0 | +15 |
| MEDIUM | ≥ 4.0 | +7 |
| LOW | ≥ 0.1 | +2 |

Critical ports (22, 3389, 3306, 6379, 27017 etc.) receive a **1.5x multiplier**.

| Total Score | Risk Level |
|---|---|
| 0 | CLEAN |
| 1–9 | LOW |
| 10–29 | MEDIUM |
| 30–59 | HIGH |
| 60+ | CRITICAL |

---

## 🔗 SIEM Integration

Output `threat_intel_report.json` is compatible with the
[PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard)
pipeline. The report structure matches the existing sensor output format.

---

## 🛠️ Tech Stack

- **Language:** Python 3.11+
- **Networking:** Python `socket`, `ssl` (standard library)
- **HTTP:** `requests`
- **CVE Data:** NIST NVD API v2
- **Standard:** CPE 2.3 (NIST)

---

## 🔐 Legal & Ethical Notice

This tool is designed for **authorized security assessments only**.
Only scan systems you own or have explicit written permission to test.
Unauthorized port scanning may be illegal in your jurisdiction.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Author

**Mr20x20** — Security Engineering Enthusiast  
GitHub: [github.com/Mr20x20](https://github.com/Mr20x20)

---

## 🔗 Related Projects

- [PyShield Dashboard](https://github.com/Mr20x20/PyShield_Dashboard) — Real-time SIEM dashboard
- [PyShield Honeypot](https://github.com/Mr20x20/pyshield-honeypot) — Attacker profiler
