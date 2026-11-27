# 🔐 Cryptographic Protocol Analyzer

> **Computer Security Course Project — Project 10**  
> A network traffic analysis tool that detects insecure cryptographic protocols and flags vulnerable configurations.
>
> Scope: a course-level, rule-based detector. It matches destination ports and scans payload bytes for known patterns — no TLS decryption, no machine learning.

---

## 📌 Objective

Analyze packet capture (`.pcap` / `.pcapng`) files to identify insecure or deprecated network protocols, weak TLS/SSL versions, and plaintext credential exposure — producing a structured, severity-rated security report.

---

## ✨ Features

| Feature | Details |
|---|---|
| **Pcap Analysis** | Parse `.pcap` and `.pcapng` files using Scapy |
| **Protocol Detection** | HTTP, FTP, Telnet, POP3, IMAP, SMTP, TFTP, SNMP, Syslog |
| **TLS Inspection** | Detect SSLv3, TLS 1.0, TLS 1.1 in handshake bytes |
| **Credential Sniffing** | Flag payloads containing `USER`, `PASS`, `password=`, etc. |
| **Severity Ratings** | Critical / High / Medium / Low per finding |
| **Streamlit GUI** | Upload file, view charts, filter findings, download CSV |
| **CLI Mode** | Terminal output with ANSI colors |
| **Demo Mode** | Works without any pcap file using built-in sample data |
| **CSV Export** | Full report download from both GUI and CLI |
| **Graceful Errors** | Friendly messages instead of crashes |

---

## 🗂 Project Structure

```
crypto_protocol_analyzer/
├── app.py               ← Streamlit web GUI
├── analyzer.py          ← Core packet analysis engine
├── cli.py               ← Command-line interface
├── rules.py             ← Insecure protocol rule definitions
├── report_generator.py  ← DataFrame, CSV, and summary logic
├── requirements.txt     ← Python dependencies
├── README.md            ← This file
├── sample_data/
│   └── demo_findings.json   ← Built-in demo dataset
└── reports/
    └── .gitkeep         ← Auto-saved CSV reports land here
```

---

## ⚙️ How It Works

1. **Input**: User uploads a `.pcap` file (GUI) or passes `--file` (CLI).
2. **Parsing**: Scapy reads each packet and extracts IP, TCP/UDP layers.
3. **Rule matching**: Each packet's destination port is checked against `rules.py`.
4. **Payload inspection**: Raw bytes are scanned for credential keywords.
5. **TLS detection**: The first bytes of TLS records are checked for deprecated version numbers.
6. **Report**: Findings are assembled, sorted by severity, and rendered as cards / table / CSV.

---

## 🚀 Installation

### Prerequisites
- Python 3.9 or newer
- Windows, macOS, or Linux

### Step-by-step

```bash
# 1. Clone or download this project folder
cd crypto_protocol_analyzer

# 2. (Recommended) Create a virtual environment
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS / Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Windows note:** Scapy on Windows may require Npcap or WinPcap to analyze live traffic.
> For analyzing pcap *files* only (which is all this tool does), no additional driver is needed.

---

## 🖥 Running the GUI

```bash
streamlit run app.py
```

The browser will open automatically at `http://localhost:8501`.

- Click **▶ Run Demo Analysis** to explore with built-in data.
- Or drag and drop a `.pcap` file to analyze real traffic.

---

## 💻 Running the CLI

```bash
# Analyze a pcap file
python cli.py --file path/to/capture.pcap

# Run the demo with built-in data
python cli.py --demo

# Analyze without saving a CSV report
python cli.py --demo --no-save
```

---

## 📊 Sample Expected Output

### CLI Summary

```
╔══════════════════════════════════════════════════════════╗
║      Cryptographic Protocol Analyzer  v1.0               ║
║      Computer Security Course Project                    ║
╚══════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────
  ANALYSIS SUMMARY
────────────────────────────────────────────────────────────
  Analyzed at    : 2025-01-15 14:32:01
  Source         : DEMO
  Total Packets  : 847
  Total Findings : 13

  Critical : 4
  High     : 6
  Medium   : 2
  Low      : 1
────────────────────────────────────────────────────────────
```

### Findings Table

| Severity | Protocol | Source IP | Destination IP | Dst Port | Issue |
|---|---|---|---|---|---|
| Critical | Telnet | 192.168.1.105 | 203.0.113.10 | 23 | Telnet session detected — full plaintext remote shell |
| Critical | FTP | 10.0.0.22 | 198.51.100.5 | 21 | Unencrypted FTP connection detected |
| Critical | Plaintext Credential | 10.0.0.22 | 198.51.100.5 | 21 | Sensitive keyword 'USER' found in plaintext payload |
| Critical | TFTP | 172.16.0.50 | 203.0.113.99 | 69 | TFTP detected — no authentication or encryption |
| High | TLS 1.0 | 192.168.1.105 | 203.0.113.10 | 443 | Deprecated TLS/SSL version detected: TLS 1.0 |
| High | HTTP | 10.0.0.33 | 198.51.100.20 | 80 | Unencrypted HTTP traffic detected |
| High | POP3 | 10.0.0.44 | 198.51.100.30 | 110 | Unencrypted POP3 email retrieval detected |
| High | IMAP | 10.0.0.55 | 198.51.100.40 | 143 | Unencrypted IMAP connection detected |
| High | SNMP | 10.0.0.66 | 198.51.100.50 | 161 | SNMP v1/v2c — community strings in cleartext |
| Medium | SMTP | 172.16.0.80 | 203.0.113.60 | 25 | Unencrypted SMTP traffic detected |
| Medium | HTTP-Alt | 10.0.0.77 | 198.51.100.70 | 8080 | HTTP on alternate port 8080 |
| Low | Syslog | 10.0.0.88 | 198.51.100.80 | 514 | Unencrypted Syslog (UDP 514) detected |

---

## ⚠️ Limitations

- Only analyzes **IPv4** TCP/UDP traffic; IPv6 and other protocols are skipped.
- TLS version detection is **heuristic-based** (inspects first bytes of raw payload).
- Cannot decrypt TLS traffic — only identifies handshake version numbers.
- Payload credential scanning may produce **false positives** on binary data.
- Large pcap files (>500 MB) may take significant time to parse.
- No live packet capture — only offline pcap file analysis.

---

## 🔮 Future Improvements

- IPv6 support
- Deep TLS inspection with cipher suite enumeration
- DNS query analysis for suspicious domain lookups
- JSON report export in addition to CSV
- Geolocation of IP addresses
- Real-time packet sniffing mode (admin/root only)
- Integration with CVE database for protocol-specific vulnerabilities
- Web dashboard with persistent history

---

## ⚖️ Ethical & Legal Notice

> **This tool is designed exclusively for authorized network analysis and educational use.**
>
> Capturing or analyzing network traffic without explicit permission from the network owner may violate computer fraud laws, wiretapping laws, and organizational policies. Always obtain proper written authorization before analyzing any network traffic. The authors accept no liability for misuse of this tool.

---

## 📚 References

- RFC 8996 — Deprecating TLS 1.0 and TLS 1.1
- NIST SP 800-52 Rev 2 — TLS Implementation Guidelines
- OWASP Transport Layer Security Cheat Sheet
- Scapy Documentation: https://scapy.net
- Streamlit Documentation: https://docs.streamlit.io
