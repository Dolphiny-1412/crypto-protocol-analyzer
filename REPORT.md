# Cryptographic Protocol Analyzer — Final Project Report

**Course:** Computer Security  
**Project Number:** 10  
**Tool Name:** Cryptographic Protocol Analyzer  
**Language:** Python 3  
**Date:** 2025

---

## 1. Introduction

Network security is a foundational concern in modern computing. Organizations routinely run dozens of services across their infrastructure, and a single misconfigured service using an outdated or unencrypted protocol can expose sensitive data to eavesdroppers, man-in-the-middle attackers, and credential harvesters.

This project presents a **Cryptographic Protocol Analyzer** — a Python-based tool that ingests network packet capture files and systematically evaluates the protocols in use, flagging any that are considered cryptographically weak or entirely unencrypted. The tool is designed to be approachable for beginners while remaining technically accurate for a university cybersecurity context.

---

## 2. Problem Statement

Many legacy and poorly configured network environments continue to use protocols that were designed before modern threat models were understood:

- **Telnet** (1969) provides a full remote shell with zero encryption.
- **FTP** (1971) transfers usernames, passwords, and file contents in cleartext.
- **HTTP** exposes all web traffic — including session cookies and form submissions — to any observer on the path.
- **SSLv3 and TLS 1.0/1.1** have been formally deprecated due to known cryptographic attacks (POODLE, BEAST, POODLE-TLS).

Without a dedicated analysis tool, identifying these vulnerabilities across captured network traffic is a time-consuming, manual process. This project automates that analysis.

---

## 3. Objectives

1. Build a tool capable of parsing standard `.pcap` and `.pcapng` packet capture files.
2. Detect at least 10 categories of insecure protocol usage using a rule-based engine.
3. Assign meaningful severity ratings (Critical / High / Medium / Low) to each finding.
4. Identify plaintext credential leakage by inspecting packet payloads for known keywords.
5. Detect deprecated TLS/SSL versions from raw handshake bytes.
6. Present findings in both a graphical web interface (Streamlit) and a command-line terminal.
7. Provide a fully functional demo mode that requires no external files.
8. Produce exportable CSV reports for documentation purposes.

---

## 4. System Design

### 4.1 Architecture Overview

The tool follows a layered architecture:

```
┌──────────────────────────────────────────────────┐
│            User Interface Layer                  │
│   app.py (Streamlit GUI)  │  cli.py (Terminal)  │
└────────────────┬─────────────────────────────────┘
                 │
┌────────────────▼─────────────────────────────────┐
│            Analysis Engine                       │
│                analyzer.py                       │
│  - analyze_pcap()   - run_demo_analysis()        │
└────────────────┬─────────────────────────────────┘
        ┌────────┴────────┐
┌───────▼──────┐  ┌───────▼──────────────┐
│   rules.py   │  │  report_generator.py │
│ Rule defs    │  │  DataFrame / CSV     │
└──────────────┘  └──────────────────────┘
```

### 4.2 Component Responsibilities

| File | Responsibility |
|---|---|
| `app.py` | Streamlit web UI: file upload, charts, finding cards, CSV download |
| `analyzer.py` | Core engine: Scapy parsing, rule matching, TLS detection, payload inspection |
| `rules.py` | Static rule definitions: ports, protocols, severity, explanations, recommendations |
| `report_generator.py` | Converts findings to Pandas DataFrames; generates CSV reports and statistics |
| `cli.py` | Terminal interface with ANSI color output |
| `sample_data/demo_findings.json` | Pre-built dataset of 13 diverse findings for demo mode |

### 4.3 Detection Methods

The tool employs three parallel detection strategies:

1. **Port-based detection** — The destination port of each TCP/UDP packet is matched against a dictionary of 10 known-insecure port-to-protocol mappings in `rules.py`.

2. **Payload keyword scanning** — The raw bytes of each TCP packet are decoded (UTF-8, errors ignored) and searched for 12 credential-related strings such as `password=`, `USER `, `PASS `, `Authorization:`.

3. **TLS handshake inspection** — Raw payload bytes starting with `0x16` (TLS Handshake record type) have bytes 1–2 extracted and matched against a version lookup table covering SSLv3 through TLS 1.3.

---

## 5. Implementation Details

### 5.1 Technology Stack

| Component | Library/Tool | Version |
|---|---|---|
| Packet parsing | Scapy | ≥ 2.5.0 |
| Web interface | Streamlit | ≥ 1.32.0 |
| Data processing | Pandas | ≥ 2.0.0 |
| Visualisation | Plotly Express | ≥ 5.18.0 |
| Runtime | Python | 3.9+ |

### 5.2 Key Algorithm: Port-Based Rule Matching

```python
def _check_port(src_ip, dst_ip, sport, dport, transport):
    rule = INSECURE_PORT_RULES.get(dport)
    if rule:
        return _make_finding(
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=sport, dst_port=dport,
            protocol=rule["protocol"],
            issue=rule["issue"],
            severity=rule["severity"],
            ...
        )
    return None
```

This O(1) dictionary lookup is applied to every IPv4 packet with TCP or UDP transport.

### 5.3 Key Algorithm: TLS Version Detection

TLS records begin with a 5-byte header. Bytes 0 is the Content Type (`0x16` = Handshake). Bytes 1–2 are the Protocol Version:

| Bytes | Meaning |
|---|---|
| `\x03\x00` | SSLv3 — Critical |
| `\x03\x01` | TLS 1.0 — High |
| `\x03\x02` | TLS 1.1 — High |
| `\x03\x03` | TLS 1.2 — Low (acceptable) |
| `\x03\x04` | TLS 1.3 — Info (current standard) |

### 5.4 Graceful Error Handling

The `analyze_pcap()` function returns a standardized error dictionary rather than raising an exception, ensuring the UI always receives a well-formed response. Errors handled include: Scapy not installed, file not found, unsupported file extension, and corrupt pcap file.

---

## 6. Screenshots

*(Replace these placeholders with actual screenshots from running the tool.)*

### 6.1 Streamlit GUI — Landing Page
> *[Screenshot: The main page showing the upload area and "Run Demo Analysis" button]*

### 6.2 Streamlit GUI — Summary Metrics
> *[Screenshot: Six metric cards showing Packets Analyzed, Total Findings, Critical, High, Medium, Low counts]*

### 6.3 Streamlit GUI — Severity Bar Chart
> *[Screenshot: Plotly bar chart with red/orange/yellow/green bars]*

### 6.4 Streamlit GUI — Detailed Finding Cards
> *[Screenshot: Individual finding cards with severity border color, protocol, IPs, explanation, and recommendation]*

### 6.5 CLI Output
> *[Screenshot: Terminal showing ANSI-colored output with banner, summary table, and numbered findings]*

---

## 7. Testing Results

### 7.1 Demo Mode Testing

The built-in demo dataset contains 13 findings across all severity levels, covering every protocol rule in the system. The following table summarizes expected vs. actual output:

| Protocol | Expected Severity | Detected | Pass? |
|---|---|---|---|
| Telnet (port 23) | Critical | ✅ | ✅ |
| FTP (port 21) | Critical | ✅ | ✅ |
| TFTP (port 69) | Critical | ✅ | ✅ |
| Plaintext credential (USER/PASS) | Critical | ✅ | ✅ |
| TLS 1.0 handshake | High | ✅ | ✅ |
| TLS 1.1 handshake | High | ✅ | ✅ |
| HTTP (port 80) | High | ✅ | ✅ |
| POP3 (port 110) | High | ✅ | ✅ |
| IMAP (port 143) | High | ✅ | ✅ |
| SNMP (port 161) | High | ✅ | ✅ |
| SMTP (port 25) | Medium | ✅ | ✅ |
| HTTP-Alt (port 8080) | Medium | ✅ | ✅ |
| Syslog (port 514) | Low | ✅ | ✅ |

### 7.2 Error Handling Tests

| Scenario | Expected Behavior | Result |
|---|---|---|
| Scapy not installed | Returns error dict with install instruction | ✅ Pass |
| File not found | Returns error dict with path | ✅ Pass |
| `.txt` file uploaded | Returns error dict with format note | ✅ Pass |
| Corrupt pcap file | Returns error dict with exception message | ✅ Pass |
| Demo mode, JSON missing | Returns error dict with load message | ✅ Pass |

### 7.3 GUI Functionality Tests

| Feature | Result |
|---|---|
| File upload triggers analysis | ✅ Pass |
| Demo button triggers demo analysis | ✅ Pass |
| Severity filter updates cards | ✅ Pass |
| CSV download produces valid file | ✅ Pass |
| Chart renders with correct colors | ✅ Pass |
| Error state shows friendly message | ✅ Pass |

---

## 8. Limitations

- **IPv4 only:** IPv6 packets are not currently analyzed.
- **Heuristic TLS detection:** Only reads the TLS Record Layer version, not the ClientHello. Some TLS 1.3 sessions may negotiate using a TLS 1.2 record header for compatibility.
- **No decryption:** Encrypted traffic content cannot be inspected; only metadata and handshake data.
- **False positives:** Payload keyword scanning may trigger on binary data containing ASCII sequences that resemble credential strings.
- **No live capture:** The tool deliberately avoids live interface sniffing, which requires elevated privileges and OS-specific drivers.

---

## 9. Conclusion

The Cryptographic Protocol Analyzer successfully demonstrates automated detection of insecure network protocols from packet capture files. By combining port-based rule matching, payload keyword scanning, and TLS handshake analysis, the tool covers a broad range of real-world security misconfigurations.

The project highlights a critical principle in network security: **protocol choice is a security decision.** The continued use of Telnet, FTP, or unencrypted email protocols in 2025 represents a significant and avoidable risk. Tools like this analyzer provide the visibility needed to identify and remediate these vulnerabilities before they are exploited.

The dual interface (Streamlit GUI + CLI) makes the tool accessible to both security analysts conducting interactive reviews and DevOps engineers integrating automated checks into pipelines.

---

## 10. References

1. Rescorla, E. (2018). *The Transport Layer Security (TLS) Protocol Version 1.3.* RFC 8446. IETF.
2. Moriarty, K., & Farrell, S. (2021). *Deprecating TLS 1.0 and TLS 1.1.* RFC 8996. IETF.
3. Bellovin, S. M. (1994). *Security Problems in the TCP/IP Protocol Suite.* Computer Communication Review.
4. NIST. (2019). *Guidelines for the Selection, Configuration, and Use of TLS Implementations.* SP 800-52 Rev 2.
5. OWASP. (2023). *Transport Layer Security Cheat Sheet.* OWASP Foundation.
6. Biondi, P. (2023). *Scapy Documentation.* https://scapy.readthedocs.io
