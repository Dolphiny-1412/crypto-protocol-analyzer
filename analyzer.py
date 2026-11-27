# analyzer.py
# Core packet analysis engine for the Cryptographic Protocol Analyzer.
# Uses Scapy to parse .pcap / .pcapng files and applies rules from rules.py
# to detect insecure protocols, weak TLS versions, and plaintext credentials.

import os
import json
import datetime

# --- Scapy import with graceful fallback ---
try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from rules import (
    INSECURE_PORT_RULES,
    CREDENTIAL_KEYWORDS,
    TLS_VERSION_MAP,
    SEVERITY_ORDER,
)

# Path to the bundled demo dataset
DEMO_DATA_PATH = os.path.join(os.path.dirname(__file__), "sample_data", "demo_findings.json")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_pcap(file_path: str) -> dict:
    """
    Parse a .pcap or .pcapng file and return a result dictionary.

    Returns:
        {
            "findings": [list of finding dicts],
            "total_packets": int,
            "error": str or None,
            "source": "pcap"
        }
    """
    if not SCAPY_AVAILABLE:
        return _error_result(
            "Scapy is not installed. Run: pip install scapy\n"
            "You can still use Demo Mode to explore the tool."
        )

    if not os.path.isfile(file_path):
        return _error_result(f"File not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in (".pcap", ".pcapng"):
        return _error_result(
            f"Unsupported file type '{ext}'. Please upload a .pcap or .pcapng file."
        )

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        return _error_result(
            f"Could not read pcap file: {exc}\n"
            "The file may be corrupt or in an unsupported format. Try Demo Mode instead."
        )

    findings = []
    total_packets = len(packets)

    for pkt in packets:
        # Only inspect IPv4 packets with TCP or UDP transport
        if not pkt.haslayer(IP):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # ---- TCP analysis ----
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport

            # Check destination port against insecure rules
            finding = _check_port(src_ip, dst_ip, sport, dport, "TCP")
            if finding:
                findings.append(finding)

            # Inspect raw payload for credential keywords
            if pkt.haslayer(Raw):
                payload_finding = _check_payload(
                    src_ip, dst_ip, sport, dport, pkt[Raw].load
                )
                if payload_finding:
                    findings.append(payload_finding)

            # Try to detect TLS version from the raw bytes of TLS handshake
            if pkt.haslayer(Raw):
                tls_finding = _check_tls_version(
                    src_ip, dst_ip, sport, dport, pkt[Raw].load
                )
                if tls_finding:
                    findings.append(tls_finding)

        # ---- UDP analysis ----
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            finding = _check_port(src_ip, dst_ip, sport, dport, "UDP")
            if finding:
                findings.append(finding)

    # Sort findings by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

    return {
        "findings": findings,
        "total_packets": total_packets,
        "error": None,
        "source": "pcap",
        "analyzed_at": _timestamp(),
    }


def run_demo_analysis() -> dict:
    """
    Return a pre-built demo result set from the bundled JSON file.
    This allows the tool to be fully demonstrated without a real pcap file.
    """
    try:
        with open(DEMO_DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        findings = data.get("findings", [])
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
        return {
            "findings": findings,
            "total_packets": data.get("total_packets", len(findings) * 12),
            "error": None,
            "source": "demo",
            "analyzed_at": _timestamp(),
        }
    except Exception as exc:
        return _error_result(f"Could not load demo data: {exc}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_port(src_ip, dst_ip, sport, dport, transport) -> dict | None:
    """Return a finding dict if dport matches an insecure rule, else None."""
    rule = INSECURE_PORT_RULES.get(dport)
    if rule:
        return _make_finding(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=rule["protocol"],
            transport=transport,
            issue=rule["issue"],
            severity=rule["severity"],
            explanation=rule["explanation"],
            recommendation=rule["recommendation"],
        )
    return None


def _check_payload(src_ip, dst_ip, sport, dport, raw_bytes) -> dict | None:
    """
    Scan raw packet bytes for credential-related keywords.
    This detects plaintext credential leakage on any port.
    """
    try:
        payload_str = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None

    for keyword in CREDENTIAL_KEYWORDS:
        if keyword.lower() in payload_str.lower():
            return _make_finding(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                protocol="Plaintext Credential",
                transport="TCP",
                issue=f"Sensitive keyword '{keyword.strip()}' found in plaintext payload",
                severity="Critical",
                explanation=(
                    f"The payload contains the string '{keyword.strip()}', suggesting "
                    "that credentials or sensitive authentication data are being transmitted "
                    "in plaintext. This data is fully readable by any network eavesdropper."
                ),
                recommendation=(
                    "Ensure all authentication occurs over an encrypted channel (HTTPS, SFTP, SSH). "
                    "Never transmit credentials in cleartext."
                ),
            )
    return None


def _check_tls_version(src_ip, dst_ip, sport, dport, raw_bytes) -> dict | None:
    """
    Detect TLS/SSL version from raw packet bytes by inspecting the TLS record header.

    TLS record structure (first 5 bytes):
      Byte 0:   Content type (0x16 = Handshake)
      Bytes 1-2: Protocol version (e.g., 0x03 0x01 = TLS 1.0)
      Bytes 3-4: Length

    This is a best-effort heuristic and will not catch all TLS traffic.
    """
    if len(raw_bytes) < 5:
        return None

    # Check for TLS Handshake record type (0x16)
    if raw_bytes[0] != 0x16:
        return None

    version_bytes = raw_bytes[1:3]
    match = TLS_VERSION_MAP.get(version_bytes)
    if not match:
        return None

    version_name, severity, explanation, recommendation = match

    # Only flag versions that are actually insecure (not TLS 1.3)
    if severity == "Info":
        return None

    return _make_finding(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=sport,
        dst_port=dport,
        protocol=version_name,
        transport="TCP",
        issue=f"Deprecated TLS/SSL version detected: {version_name}",
        severity=severity,
        explanation=explanation,
        recommendation=recommendation,
    )


def _make_finding(**kwargs) -> dict:
    """Build a standardized finding dictionary."""
    return {
        "src_ip":         kwargs.get("src_ip", "N/A"),
        "dst_ip":         kwargs.get("dst_ip", "N/A"),
        "src_port":       kwargs.get("src_port", 0),
        "dst_port":       kwargs.get("dst_port", 0),
        "protocol":       kwargs.get("protocol", "Unknown"),
        "transport":      kwargs.get("transport", "TCP"),
        "issue":          kwargs.get("issue", ""),
        "severity":       kwargs.get("severity", "Low"),
        "explanation":    kwargs.get("explanation", ""),
        "recommendation": kwargs.get("recommendation", ""),
    }


def _error_result(message: str) -> dict:
    """Return a result dict representing an analysis error."""
    return {
        "findings": [],
        "total_packets": 0,
        "error": message,
        "source": "error",
        "analyzed_at": _timestamp(),
    }


def _timestamp() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
