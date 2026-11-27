# rules.py
# Defines detection rules for insecure cryptographic and network protocols.
# Each rule maps a known-vulnerable port/protocol to a severity rating,
# a human-readable explanation, and a recommended remediation step.

INSECURE_PORT_RULES = {
    80: {
        "protocol": "HTTP",
        "issue": "Unencrypted HTTP traffic detected",
        "severity": "High",
        "explanation": (
            "HTTP transmits data in plaintext, including cookies, form data, and credentials. "
            "Any network observer (ISP, attacker on LAN, proxy) can intercept and read or modify this traffic."
        ),
        "recommendation": "Migrate to HTTPS (TLS 1.2 or TLS 1.3). Implement HSTS headers.",
    },
    21: {
        "protocol": "FTP",
        "issue": "Unencrypted FTP connection detected",
        "severity": "Critical",
        "explanation": (
            "FTP sends credentials (USER/PASS commands) and file content in cleartext. "
            "Credentials are trivially sniffable on the same network segment."
        ),
        "recommendation": "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS).",
    },
    23: {
        "protocol": "Telnet",
        "issue": "Telnet session detected — full plaintext remote shell",
        "severity": "Critical",
        "explanation": (
            "Telnet provides no encryption whatsoever. Every keystroke, including passwords and commands, "
            "is transmitted in cleartext. This is considered completely insecure for any production use."
        ),
        "recommendation": "Replace Telnet with SSH (port 22) immediately. Disable Telnet service on all devices.",
    },
    110: {
        "protocol": "POP3",
        "issue": "Unencrypted POP3 email retrieval detected",
        "severity": "High",
        "explanation": (
            "POP3 on port 110 transmits email credentials and message content in cleartext. "
            "Attackers on the same network can harvest login credentials and read private email."
        ),
        "recommendation": "Use POP3S (port 995) with TLS, or migrate to IMAP over TLS (port 993).",
    },
    143: {
        "protocol": "IMAP",
        "issue": "Unencrypted IMAP connection detected",
        "severity": "High",
        "explanation": (
            "IMAP on port 143 without STARTTLS exposes email credentials and message content in plaintext. "
            "This allows credential theft and email eavesdropping."
        ),
        "recommendation": "Enforce STARTTLS on port 143, or use IMAPS on port 993.",
    },
    25: {
        "protocol": "SMTP",
        "issue": "Unencrypted SMTP traffic detected",
        "severity": "Medium",
        "explanation": (
            "SMTP on port 25 without STARTTLS transmits email in plaintext. "
            "While server-to-server SMTP is sometimes plaintext by design, it is best practice to enforce TLS."
        ),
        "recommendation": "Configure SMTP with STARTTLS (port 587) or SMTPS (port 465) for submission.",
    },
    8080: {
        "protocol": "HTTP-Alt",
        "issue": "Unencrypted HTTP traffic on alternate port 8080",
        "severity": "Medium",
        "explanation": (
            "Port 8080 is commonly used as an HTTP proxy or alternate web server port. "
            "Traffic on this port is typically unencrypted."
        ),
        "recommendation": "Use HTTPS on port 443 or 8443 instead.",
    },
    69: {
        "protocol": "TFTP",
        "issue": "Trivial FTP (TFTP) detected — no authentication or encryption",
        "severity": "Critical",
        "explanation": (
            "TFTP provides no authentication and no encryption. It is commonly used to serve "
            "firmware/config files on networks, making it a high-value attack target."
        ),
        "recommendation": "Use SFTP or SCP for secure file transfer. Restrict TFTP to isolated management VLANs.",
    },
    161: {
        "protocol": "SNMP",
        "issue": "SNMP v1/v2c likely — community strings in cleartext",
        "severity": "High",
        "explanation": (
            "SNMP versions 1 and 2c use cleartext community strings as authentication. "
            "These strings can be intercepted and used to query or even configure network devices."
        ),
        "recommendation": "Upgrade to SNMPv3 with authentication and encryption (authPriv mode).",
    },
    514: {
        "protocol": "Syslog",
        "issue": "Unencrypted Syslog (UDP 514) detected",
        "severity": "Low",
        "explanation": (
            "Traditional syslog over UDP port 514 transmits log data in cleartext with no integrity protection. "
            "Logs can be intercepted or spoofed."
        ),
        "recommendation": "Use Syslog over TLS (RFC 5425) on TCP port 6514.",
    },
}

# Keywords in packet payloads that suggest credential or sensitive data exposure
CREDENTIAL_KEYWORDS = [
    "username=",
    "password=",
    "passwd=",
    "pass=",
    "login=",
    "USER ",
    "PASS ",
    "Authorization:",
    "credentials",
    "secret=",
    "token=",
    "api_key=",
]

# TLS/SSL version identifiers found in TLS ClientHello/ServerHello handshake bytes
TLS_VERSION_MAP = {
    b"\x03\x00": ("SSLv3",   "Critical",
                  "SSLv3 is broken (POODLE attack). No modern client should use it.",
                  "Disable SSLv3 entirely. Use TLS 1.2 or TLS 1.3."),
    b"\x03\x01": ("TLS 1.0", "High",
                  "TLS 1.0 is deprecated (RFC 8996). Vulnerable to BEAST and POODLE-TLS attacks.",
                  "Upgrade to TLS 1.2 minimum. Prefer TLS 1.3."),
    b"\x03\x02": ("TLS 1.1", "High",
                  "TLS 1.1 is deprecated (RFC 8996). No longer considered secure.",
                  "Upgrade to TLS 1.2 minimum. Prefer TLS 1.3."),
    b"\x03\x03": ("TLS 1.2", "Low",
                  "TLS 1.2 is acceptable but aging. Some cipher suites may be weak.",
                  "Consider upgrading to TLS 1.3 where possible."),
    b"\x03\x04": ("TLS 1.3", "Info",
                  "TLS 1.3 is the current recommended standard.",
                  "No action required."),
}

# Severity ordering for sorting/display
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_COLORS = {
    "Critical": "#FF3B30",
    "High":     "#FF9500",
    "Medium":   "#FFCC00",
    "Low":      "#34C759",
    "Info":     "#007AFF",
}
