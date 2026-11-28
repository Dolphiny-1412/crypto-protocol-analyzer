from rules import CREDENTIAL_KEYWORDS, INSECURE_PORT_RULES, SEVERITY_ORDER, TLS_VERSION_MAP

REQUIRED = {"protocol", "issue", "severity", "explanation", "recommendation"}


def test_every_port_rule_is_complete():
    for port, rule in INSECURE_PORT_RULES.items():
        assert REQUIRED <= set(rule), f"port {port} is missing fields"
        assert rule["severity"] in SEVERITY_ORDER


def test_known_cleartext_ports_are_covered():
    for port in (21, 23, 25, 80, 110, 143):
        assert port in INSECURE_PORT_RULES


def test_telnet_and_ftp_are_critical():
    assert INSECURE_PORT_RULES[23]["severity"] == "Critical"
    assert INSECURE_PORT_RULES[21]["severity"] == "Critical"


def test_tls_map_flags_old_versions_only():
    assert TLS_VERSION_MAP[b"\x03\x00"][1] == "Critical"
    assert TLS_VERSION_MAP[b"\x03\x01"][1] == "High"
    assert TLS_VERSION_MAP[b"\x03\x02"][1] == "High"
    assert TLS_VERSION_MAP[b"\x03\x04"][1] == "Info"


def test_severity_order_is_strict():
    assert SEVERITY_ORDER["Critical"] < SEVERITY_ORDER["High"] < SEVERITY_ORDER["Medium"] < SEVERITY_ORDER["Low"]


def test_credential_keywords_are_nonempty_strings():
    assert CREDENTIAL_KEYWORDS and all(isinstance(k, str) and k for k in CREDENTIAL_KEYWORDS)
