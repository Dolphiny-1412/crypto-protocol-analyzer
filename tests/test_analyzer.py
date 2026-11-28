import pytest

import analyzer


def test_port_rule_hit_and_miss():
    hit = analyzer._check_port("10.0.0.1", "10.0.0.2", 50000, 23, "TCP")
    assert hit["protocol"] == "Telnet" and hit["severity"] == "Critical"
    assert analyzer._check_port("10.0.0.1", "10.0.0.2", 50000, 443, "TCP") is None


def test_payload_credential_detection_is_case_insensitive():
    f = analyzer._check_payload("a", "b", 1, 80, b"POST /login HTTP/1.1\r\n\r\nUserName=bob&Password=hunter2")
    assert f is not None and f["severity"] == "Critical"


def test_payload_without_keywords_is_clean():
    assert analyzer._check_payload("a", "b", 1, 80, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n") is None


@pytest.mark.parametrize(
    "version,expected",
    [(b"\x03\x00", "SSLv3"), (b"\x03\x01", "TLS 1.0"), (b"\x03\x02", "TLS 1.1")],
)
def test_old_tls_versions_are_flagged(version, expected):
    record = b"\x16" + version + b"\x00\x2f" + b"\x01" * 10
    f = analyzer._check_tls_version("a", "b", 1, 443, record)
    assert f is not None and f["protocol"] == expected


def test_modern_tls_and_non_handshake_are_not_flagged():
    assert analyzer._check_tls_version("a", "b", 1, 443, b"\x16\x03\x04\x00\x2f" + b"\x01" * 10) is None
    assert analyzer._check_tls_version("a", "b", 1, 443, b"\x17\x03\x01\x00\x2f" + b"\x01" * 10) is None
    assert analyzer._check_tls_version("a", "b", 1, 443, b"\x16\x03") is None


def test_demo_analysis_loads_and_is_sorted():
    r = analyzer.run_demo_analysis()
    assert r["error"] is None and r["source"] == "demo" and r["findings"]
    order = [analyzer.SEVERITY_ORDER[f["severity"]] for f in r["findings"]]
    assert order == sorted(order)


def test_missing_and_wrong_extension_files_return_errors(tmp_path):
    assert analyzer.analyze_pcap(str(tmp_path / "nope.pcap"))["error"]
    txt = tmp_path / "x.txt"
    txt.write_text("hi")
    assert "Unsupported" in analyzer.analyze_pcap(str(txt))["error"]


@pytest.mark.skipif(not analyzer.SCAPY_AVAILABLE, reason="scapy not installed")
def test_end_to_end_on_a_generated_pcap(tmp_path):
    from scapy.all import IP, TCP, UDP, Raw, wrpcap

    pkts = [
        IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000, dport=21) / Raw(load=b"USER admin\r\n"),
        IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40001, dport=443) / Raw(load=b"\x16\x03\x01\x00\x2f" + b"\x00" * 10),
        IP(src="10.0.0.5", dst="10.0.0.9") / UDP(sport=40002, dport=69) / Raw(load=b"x"),
        IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40003, dport=443) / Raw(load=b"\x16\x03\x04\x00\x2f" + b"\x00" * 10),
    ]
    path = tmp_path / "t.pcap"
    wrpcap(str(path), pkts)
    r = analyzer.analyze_pcap(str(path))
    assert r["error"] is None and r["total_packets"] == 4
    protos = [f["protocol"] for f in r["findings"]]
    assert "FTP" in protos and "TFTP" in protos and "TLS 1.0" in protos and "Plaintext Credential" in protos
    assert "TLS 1.3" not in protos
