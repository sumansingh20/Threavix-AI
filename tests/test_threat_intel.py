"""Offline unit tests for Threavix IOC extraction and refanging utilities."""

from app.utils.threat_intel import (
    extract_iocs,
    is_private_ip,
    refang,
    summarise_iocs,
)

_KNOWN_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_KNOWN_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def test_refang_url_and_domain():
    assert refang("hxxp://evil[.]com/path") == "http://evil.com/path"
    assert refang("hxxps://evil(.)com") == "https://evil.com"


def test_refang_email():
    assert refang("analyst[at]evil[.]com") == "analyst@evil.com"
    assert refang("analyst(at)evil(dot)com") == "analyst@evil.com"


def test_extract_defanged_indicators():
    text = (
        "Callback to hxxp://malicious[.]example/path from 203.0.113.9, "
        f"payload MD5 {_KNOWN_MD5}, referenced CVE-2021-44228."
    )
    iocs = extract_iocs(text)

    assert "http://malicious.example/path" in iocs["urls"]
    assert "203.0.113.9" in iocs["ipv4"]
    assert "malicious.example" in iocs["domains"]
    assert _KNOWN_MD5 in iocs["md5"]
    assert "CVE-2021-44228" in iocs["cves"]


def test_sha256_not_split_into_md5_or_sha1():
    iocs = extract_iocs(_KNOWN_SHA256)
    assert _KNOWN_SHA256 in iocs["sha256"]
    assert iocs["md5"] == []
    assert iocs["sha1"] == []


def test_duplicate_indicators_are_deduplicated():
    iocs = extract_iocs("8.8.8.8 8.8.8.8 8.8.8.8")
    assert iocs["ipv4"] == ["8.8.8.8"]


def test_invalid_ipv4_is_rejected():
    iocs = extract_iocs("999.999.999.999")
    assert iocs["ipv4"] == []


def test_private_ip_detection():
    assert is_private_ip("10.0.0.1")
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("192.168.1.10")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("not-an-ip")


def test_summarise_iocs():
    summary = summarise_iocs(extract_iocs("8.8.8.8 evil.example"))
    assert "ipv4" in summary
    assert "domains" in summary


def test_summarise_empty():
    assert summarise_iocs(extract_iocs("no indicators here")) == "  - none detected"
