"""Offline tests for the CVE report formatter.

These tests do not touch the network. They feed the formatter records that
match the shapes the CIRCL API has served over time.
"""

from app.core.langgraph.tools.cve_lookup import format_cve

CVE50_SAMPLE = {
    "cveMetadata": {
        "cveId": "CVE-2024-3400",
        "state": "PUBLISHED",
        "datePublished": "2024-04-12T17:15:00Z",
        "dateUpdated": "2024-08-02T00:00:00Z",
    },
    "containers": {
        "cna": {
            "descriptions": [
                {"lang": "en", "value": "A command injection vulnerability in the GlobalProtect feature of PAN-OS."}
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 10,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }
            ],
            "problemTypes": [
                {"descriptions": [{"cweId": "CWE-77", "lang": "en", "type": "CWE"}]}
            ],
            "affected": [
                {"vendor": "Palo Alto Networks", "product": "PAN-OS"},
                {"vendor": "Palo Alto Networks", "product": "PAN-OS"},
            ],
            "references": [
                {"url": "https://security.paloaltonetworks.com/CVE-2024-3400"},
            ],
        }
    },
}


def test_format_cve50_includes_key_fields():
    report = format_cve(CVE50_SAMPLE)
    assert "CVE-2024-3400" in report
    assert "CVSS v3.1: 10" in report
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in report
    assert "CWE-77" in report
    assert "Palo Alto Networks PAN-OS" in report
    assert "security.paloaltonetworks.com" in report
    assert "command injection" in report


def test_format_cve50_dedupes_products():
    report = format_cve(CVE50_SAMPLE)
    assert report.count("Palo Alto Networks PAN-OS") == 1


def test_format_legacy_records_still_work():
    legacy = {
        "id": "CVE-2021-44228",
        "cvss3": 9.8,
        "cvss3-vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe": "CWE-502",
        "summary": "Apache Log4j2 remote code execution.",
        "vulnerable_product": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
        "references": ["https://logging.apache.org/log4j/2.x/security.html"],
    }
    report = format_cve(legacy)
    assert "CVE-2021-44228" in report
    assert "CVSS v3: 9.8" in report
    assert "CWE-502" in report
    assert "Log4j2" in report


def test_format_cve_empty_input():
    assert "No vulnerability data" in format_cve({})
