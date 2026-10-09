"""Indicator of Compromise (IOC) extraction tool.

This tool extracts and defangs/refangs network and file indicators from raw
text such as SIEM alerts, phishing emails, paste dumps or analyst notes. It is
fully offline and therefore always available, even without internet access or
API keys.
"""

from langchain_core.tools import tool

from app.utils.threat_intel import extract_iocs


@tool
def ioc_extractor(text: str) -> str:
    """Extract Indicators of Compromise (IOCs) from a block of text.

    Detects and normalises IPv4 addresses, domains, URLs, MD5/SHA1/SHA256
    hashes, email addresses and CVE identifiers. Defanged indicators such as
    ``evil[.]com`` or ``hxxp://`` are automatically refanged. Use this whenever
    an alert, email, log excerpt or report needs to be parsed for indicators.

    Args:
        text: The raw text (alert, email body, log line, report) to analyse.

    Returns:
        A categorised, de-duplicated list of extracted indicators.
    """
    iocs = extract_iocs(text)
    total = sum(len(values) for values in iocs.values())

    lines = [f"Extracted {total} unique indicator(s):"]
    for indicator_type, values in iocs.items():
        if values:
            lines.append(f"- {indicator_type} ({len(values)}): {', '.join(values)}")
    if total == 0:
        lines.append("- No indicators detected. The text may be defanged in an unsupported way.")

    return "\n".join(lines)
