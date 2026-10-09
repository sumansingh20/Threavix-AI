"""Threat-intelligence utilities used by Threavix tools.

This module contains pure, dependency-light helpers for normalising and
extracting Indicators of Compromise (IOCs) from free text. It is intentionally
side-effect free so that it can be unit-tested without network access.
"""

import ipaddress
import re
from typing import Dict, List

# Mapping used to convert defanged indicators (commonly shared by threat
# researchers to avoid accidental clicks) back into their real form.
_REFANG_PATTERNS = [
    (r"hxxps", "https"),
    (r"hxxp", "http"),
    (r"\[\s*://\s*\]", "://"),
    (r"\[\s*\.\s*\]", "."),
    (r"\(\s*\.\s*\)", "."),
    (r"\{\s*\.\s*\}", "."),
    (r"\[\s*dot\s*\]", "."),
    (r"\(\s*dot\s*\)", "."),
    (r"\[\s*at\s*\]", "@"),
    (r"\(\s*at\s*\)", "@"),
    (r"\[\s*:\s*\]", ":"),
    (r"\[\s*@\s*\]", "@"),
]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\)\]]+", re.IGNORECASE)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}\b")


def refang(text: str) -> str:
    """Convert defanged indicators back into their real, actionable form.

    Args:
        text: Text that may contain defanged indicators (e.g. ``hxxp://``,
            ``evil[.]com``).

    Returns:
        str: The refanged text.
    """
    if not text:
        return ""
    result = text
    for pattern, replacement in _REFANG_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def _valid_ipv4(candidate: str) -> bool:
    """Return True if the candidate is a syntactically valid IPv4 address."""
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def _looks_like_domain(candidate: str) -> bool:
    """Filter out non-domain matches such as bare IPs or version numbers."""
    if _IPV4_RE.fullmatch(candidate):
        return False
    # Reject strings that are only digits/dots (e.g. "1.2.3.4.5" style noise).
    if candidate.replace(".", "").isdigit():
        return False
    # Require a plausible alphabetic TLD to reduce false positives from files.
    tld = candidate.rsplit(".", 1)[-1]
    return len(tld) >= 2 and not tld.isdigit()


def _dedup(values: List[str]) -> List[str]:
    """Case-insensitive de-duplication that preserves insertion order."""
    seen = set()
    ordered = []
    for value in values:
        key = value.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(value)
    return ordered


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """Extract common Indicators of Compromise from arbitrary text.

    The extraction pipeline refangs the input first so that both live and
    defanged indicators are detected. Supported indicator types are IPv4
    addresses, domains, URLs, MD5/SHA1/SHA256 hashes, email addresses and CVE
    identifiers.

    Args:
        text: The raw text to analyse (log line, email, alert, report, ...).

    Returns:
        Dict[str, List[str]]: A mapping of indicator type to a de-duplicated
        list of values.
    """
    normalised = refang(text or "")

    urls = _dedup(_URL_RE.findall(normalised))

    emails = _dedup(_EMAIL_RE.findall(normalised))

    ips = _dedup([ip for ip in _IPV4_RE.findall(normalised) if _valid_ipv4(ip)])

    # Domains may also appear inside URLs/emails; that is acceptable because the
    # domain is itself an indicator worth pivoting on.
    domains = _dedup([d for d in _DOMAIN_RE.findall(normalised) if _looks_like_domain(d)])

    sha256 = _dedup(_SHA256_RE.findall(normalised))
    sha1 = _dedup(_SHA1_RE.findall(normalised))
    md5 = _dedup(_MD5_RE.findall(normalised))

    cves = _dedup([cve.upper() for cve in _CVE_RE.findall(normalised)])

    return {
        "ipv4": ips,
        "domains": domains,
        "urls": urls,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "emails": emails,
        "cves": cves,
    }


def is_private_ip(value: str) -> bool:
    """Return True if the value is a private, loopback or reserved IP address."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast


def summarise_iocs(iocs: Dict[str, List[str]]) -> str:
    """Render an IOC dictionary as a compact human-readable summary."""
    lines = []
    for indicator_type, values in iocs.items():
        if values:
            lines.append(f"  - {indicator_type} ({len(values)}): {', '.join(values)}")
    return "\n".join(lines) if lines else "  - none detected"
