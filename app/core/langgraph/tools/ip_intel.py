"""IP address enrichment tool.

Performs threat-intelligence enrichment of an IPv4/IPv6 address using keyless
public sources by default (ipwho.is) and optionally premium providers
(AbuseIPDB, VirusTotal) when API keys are configured.
"""

import ipaddress
from typing import List

from langchain_core.tools import tool

from app.core.config import settings
from app.core.langgraph.tools._http import get_json
from app.utils.threat_intel import is_private_ip


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _ipwhois(ip: str) -> List[str]:
    ok, data = await get_json(f"https://ipwho.is/{ip}")
    if not ok or not isinstance(data, dict) or not data.get("success", True):
        return []
    connection = data.get("connection") or {}
    security = data.get("security") or {}
    lines = [
        "Geolocation / ASN (ipwho.is):",
        f"  country: {data.get('country')} ({data.get('country_code')})",
        f"  region/city: {data.get('region')} / {data.get('city')}",
        f"  asn: {connection.get('asn')}",
        f"  org/isp: {connection.get('org')} / {connection.get('isp')}",
        f"  proxy: {security.get('proxy')}  vpn: {security.get('vpn')}  tor: {security.get('tor')}  hosting: {security.get('hosting')}",
    ]
    return lines


async def _abuseipdb(ip: str) -> List[str]:
    ok, data = await get_json(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
    )
    if not ok or not isinstance(data, dict):
        return []
    d = data.get("data") or {}
    return [
        "Abuse confidence (AbuseIPDB):",
        f"  abuseConfidenceScore: {d.get('abuseConfidenceScore')}%",
        f"  totalReports: {d.get('totalReports')} from {d.get('numDistinctUsers')} distinct users",
        f"  lastReportedAt: {d.get('lastReportedAt')}",
        f"  usageType: {d.get('usageType')}",
    ]


async def _virustotal(ip: str) -> List[str]:
    ok, data = await get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
    )
    if not ok or not isinstance(data, dict):
        return []
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    return [
        "VirusTotal detections:",
        f"  malicious: {stats.get('malicious')}  suspicious: {stats.get('suspicious')}  harmless: {stats.get('harmless')}  undetected: {stats.get('undetected')}",
        f"  reputation: {attributes.get('reputation')}",
        f"  as_owner: {attributes.get('as_owner')}  network: {attributes.get('network')}",
    ]


@tool
async def ip_intel(ip_address: str) -> str:
    """Enrich an IP address with geolocation, ASN and reputation intelligence.

    Uses keyless public sources by default and automatically adds AbuseIPDB /
    VirusTotal results when their API keys are configured. Private, loopback
    and reserved addresses are detected and skipped.

    Args:
        ip_address: The IPv4 or IPv6 address to investigate (e.g. ``8.8.8.8``).

    Returns:
        A formatted threat-intelligence report for the address.
    """
    ip = (ip_address or "").strip()
    if not _is_ip(ip):
        return f"'{ip_address}' is not a valid IPv4/IPv6 address."

    if is_private_ip(ip):
        return (
            f"{ip} is a private, loopback or reserved address. "
            "External reputation sources do not track it; pivot to internal asset/identity context instead."
        )

    sections: List[str] = [f"Threat intelligence for {ip}"]
    sections.extend(await _ipwhois(ip))
    if settings.ABUSEIPDB_API_KEY:
        sections.extend(await _abuseipdb(ip))
    if settings.VIRUSTOTAL_API_KEY:
        sections.extend(await _virustotal(ip))

    if len(sections) == 1:
        return f"No enrichment data could be retrieved for {ip}. Sources may be unreachable."

    sections.append(
        "Analyst note: corroborate reputation findings with internal telemetry before blocking."
    )
    return "\n".join(sections)
