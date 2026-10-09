"""VirusTotal enrichment tool (optional).

Requires a ``VIRUSTOTAL_API_KEY``. When the key is absent the tool explains how
to enable it and suggests the keyless alternatives built into Threavix, so the
agent can still make progress.
"""

import ipaddress
import re

from langchain_core.tools import tool

from app.core.config import settings
from app.core.langgraph.tools._http import get_json

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])+$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

_ENABLE_HINT = (
    "VirusTotal enrichment is not enabled. Set VIRUSTOTAL_API_KEY in your .env "
    "to unlock it. Meanwhile, use ip_intel (IP geolocation/reputation) or "
    "web_search, or ioc_extractor to pivot on the indicator."
)


def _classify(indicator: str):
    """Return the VirusTotal endpoint segment and type for an indicator."""
    try:
        ipaddress.ip_address(indicator)
        return "ip_addresses", "ip"
    except ValueError:
        pass
    if _HASH_RE.match(indicator):
        return "files", "file"
    if _DOMAIN_RE.match(indicator):
        return "domains", "domain"
    return None, "unknown"


@tool
async def virustotal_lookup(indicator: str) -> str:
    """Look up an IP, domain or file hash on VirusTotal.

    Aggregates multi-engine detections, reputation and metadata for an
    indicator. Requires a configured VirusTotal API key; otherwise returns
    guidance on enabling it.

    Args:
        indicator: An IP address, domain name, or MD5/SHA1/SHA256 file hash.

    Returns:
        A formatted VirusTotal report or a configuration hint.
    """
    if not settings.VIRUSTOTAL_API_KEY:
        return _ENABLE_HINT

    value = (indicator or "").strip()
    endpoint, kind = _classify(value)
    if not endpoint:
        return f"'{indicator}' is not a recognised IP, domain or file hash."

    ok, data = await get_json(
        f"https://www.virustotal.com/api/v3/{endpoint}/{value}",
        headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
    )
    if not ok:
        return f"VirusTotal lookup failed for {value}: {data}"
    if not isinstance(data, dict) or "data" not in data:
        return f"No VirusTotal record found for {value}."

    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    lines = [
        f"VirusTotal report for {value} ({kind})",
        f"Detection stats: malicious={stats.get('malicious')} suspicious={stats.get('suspicious')} "
        f"harmless={stats.get('harmless')} undetected={stats.get('undetected')}",
        f"Reputation: {attributes.get('reputation')}",
    ]
    if kind == "file":
        lines.append(f"Meaningful name: {attributes.get('meaningful_name')}")
        lines.append(f"Type: {attributes.get('type_description')}")
        lines.append(f"Size: {attributes.get('size')} bytes")
    if kind in ("ip", "domain"):
        lines.append(f"AS owner: {attributes.get('as_owner')}")
        lines.append(f"Country: {attributes.get('country')}")

    return "\n".join(lines)
