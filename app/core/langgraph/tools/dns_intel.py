"""DNS intelligence tool.

Resolves common DNS record types for a domain and surfaces MX/NS/TXT context
that is useful during phishing, domain-takedown and infrastructure pivoting
investigations. Uses the system resolver via dnspython.
"""

import asyncio
from typing import List

import dns.asyncresolver
import dns.exception
from langchain_core.tools import tool

_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


async def _resolve(resolver: dns.asyncresolver.Resolver, domain: str, record_type: str) -> List[str]:
    try:
        answer = await resolver.resolve(domain, record_type, lifetime=8.0)
        return [record.to_text() for record in answer]
    except (dns.exception.DNSException, asyncio.TimeoutError):
        return []


@tool
async def dns_intel(domain: str) -> str:
    """Resolve DNS records for a domain (A, AAAA, CNAME, MX, NS, TXT, SOA).

    Useful for investigating domains found in phishing emails, C2 callbacks or
    suspicious alerts and for pivoting across related infrastructure. TXT
    records frequently expose SPF/DMARC posture and verification tokens.

    Args:
        domain: The domain to resolve (e.g. ``example.com``).

    Returns:
        A formatted list of DNS records grouped by record type.
    """
    name = (domain or "").strip().strip(".")
    if not name or "." not in name:
        return f"'{domain}' is not a valid domain name."

    resolver = dns.asyncresolver.Resolver()
    results = await asyncio.gather(*[_resolve(resolver, name, rt) for rt in _RECORD_TYPES])

    lines = [f"DNS intelligence for {name}"]
    found_any = False
    for record_type, records in zip(_RECORD_TYPES, results):
        if records:
            found_any = True
            lines.append(f"{record_type}:")
            for record in records:
                lines.append(f"  - {record}")

    if not found_any:
        return f"No DNS records could be resolved for {name} (NXDOMAIN, offline, or timeout)."

    return "\n".join(lines)
