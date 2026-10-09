"""CVE vulnerability lookup tool.

Looks up CVE details (description, CVSS scores, CWE weakness and references)
via the public, keyless CIRCL CVE API. Useful for vulnerability triage during
incident response and for correlating exploited vulnerabilities with alerts.

The CIRCL API serves CVE records in the CVE 5.0 JSON schema
(``cveMetadata`` plus ``containers``). Older deployments returned a flat
document (``summary``, ``cvss3`` ...). Both shapes are handled here so the tool
keeps working across API revisions.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.tools import tool

from app.core.langgraph.tools._http import get_json

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# Order matters: prefer the newest CVSS version when several are present.
_CVSS_KEYS = [
    ("cvssV4_0", "CVSS v4.0"),
    ("cvssV3_1", "CVSS v3.1"),
    ("cvssV3_0", "CVSS v3.0"),
    ("cvssV2_0", "CVSS v2.0"),
]


def _first_english(values: List[Dict[str, Any]]) -> Optional[str]:
    """Return the English ``value`` from a CVE 5.0 language-tagged list."""
    fallback: Optional[str] = None
    for item in values or []:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not value:
            continue
        if item.get("lang") == "en":
            return value
        if fallback is None:
            fallback = value
    return fallback


def _extract_cvss(metrics: List[Dict[str, Any]]) -> Optional[Tuple[str, Any, Any]]:
    """Find the best CVSS entry in a list of CVE 5.0 metric objects."""
    for key, label in _CVSS_KEYS:
        for metric in metrics or []:
            if not isinstance(metric, dict):
                continue
            entry = metric.get(key)
            if isinstance(entry, dict):
                return label, entry.get("baseScore"), entry.get("vectorString")
    return None


def _format_cve50(data: Dict[str, Any]) -> str:
    containers = data.get("containers") or {}
    meta = data.get("cveMetadata") or {}
    cna = containers.get("cna") or {}
    adp = containers.get("adp") or []

    identifier = meta.get("cveId") or "unknown CVE"
    lines: List[str] = [f"Vulnerability report: {identifier}"]

    metrics: List[Dict[str, Any]] = list(cna.get("metrics") or [])
    for entry in adp:
        if isinstance(entry, dict):
            metrics.extend(entry.get("metrics") or [])

    cvss = _extract_cvss(metrics)
    if cvss:
        label, score, vector = cvss
        lines.append(f"{label}: {score} ({vector or 'n/a'})")

    cwes: List[str] = []
    for problem_type in cna.get("problemTypes") or []:
        for description in (problem_type or {}).get("descriptions") or []:
            cwe = (description or {}).get("cweId")
            if cwe and cwe not in cwes:
                cwes.append(cwe)
    if cwes:
        lines.append(f"CWE: {', '.join(cwes)}")

    if meta.get("datePublished"):
        lines.append(f"Published: {meta['datePublished']}  Modified: {meta.get('dateUpdated')}")

    summary = _first_english(cna.get("descriptions") or [])
    if summary:
        lines.append(f"Summary: {summary.strip()}")

    affected = cna.get("affected") or []
    if affected:
        lines.append("Affected products:")
        seen = set()
        shown = 0
        for item in affected:
            if not isinstance(item, dict):
                continue
            label = " ".join(part for part in [item.get("vendor"), item.get("product")] if part)
            label = label or "unknown"
            if label in seen:
                continue
            seen.add(label)
            lines.append(f"  - {label}")
            shown += 1
            if shown >= 15:
                break
        if len(affected) > shown:
            lines.append(f"  ... and {len(affected) - shown} more entries")

    references = [
        ref.get("url")
        for ref in cna.get("references") or []
        if isinstance(ref, dict) and ref.get("url")
    ]
    if references:
        lines.append("References:")
        for url in references[:10]:
            lines.append(f"  - {url}")

    return "\n".join(lines)


def _format_legacy(data: Dict[str, Any]) -> str:
    lines: List[str] = [f"Vulnerability report: {data.get('id', 'unknown CVE')}"]
    if data.get("cvss3") is not None:
        lines.append(f"CVSS v3: {data.get('cvss3')} ({data.get('cvss3-vector', 'n/a')})")
    if data.get("cvss") is not None:
        lines.append(f"CVSS v2: {data.get('cvss')} ({data.get('cvss-vector', 'n/a')})")
    if data.get("cwe"):
        lines.append(f"CWE: {data.get('cwe')}")
    if data.get("Published"):
        lines.append(f"Published: {data.get('Published')}  Modified: {data.get('Modified')}")

    lines.append(f"Summary: {data.get('summary', 'n/a')}")

    vulnerable_products = data.get("vulnerable_product") or []
    if vulnerable_products:
        lines.append("Affected products:")
        for product in vulnerable_products[:15]:
            lines.append(f"  - {product}")
        if len(vulnerable_products) > 15:
            lines.append(f"  ... and {len(vulnerable_products) - 15} more")

    references = data.get("references") or []
    if references:
        lines.append("References:")
        for reference in references[:10]:
            lines.append(f"  - {reference}")

    return "\n".join(lines)


def format_cve(data: Dict[str, Any]) -> str:
    """Render a CIRCL CVE record (CVE 5.0 or legacy) as a readable report."""
    if not isinstance(data, dict) or not data:
        return "No vulnerability data available for this identifier."

    if "cveMetadata" in data or "containers" in data:
        return _format_cve50(data)
    if any(key in data for key in ("cvss3", "cvss", "summary", "vulnerable_product")):
        return _format_legacy(data)

    lines = ["Vulnerability report: unknown CVE", f"Summary: {data.get('summary', 'n/a')}"]
    return "\n".join(lines)


@tool
async def cve_lookup(cve_id: str) -> str:
    """Look up a CVE vulnerability by ID.

    Returns the summary, CVSS v3/v4 scores and vectors, associated CWE
    weakness and reference links so an analyst can rapidly assess severity and
    prioritise patching or containment.

    Args:
        cve_id: The CVE identifier (e.g. ``CVE-2021-44228``).

    Returns:
        A formatted vulnerability report, or a message if the CVE is unknown.
    """
    identifier = (cve_id or "").strip().upper()
    if not _CVE_RE.match(identifier):
        return f"'{cve_id}' is not a valid CVE identifier. Expected format: CVE-YYYY-NNNN."

    ok, data = await get_json(f"https://cve.circl.lu/api/cve/{identifier}")
    if not ok:
        return f"Could not retrieve {identifier}: {data}"
    if not data:
        return f"{identifier} was not found in the CIRCL CVE database."

    return format_cve(data)
