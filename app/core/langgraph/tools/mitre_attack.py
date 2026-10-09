"""MITRE ATT&CK technique lookup tool.

Downloads the official MITRE ATT&CK Enterprise STIX bundle from the public
``attack-stix-data`` repository (no API key required), caches it locally, and
answers lookups by technique ID (``T1059`` / ``T1059.001``) or free-text
keyword. Understanding adversary techniques helps analysts map observed
activity to tactics and build detection coverage.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from langchain_core.tools import tool

from app.core.config import settings
from app.core.logging import logger

_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
_CACHE_DIR = Path.home() / ".cache" / "threavix"
_CACHE_FILE = _CACHE_DIR / "enterprise-attack.json"
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def _download_stix() -> bool:
    """Download and cache the ATT&CK STIX bundle. Returns True on success."""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with httpx.stream("GET", _STIX_URL, timeout=60.0, follow_redirects=True) as response:
            response.raise_for_status()
            with open(_CACHE_FILE, "wb") as handle:
                for chunk in response.iter_bytes():
                    handle.write(chunk)
        logger.info("mitre_attack_stix_downloaded", path=str(_CACHE_FILE))
        return True
    except (httpx.HTTPError, OSError) as exc:
        logger.warning("mitre_attack_download_failed", error=str(exc))
        return False


def _load_bundle() -> Optional[Dict[str, Any]]:
    """Load the cached STIX bundle, downloading it first if necessary."""
    if not _CACHE_FILE.exists() and not _download_stix():
        return None
    try:
        with open(_CACHE_FILE, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        logger.warning("mitre_attack_parse_failed", error=str(exc))
        return None


def _build_index(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract attack-pattern techniques from a STIX bundle."""
    techniques: List[Dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        technique_id = ""
        for reference in obj.get("external_references", []) or []:
            if reference.get("source_name") == "mitre-attack":
                technique_id = reference.get("external_id", "")
                break
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", []) or []
            if phase.get("phase_name")
        ]
        techniques.append(
            {
                "id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []) or [],
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
        )
    return techniques


def _format(technique: Dict[str, Any]) -> str:
    description = technique["description"].strip().replace("\n", " ")
    if len(description) > 700:
        description = description[:700] + "..."
    lines = [
        f"{technique['id']} — {technique['name']}",
        f"Tactics: {', '.join(technique['tactics']) or 'n/a'}",
        f"Platforms: {', '.join(technique['platforms']) or 'n/a'}",
        f"Sub-technique: {technique['is_subtechnique']}",
        f"Description: {description}",
    ]
    return "\n".join(lines)


@tool
async def mitre_attack_lookup(query: str) -> str:
    """Look up MITRE ATT&CK techniques by ID or keyword.

    Understand how adversaries operate by mapping observed behaviour to ATT&CK
    tactics and techniques. Accepts a technique ID (e.g. ``T1059`` or
    ``T1059.001``) for an exact match, or a keyword such as ``phishing``,
    ``powershell`` or ``credential dumping`` for a ranked search.

    Args:
        query: A technique ID or a free-text keyword describing adversary behaviour.

    Returns:
        The matched technique(s) with tactics, platforms and description.
    """
    text = (query or "").strip()
    if not text:
        return "Provide a technique ID (e.g. T1059) or a keyword (e.g. phishing)."

    bundle = await asyncio.to_thread(_load_bundle)
    if not bundle:
        return "MITRE ATT&CK data is unavailable (download failed and no local cache). Check connectivity."

    techniques = _build_index(bundle)

    if _TECHNIQUE_ID_RE.match(text):
        target = text.upper()
        for technique in techniques:
            if technique["id"].upper() == target:
                return _format(technique)
        return f"No ATT&CK Enterprise technique found with ID {target}."

    needle = text.lower()
    matches = [
        technique
        for technique in techniques
        if needle in technique["name"].lower() or needle in technique["description"].lower()
    ]
    if not matches:
        return f"No ATT&CK Enterprise techniques matched '{text}'."

    matches.sort(key=lambda technique: needle not in technique["name"].lower())
    header = f"Top {min(len(matches), 5)} ATT&CK techniques matching '{text}':\n"
    return header + "\n\n".join(_format(technique) for technique in matches[:5])
