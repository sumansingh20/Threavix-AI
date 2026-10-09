"""LangGraph tools powering the Threavix cyber threat-intelligence agent.

The toolset blends offline analysis (IOC extraction, incident-response
playbooks) with keyless enrichment (IP/DNS/CVE/MITRE/OSINT) and optional
premium integrations (VirusTotal). Tools degrade gracefully so the agent keeps
working without any threat-intel API keys.
"""

from langchain_core.tools.base import BaseTool

from .cve_lookup import cve_lookup
from .dns_intel import dns_intel
from .ioc_extractor import ioc_extractor
from .ip_intel import ip_intel
from .ir_playbook import ir_playbook
from .mitre_attack import mitre_attack_lookup
from .virustotal import virustotal_lookup
from .web_search import web_search_tool

tools: list[BaseTool] = [
    ioc_extractor,
    ip_intel,
    dns_intel,
    cve_lookup,
    mitre_attack_lookup,
    ir_playbook,
    virustotal_lookup,
    web_search_tool,
]
