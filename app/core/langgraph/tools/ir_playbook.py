"""Incident Response playbook tool.

Provides structured, offline incident-response guidance aligned to the NIST
SP 800-61 (Preparation, Detection & Analysis, Containment/Eradication/Recovery,
Post-Incident Activity) and SANS PICERL lifecycle. Guidance is bundled with the
application so it remains available even without internet access.
"""

from typing import Dict, List, Optional

from langchain_core.tools import tool

_PLAYBOOKS: Dict[str, Dict[str, List[str]]] = {
    "phishing": {
        "aliases": ["email", "spoof", "business email", "bec", "spearphishing", "spam"],
        "mitre": ["T1566 Phishing", "T1598 Phishing for Information", "T1204 User Execution"],
        "detect": [
            "Collect the original message with full headers (Received chain, SPF/DKIM/DMARC results).",
            "Extract and defang all URLs, attachments and sender infrastructure (ioc_extractor).",
        ],
        "contain": [
            "Quarantine/delete matching messages from all mailboxes via the mail gateway.",
            "Block malicious sender domains/IPs and URLs at the mail gateway, proxy and DNS sinkhole.",
            "Reset credentials for any user who submitted credentials or opened the payload.",
        ],
        "eradicate": [
            "Remove any delivered payloads and persistence (mail rules, OAuth grants, scheduled tasks).",
            "Revoke active sessions and refresh tokens for affected identities.",
        ],
        "recover": [
            "Restore mailbox rules and monitor for re-delivery.",
            "Re-enable accounts after MFA re-enrollment and verification.",
        ],
        "investigate": [
            "Identify all recipients and who interacted (clicks, opens, credential submission).",
            "Determines whether the campaign is targeted or commodity.",
        ],
        "evidence": ["Original .eml/.msg", "Mail gateway logs", "Proxy/DNS logs", "Identity sign-in logs"],
    },
    "ransomware": {
        "aliases": ["encrypt", "lockbit", "conti", "crypto", "extortion", "double extortion"],
        "mitre": ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery", "T1489 Service Stop"],
        "detect": [
            "Look for mass file rename/encryption, ransom notes and deleted shadow copies.",
            "Identify initial access vector (phishing, exposed RDP/VPN, vulnerable edge device).",
        ],
        "contain": [
            "Isolate affected hosts and C2 at the network layer (do NOT power off, preserve memory).",
            "Disable compromised privileged accounts and terminate active RDP/VPN sessions.",
            "Block known C2 infrastructure and ransomware file-hash IOCs.",
        ],
        "eradicate": [
            "Remove the ransomware binary, persistence and any backdoors/tunneling tools.",
            "Patch the initial access vector and close exposed services.",
        ],
        "recover": [
            "Restore from known-good, isolated backups after validating integrity.",
            "Rebuild compromised hosts rather than cleaning them where feasible.",
        ],
        "investigate": [
            "Establish dwell time and lateral movement before encryption.",
            "Determine whether data was exfiltrated before encryption (double extortion).",
        ],
        "evidence": ["Ransom note", "Pre-encryption file listing", "Backup integrity", "EPP/EDR timeline"],
    },
    "malware": {
        "aliases": ["trojan", "backdoor", "rootkit", "loader", "dropper", "rat", "infostealer"],
        "mitre": ["T1059 Command and Scripting Interpreter", "T1547 Boot or Logon Autostart", "T1071 Application Layer Protocol"],
        "detect": [
            "Hash the sample (MD5/SHA1/SHA256) and query reputation (virustotal_lookup).",
            "Review process lineage, persistence and network connections on the host.",
        ],
        "contain": [
            "Isolate the host and block C2 domains/IPs.",
            "Suspend scheduled tasks, services and WMI subscriptions used for persistence.",
        ],
        "eradicate": [
            "Remove binaries, persistence and any dropped tooling.",
            "Reset credentials that may have been harvested.",
        ],
        "recover": ["Rebuild or restore the host and monitor for re-infection."],
        "investigate": ["Determine delivery vector, patient zero and spread across the estate."],
        "evidence": ["Sample hashes", "EDR process tree", "Persistence artifacts", "Network capture"],
    },
    "compromised_credentials": {
        "aliases": ["account takeover", "credential", "password", "impossible travel", "mfa fatigue", "brute force"],
        "mitre": ["T1078 Valid Accounts", "T1110 Brute Force", "T1621 Multi-Factor Authentication Request Generation"],
        "detect": [
            "Review sign-in logs for impossible travel, new devices, MFA prompts and legacy protocols.",
            "Check for new mail rules, OAuth app consents and mailbox forwarding.",
        ],
        "contain": [
            "Force password reset and revoke all active sessions/refresh tokens.",
            "Re-enroll MFA and block legacy authentication protocols.",
        ],
        "eradicate": ["Remove attacker persistence: mail rules, OAuth grants, app passwords, alternate contacts."],
        "recover": ["Re-enable the account with MFA and monitor sign-ins closely."],
        "investigate": ["Confirm whether the account was used for internal lateral movement or data access."],
        "evidence": ["Entra ID / IdP sign-in logs", "Audit logs", "Mailbox rule changes", "OAuth consent grants"],
    },
    "data_exfiltration": {
        "aliases": ["exfil", "data leak", "insider data", "upload large", "dlp", "transfer"],
        "mitre": ["T1041 Exfiltration Over C2 Channel", "T1567 Exfiltration Over Web Service", "T1048 Exfiltration Over Alternative Protocol"],
        "detect": [
            "Baseline normal egress volume and flag anomalous large transfers or cloud uploads.",
            "Correlate with DLP alerts, proxy logs and cloud audit trails.",
        ],
        "contain": [
            "Block the exfiltration channel (domain, IP, cloud app) at egress controls.",
            "Disable the responsible account/session pending investigation.",
        ],
        "eradicate": ["Remove the transfer tooling and revoke access to the destination service."],
        "recover": ["Assess regulatory/notification obligations and rotate exposed secrets."],
        "investigate": ["Quantify what data left, to where and under whose authority."],
        "evidence": ["Proxy/firewall egress logs", "DLP alerts", "Cloud audit logs", "File access records"],
    },
    "ddos": {
        "aliases": ["denial of service", "dos", "flood", "amplification", "volumetric"],
        "mitre": ["T1498 Network Denial of Service", "T1499 Endpoint Denial of Service"],
        "detect": ["Identify traffic profile, source distribution and targeted service/port."],
        "contain": [
            "Enable upstream scrubbing/rate limiting and anycast/CDN absorption.",
            "Apply targeted ACLs and SYN-cookie / connection limits.",
        ],
        "eradicate": ["Harden exposed services and disable unnecessary reflection vectors."],
        "recover": ["Scale capacity, tune WAF/proxy thresholds and monitor for renewed waves."],
        "investigate": ["Determine motive and whether DDoS masks another intrusion."],
        "evidence": ["NetFlow/sFlow", "Edge device counters", "Provider scrubbing reports"],
    },
    "web_application_compromise": {
        "aliases": ["webshell", "sql injection", "rce", "web app", "cms", "deserialization"],
        "mitre": ["T1505.003 Web Shell", "T1190 Exploit Public-Facing Application", "T1059 Command and Scripting Interpreter"],
        "detect": [
            "Review web logs for exploitation patterns and unexpected file writes.",
            "Search the webroot for webshells and modified files.",
        ],
        "contain": [
            "Take the application offline or place it behind a restrictive WAF.",
            "Block the source IPs and rotate all application secrets and DB credentials.",
        ],
        "eradicate": ["Remove webshells, patch the exploited vulnerability and redeploy from clean source."],
        "recover": ["Restore service and validate integrity; monitor for re-exploitation."],
        "investigate": ["Determine whether the database was accessed or modified."],
        "evidence": ["Web/proxy logs", "File integrity baseline", "Database audit logs", "Deployment artifacts"],
    },
    "insider_threat": {
        "aliases": ["insider", "employee", "rogue", "privilege misuse", "terminated employee"],
        "mitre": ["T1078 Valid Accounts", "T1530 Data from Cloud Storage", "T1567 Exfiltration Over Web Service"],
        "detect": ["Review access to sensitive repositories, mass downloads and off-hours activity."],
        "contain": ["Restrict the identity's access and preserve evidence with legal/HR guidance."],
        "eradicate": ["Revoke entitlements, tokens and physical/network access as appropriate."],
        "recover": ["Rotate shared credentials the individual could access."],
        "investigate": ["Work with Legal/HR; maintain chain of custody."],
        "evidence": ["DLP", "badge logs", "repository audit", "email/IM records (with legal hold)"],
    },
    "cloud_compromise": {
        "aliases": ["aws", "azure", "gcp", "cloud", "iam", "access key", "bucket"],
        "mitre": ["T1078.004 Cloud Accounts", "T1530 Data from Cloud Storage", "T1098 Account Manipulation"],
        "detect": [
            "Review CloudTrail/Activity/Audit logs for new keys, role changes and unusual regions.",
            "Check for public buckets, snapshots and backdoor IAM roles/users.",
        ],
        "contain": [
            "Disable compromised keys/roles and revoke sessions.",
            "Restrict the account with a deny-all guardrail policy.",
        ],
        "eradicate": ["Remove backdoor principals, key pairs and trust relationships."],
        "recover": ["Rotate all secrets and re-establish least-privilege IAM."],
        "investigate": ["Identify all resources accessed and data affected."],
        "evidence": ["CloudTrail/Activity logs", "IAM policy history", "Storage access logs", "GuardDuty/Defender alerts"],
    },
    "supply_chain": {
        "aliases": ["third party", "vendor", "software supply", "dependency", "build pipeline"],
        "mitre": ["T1195 Supply Chain Compromise", "T1195.002 Compromise Software Supply Chain"],
        "detect": ["Correlate the vendor advisory with internal deployment inventory and build provenance."],
        "contain": ["Freeze/roll back the affected component and block the malicious update channel."],
        "eradicate": ["Remove the compromised component and rebuild artifacts from trusted sources."],
        "recover": ["Redeploy clean artifacts and verify integrity/signatures."],
        "investigate": ["Determine whether the malicious component executed and with what privileges."],
        "evidence": ["SBOM", "build logs", "package manifest", "vendor advisory"],
    },
}


def _match_incident(text: str) -> Optional[str]:
    """Return the best matching playbook key for the given text."""
    haystack = text.lower()
    for key, playbook in _PLAYBOOKS.items():
        if key.replace("_", " ") in haystack:
            return key
        for alias in playbook.get("aliases", []):
            if alias in haystack:
                return key
    return None


def _render(key: str) -> str:
    playbook = _PLAYBOOKS[key]
    lines = [f"Incident Response Playbook: {key.replace('_', ' ').title()}"]
    lines.append(f"MITRE ATT&CK relevance: {', '.join(playbook.get('mitre', []))}")
    for section in ("detect", "contain", "eradicate", "recover", "investigate", "evidence"):
        steps = playbook.get(section)
        if steps:
            lines.append(f"\n{section.upper()} / {_section_label(section)}:")
            lines.extend(f"  {idx}. {step}" for idx, step in enumerate(steps, start=1))
    return "\n".join(lines)


def _section_label(section: str) -> str:
    labels = {
        "detect": "NIST: Detection & Analysis",
        "contain": "NIST: Containment",
        "eradicate": "NIST: Eradication",
        "recover": "NIST: Recovery",
        "investigate": "NIST: Analysis",
        "evidence": "Evidence to preserve",
    }
    return labels.get(section, section)


@tool
def ir_playbook(incident_type: str) -> str:
    """Return a structured incident-response playbook for an incident type.

    Supported incident types include phishing, ransomware, malware,
    compromised_credentials (account takeover), data_exfiltration, ddos,
    web_application_compromise, insider_threat, cloud_compromise and
    supply_chain. Guidance follows the NIST SP 800-61 and SANS PICERL
    lifecycle and works fully offline.

    Args:
        incident_type: The incident type or a short description (e.g.
            ``ransomware`` or ``account takeover``).

    Returns:
        A phase-by-phase response playbook with MITRE mapping and evidence to preserve.
    """
    text = (incident_type or "").strip()
    if not text:
        available = ", ".join(sorted(key.replace("_", " ") for key in _PLAYBOOKS))
        return f"Provide an incident type. Available playbooks: {available}."

    key = _match_incident(text)
    if not key:
        available = ", ".join(sorted(key.replace("_", " ") for key in _PLAYBOOKS))
        return f"No playbook matched '{incident_type}'. Available playbooks: {available}."

    return _render(key)
