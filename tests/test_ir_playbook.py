"""Offline tests for the incident-response playbook tool."""

from app.core.langgraph.tools.ir_playbook import ir_playbook


def _text(result) -> str:
    """Normalise a tool result (str or content blocks) into text."""
    if isinstance(result, str):
        return result
    return str(result)


def test_ransomware_playbook_has_phases():
    output = _text(ir_playbook.invoke({"incident_type": "ransomware"}))
    assert "Ransomware" in output
    assert "CONTAIN" in output.upper()
    assert "MITRE ATT&CK" in output


def test_alias_matching_for_account_takeover():
    output = _text(ir_playbook.invoke({"incident_type": "account takeover"}))
    assert "Compromised Credentials" in output


def test_unknown_incident_lists_available():
    output = _text(ir_playbook.invoke({"incident_type": "alien invasion"}))
    assert "No playbook matched" in output
    assert "phishing" in output


def test_empty_incident_type_prompts_user():
    output = _text(ir_playbook.invoke({"incident_type": ""}))
    assert "Provide an incident type" in output
