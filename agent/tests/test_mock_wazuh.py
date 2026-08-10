from app.schemas import SecurityAlertInput
from app.tools.mock_wazuh import (
    search_related_security_events,
)


def test_mock_wazuh_returns_related_evidence():
    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH brute force suspected.",
    )

    evidence = search_related_security_events(
        alert
    )

    assert len(evidence) == 3

    assert any(
        "No successful SSH authentication"
        in item
        for item in evidence
    )

    assert any(
        "workstation-07" in item
        for item in evidence
    )