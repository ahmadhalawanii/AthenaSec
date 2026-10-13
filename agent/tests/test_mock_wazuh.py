from app.schemas import SecurityAlertInput
from app.tools.mock_wazuh import (
    gather_requested_evidence,
)


def test_gathers_only_requested_authentication_evidence():
    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH brute force suspected.",
    )

    evidence = gather_requested_evidence(
        alert,
        [
            "authentication_history",
        ],
    )

    assert any(
        "151 failed SSH authentication"
        in item.content
        for item in evidence
    )

    assert any(
        "No successful SSH authentication"
        in item.content
        for item in evidence
    )

    assert not any(
        "workstation-07"
        in item.content
        for item in evidence
    )


def test_gathers_endpoint_context_when_requested():
    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH brute force suspected.",
    )

    evidence = gather_requested_evidence(
        alert,
        [
            "source_endpoint_context",
        ],
    )

    assert any(
        "workstation-07"
        in item.content
        for item in evidence
    )


def test_gathers_multiple_requested_evidence_types():
    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH brute force suspected.",
    )

    evidence = gather_requested_evidence(
        alert,
        [
            "authentication_history",
            "source_endpoint_context",
        ],
    )

    assert any(
        "No successful SSH authentication"
        in item.content
        for item in evidence
    )

    assert any(
        "workstation-07"
        in item.content
        for item in evidence
    )