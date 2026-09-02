from app.schemas import (
    SecurityAlertInput,
)
from app.services.misp_indicator_extractor import (
    extract_misp_indicators,
)


def test_extracts_source_and_destination_ip_indicators():
    alert = SecurityAlertInput(
        alert_id="ALT-MISP-001",
        source="wazuh",
        event_text=(
            "Suspicious network activity detected."
        ),
        metadata={
            "source_ip": "203.0.113.10",
            "destination_ip": "10.0.0.25",
        },
    )

    indicators = extract_misp_indicators(
        alert
    )

    assert indicators == [
        (
            "ip-src",
            "203.0.113.10",
        ),
        (
            "ip-dst",
            "10.0.0.25",
        ),
    ]

def test_returns_empty_list_when_no_misp_indicators_exist():
    alert = SecurityAlertInput(
        alert_id="ALT-MISP-002",
        source="wazuh",
        event_text=(
            "Authentication event without IP metadata."
        ),
        metadata={},
    )

    indicators = extract_misp_indicators(
        alert
    )

    assert indicators == []


def test_ignores_blank_ip_indicators():
    alert = SecurityAlertInput(
        alert_id="ALT-MISP-003",
        source="wazuh",
        event_text=(
            "Network event with blank IP metadata."
        ),
        metadata={
            "source_ip": "   ",
            "destination_ip": "",
        },
    )

    indicators = extract_misp_indicators(
        alert
    )

    assert indicators == []