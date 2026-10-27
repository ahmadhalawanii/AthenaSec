import pytest

from app.ml.operational_events import operational_event_reason
from app.tools.wazuh_alert_parser import parse_wazuh_alert


def startup_alert():
    return parse_wazuh_alert({
        "id": "1793112187.0",
        "timestamp": "2026-10-27T12:00:00+00:00",
        "rule": {
            "id": "502",
            "level": 3,
            "description": "Wazuh server started.",
            "groups": ["ossec"],
        },
        "decoder": {"name": "ossec"},
        "agent": {"id": "000"},
        "location": "wazuh-monitord",
    })


def test_recognizes_wazuh_manager_startup():
    assert operational_event_reason(startup_alert()) == (
        "wazuh_manager_startup"
    )


@pytest.mark.parametrize("field,value", [
    ("rule_id", "5712"),
    ("rule_level", 10),
    ("rule_description", "Repeated authentication failures."),
    ("decoder_name", "sshd"),
    ("agent_id", "007"),
    ("location", "/var/log/auth.log"),
    ("rule_groups", ["ossec", "authentication_failed"]),
    ("source_ip", "203.0.113.10"),
    ("target_user", "root"),
    ("command", "sudo usermod"),
    ("mitre_ids", ["T1110"]),
    ("failed_attempts", 10),
])
def test_does_not_exclude_other_events(field, value):
    alert = startup_alert()
    alert.metadata[field] = value

    assert operational_event_reason(alert) is None


def test_does_not_exclude_manual_alerts():
    alert = startup_alert().model_copy(
        update={"source": "manual"}
    )

    assert operational_event_reason(alert) is None
