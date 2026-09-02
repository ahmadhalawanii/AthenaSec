import pytest

from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)


RAW_WAZUH_ALERT = {
    "timestamp": "2026-08-14T18:30:00.000+0000",
    "rule": {
        "level": 10,
        "description": (
            "sshd: Multiple authentication failures."
        ),
        "id": "5712",
        "frequency": 8,
        "groups": [
            "authentication_failures",
            "sshd",
        ],
        "mitre": {
            "id": [
                "T1110.001",
            ],
            "tactic": [
                "Credential Access",
            ],
            "technique": [
                "Password Guessing",
            ],
        },
    },
    "agent": {
        "id": "007",
        "name": "workstation-07",
        "ip": "192.168.1.20",
    },
    "id": "1716206454.722325",
    "full_log": (
        "Failed password for root from "
        "192.168.1.45 port 55122 ssh2"
    ),
    "previous_output": (
        "Failed password for root from "
        "192.168.1.45 port 55121 ssh2\n"
        "Failed password for root from "
        "192.168.1.45 port 55120 ssh2"
    ),
    "data": {
        "srcip": "192.168.1.45",
        "srcuser": "attacker",
        "dstuser": "root",
        "srcport": "55122",
        "dstip": "192.168.1.20",
        "dstport": "22",
    },
    "decoder": {
        "name": "sshd",
        "parent": "sshd",
    },
    "location": "/var/log/auth.log",
}


def test_parses_raw_wazuh_alert():
    alert = parse_wazuh_alert(
        RAW_WAZUH_ALERT
    )

    assert alert.alert_id == (
        "wazuh:1716206454.722325"
    )

    assert alert.source == "wazuh"

    assert (
        "Failed password for root"
        in alert.event_text
    )

    assert alert.metadata[
        "source_ip"
    ] == "192.168.1.45"

    assert alert.metadata[
        "source_user"
    ] == "attacker"

    assert alert.metadata[
        "target_user"
    ] == "root"

    assert alert.metadata[
        "agent_id"
    ] == "007"

    assert alert.metadata[
        "rule_id"
    ] == "5712"

    assert alert.metadata[
        "rule_level"
    ] == 10


def test_preserves_wazuh_correlation_metadata():
    alert = parse_wazuh_alert(
        RAW_WAZUH_ALERT
    )

    assert alert.metadata[
        "rule_description"
    ] == (
        "sshd: Multiple authentication failures."
    )

    assert alert.metadata[
        "rule_frequency"
    ] == 8

    assert alert.metadata[
        "previous_output"
    ] == RAW_WAZUH_ALERT[
        "previous_output"
    ]

    assert alert.metadata[
        "decoder_name"
    ] == "sshd"

    assert alert.metadata[
        "decoder_parent"
    ] == "sshd"

    assert alert.metadata[
        "mitre_ids"
    ] == [
        "T1110.001",
    ]

    assert alert.metadata[
        "mitre_tactics"
    ] == [
        "Credential Access",
    ]

    assert alert.metadata[
        "mitre_techniques"
    ] == [
        "Password Guessing",
    ]


def test_derives_failed_attempts_from_wazuh_frequency():
    alert = parse_wazuh_alert(
        RAW_WAZUH_ALERT
    )

    assert alert.metadata[
        "failed_attempts"
    ] == 8


def test_derives_privileged_target_for_root_user():
    alert = parse_wazuh_alert(
        RAW_WAZUH_ALERT
    )

    assert alert.metadata[
        "privileged_target"
    ] is True


def test_parses_wazuh_indexer_hit():
    hit = {
        "_id": "index-document-123",
        "_index": (
            "wazuh-alerts-4.x-2026.08.14"
        ),
        "_source": RAW_WAZUH_ALERT,
    }

    alert = parse_wazuh_alert(
        hit
    )

    assert alert.alert_id == (
        "wazuh-alerts-4.x-2026.08.14:"
        "index-document-123"
    )

    assert alert.metadata[
        "wazuh_document_id"
    ] == "index-document-123"

    assert alert.metadata[
        "wazuh_index"
    ] == (
        "wazuh-alerts-4.x-2026.08.14"
    )


def test_rule_description_is_used_when_full_log_missing():
    payload = {
        **RAW_WAZUH_ALERT,
        "full_log": None,
    }

    alert = parse_wazuh_alert(
        payload
    )

    assert alert.event_text == (
        "sshd: Multiple authentication failures."
    )


def test_alert_without_identifier_is_rejected():
    payload = {
        "rule": {
            "description": "Test alert",
        }
    }

    with pytest.raises(
        ValueError,
        match="identifier",
    ):
        parse_wazuh_alert(
            payload
        )