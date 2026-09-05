from training.wazuh_bridge import (
    training_row_from_wazuh_event,
)


def test_wazuh_event_becomes_canonical_training_row():
    event = {
        "id": "wazuh-test-001",
        "rule": {
            "level": 10,
            "frequency": 12,
            "groups": [
                "authentication_failed",
                "sshd",
            ],
            "mitre": {
                "id": [
                    "T1110",
                ],
            },
        },
        "data": {
            "srcip": "192.0.2.10",
            "srcport": "45678",
            "dstport": "22",
            "dstuser": "root",
        },
        "agent": {
            "id": "007",
            "name": "workstation-07",
        },
    }

    row = training_row_from_wazuh_event(
        event=event,
        label="brute_force",
        source_dataset="cic_ids_2018",
        source_row_id="row-123",
    )

    assert row.rule_level == 10.0
    assert row.rule_frequency == 12.0
    assert row.failed_attempts == 12.0
    assert row.privileged_target == 1.0
    assert row.source_port == 45678.0
    assert row.destination_port == 22.0
    assert row.has_source_ip == 1.0
    assert row.has_target_user == 1.0
    assert row.has_agent == 1.0
    assert row.mitre_id_count == 1.0
    assert row.rule_group_count == 2.0

    assert row.label == "brute_force"
    assert row.source_dataset == "cic_ids_2018"
    assert row.source_row_id == "row-123"