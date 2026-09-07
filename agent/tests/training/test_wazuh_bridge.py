import pytest
from training import wazuh_bridge
from training.behavior_manifest import (
    BehaviorReplay,
)
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
    assert (
        row.source_dataset
        == "cic_ids_2018"
    )
    assert (
        row.source_row_id
        == "row-123"
    )


def test_behavior_replay_alert_becomes_training_row():
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id=(
            "Tuesday-WorkingHours."
            "pcap_ISCX.csv:12345"
        ),
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    alerts = [
        {
            "id": "unrelated-alert",
            "rule": {
                "id": "5712",
                "level": 10,
                "frequency": 8,
                "groups": [
                    "authentication_failures",
                    "sshd",
                ],
            },
            "data": {
                "srcip": "203.0.113.50",
            },
        },
        {
            "id": "matching-alert",
            "rule": {
                "id": "5763",
                "level": 12,
                "frequency": 10,
                "groups": [
                    "authentication_failures",
                    "sshd",
                    "syslog",
                ],
                "mitre": {
                    "id": [
                        "T1110",
                    ],
                },
            },
            "data": {
                "srcip": "198.51.100.25",
                "srcport": "49152",
                "dstport": "22",
                "dstuser": "root",
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
        },
    ]

    row = (
        wazuh_bridge
        .training_row_from_behavior_replay_alerts(
            replay=replay,
            alerts=alerts,
        )
    )

    assert row.rule_level == 12.0
    assert row.rule_frequency == 10.0
    assert row.failed_attempts == 10.0
    assert row.privileged_target == 1.0
    assert row.source_port == 49152.0
    assert row.destination_port == 22.0
    assert row.has_source_ip == 1.0
    assert row.has_target_user == 1.0
    assert row.has_agent == 1.0
    assert row.mitre_id_count == 1.0
    assert row.rule_group_count == 3.0

    assert row.label == "brute_force"

    assert (
        row.source_dataset
        == "cic_ids_2017"
    )

    assert (
        row.source_row_id
        == replay.source_row_id
    )

def test_behavior_replay_alert_rejects_scenario_label_mismatch():
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="sample.csv:1",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_authentication_success"
        ),
    )

    alerts = [
        {
            "id": "benign-alert",
            "rule": {
                "id": "5715",
                "level": 3,
                "groups": [
                    "authentication_success",
                    "sshd",
                ],
            },
            "data": {
                "srcip": "203.0.113.90",
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
        },
    ]

    with pytest.raises(
        ValueError,
        match="Wazuh scenario label mismatch",
    ):
        (
            wazuh_bridge
            .training_row_from_behavior_replay_alerts(
                replay=replay,
                alerts=alerts,
            )
        )

def test_behavior_replay_alert_batches_become_training_rows():
    first_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="cic2017:100",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_invalid_user_bruteforce"
        ),
    )

    first_alerts = [
        {
            "id": "alert-invalid-user",
            "rule": {
                "id": "5712",
                "level": 10,
                "frequency": 8,
                "groups": [
                    "authentication_failures",
                    "sshd",
                ],
            },
            "data": {
                "srcip": "203.0.113.50",
                "dstport": "22",
                "dstuser": "invalid-user",
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
        },
    ]

    second_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2018",
        source_row_id="cic2018:200",
        source_behavior="SSH-Bruteforce",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    second_alerts = [
        {
            "id": "alert-root-password",
            "rule": {
                "id": "5763",
                "level": 12,
                "frequency": 10,
                "groups": [
                    "authentication_failures",
                    "sshd",
                ],
            },
            "data": {
                "srcip": "198.51.100.25",
                "dstport": "22",
                "dstuser": "root",
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
        },
    ]

    rows = (
        wazuh_bridge
        .training_rows_from_behavior_replay_alert_batches(
            replay_alert_batches=[
                (
                    first_replay,
                    first_alerts,
                ),
                (
                    second_replay,
                    second_alerts,
                ),
            ]
        )
    )

    assert len(rows) == 2

    assert (
        rows[0].source_dataset
        == "cic_ids_2017"
    )
    assert (
        rows[0].source_row_id
        == "cic2017:100"
    )
    assert rows[0].rule_level == 10.0
    assert rows[0].failed_attempts == 8.0

    assert (
        rows[1].source_dataset
        == "cic_ids_2018"
    )
    assert (
        rows[1].source_row_id
        == "cic2018:200"
    )
    assert rows[1].rule_level == 12.0
    assert rows[1].failed_attempts == 10.0
    assert rows[1].privileged_target == 1.0


def test_behavior_replay_alert_batches_identify_missing_replay():
    first_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="cic2017:100",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_invalid_user_bruteforce"
        ),
    )

    first_alerts = [
        {
            "id": "alert-invalid-user",
            "rule": {
                "id": "5712",
                "level": 10,
                "frequency": 8,
                "groups": [
                    "authentication_failures",
                    "sshd",
                ],
            },
            "data": {
                "srcip": "203.0.113.50",
                "dstport": "22",
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
        },
    ]

    missing_replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2018",
        source_row_id="cic2018:missing",
        source_behavior="SSH-Bruteforce",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    with pytest.raises(
        ValueError,
        match=(
            "Failed behavior replay "
            "cic_ids_2018 "
            "cic2018:missing"
        ),
    ):
        (
            wazuh_bridge
            .training_rows_from_behavior_replay_alert_batches(
                replay_alert_batches=[
                    (
                        first_replay,
                        first_alerts,
                    ),
                    (
                        missing_replay,
                        [],
                    ),
                ]
            )
        )