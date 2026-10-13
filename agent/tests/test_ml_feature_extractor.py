from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
    extract_ml_features,
    feature_vector_from_alert,
)
from app.schemas import SecurityAlertInput


def test_extract_ml_features_uses_wazuh_metadata():
    alert = SecurityAlertInput(
        alert_id="ALT-ML-FEATURES-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
        metadata={
            "rule_level": 10,
            "rule_frequency": 148,
            "rule_groups": [
                "authentication_failed",
                "sshd",
            ],
            "mitre_ids": [
                "T1110",
            ],
            "agent_id": "007",
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "source_port": 49152,
            "destination_port": 22,
            "failed_attempts": 148,
            "privileged_target": True,
            "decoder_name": "sshd",
            "decoder_parent": "sshd",
        },
    )

    features = extract_ml_features(
        alert
    )

    assert features == {
        "rule_level": 10.0,
        "rule_frequency": 148.0,
        "failed_attempts": 148.0,
        "privileged_target": 1.0,
        "source_port": 49152.0,
        "destination_port": 22.0,
        "has_source_ip": 1.0,
        "has_target_user": 1.0,
        "has_agent": 1.0,
        "mitre_id_count": 1.0,
        "rule_group_count": 2.0,
        "is_sudo_event": 0.0,
        "is_account_change_event": 0.0,
        "is_privilege_group_change": 0.0,
        "has_command": 0.0,
    }


def test_extract_ml_features_handles_missing_metadata():
    alert = SecurityAlertInput(
        alert_id="ALT-ML-FEATURES-002",
        source="wazuh",
        event_text="Generic Wazuh alert.",
        metadata={},
    )

    features = extract_ml_features(
        alert
    )

    assert features == {
        "rule_level": 0.0,
        "rule_frequency": 0.0,
        "failed_attempts": 0.0,
        "privileged_target": 0.0,
        "source_port": 0.0,
        "destination_port": 0.0,
        "has_source_ip": 0.0,
        "has_target_user": 0.0,
        "has_agent": 0.0,
        "mitre_id_count": 0.0,
        "rule_group_count": 0.0,
        "is_sudo_event": 0.0,
        "is_account_change_event": 0.0,
        "is_privilege_group_change": 0.0,
        "has_command": 0.0,
    }


def test_ml_feature_order_is_stable():
    alert = SecurityAlertInput(
        alert_id="ALT-ML-FEATURES-003",
        source="wazuh",
        event_text="Test alert.",
        metadata={
            "rule_level": 8,
            "rule_frequency": 10,
            "failed_attempts": 10,
            "privileged_target": True,
            "source_port": 50000,
            "destination_port": 22,
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "agent_id": "007",
            "mitre_ids": ["T1110"],
            "rule_groups": [
                "authentication_failed"
            ],
        },
    )

    features = extract_ml_features(
        alert
    )

    assert list(
        features.keys()
    ) == [
        "rule_level",
        "rule_frequency",
        "failed_attempts",
        "privileged_target",
        "source_port",
        "destination_port",
        "has_source_ip",
        "has_target_user",
        "has_agent",
        "mitre_id_count",
        "rule_group_count",
        "is_sudo_event",
        "is_account_change_event",
        "is_privilege_group_change",
        "has_command",
    ]


def test_ml_feature_names_match_runtime_feature_order():
    assert ML_FEATURE_NAMES == [
        "rule_level",
        "rule_frequency",
        "failed_attempts",
        "privileged_target",
        "source_port",
        "destination_port",
        "has_source_ip",
        "has_target_user",
        "has_agent",
        "mitre_id_count",
        "rule_group_count",
        "is_sudo_event",
        "is_account_change_event",
        "is_privilege_group_change",
        "has_command",
    ]


def test_feature_vector_matches_feature_name_order():
    alert = SecurityAlertInput(
        alert_id="ALT-ML-FEATURES-004",
        source="wazuh",
        event_text="Test alert.",
        metadata={
            "rule_level": 10,
            "rule_frequency": 25,
            "failed_attempts": 20,
            "privileged_target": True,
            "source_port": 50000,
            "destination_port": 22,
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "agent_id": "007",
            "mitre_ids": [
                "T1110",
                "T1078",
            ],
            "rule_groups": [
                "authentication_failed",
                "sshd",
            ],
            "decoder_name": "sudo",
            "decoder_parent": "sudo",
            "command": "/bin/bash",
        },
    )

    vector = feature_vector_from_alert(
        alert
    )

    assert vector == [
        10.0,
        25.0,
        20.0,
        1.0,
        50000.0,
        22.0,
        1.0,
        1.0,
        1.0,
        2.0,
        2.0,
        1.0,
        0.0,
        0.0,
        1.0,
    ]

    assert len(vector) == len(
        ML_FEATURE_NAMES
    )


def test_extract_ml_features_derives_privilege_semantics():
    sudo_alert = SecurityAlertInput(
        alert_id="ALT-ML-SEMANTIC-001",
        source="wazuh",
        event_text=(
            "Successful sudo to ROOT executed."
        ),
        metadata={
            "decoder_name": "sudo",
            "decoder_parent": "sudo",
            "target_user": "root",
            "command": "/bin/bash",
        },
    )

    sudo_features = extract_ml_features(
        sudo_alert
    )

    assert (
        sudo_features[
            "is_sudo_event"
        ]
        == 1.0
    )

    assert (
        sudo_features[
            "is_account_change_event"
        ]
        == 0.0
    )

    assert (
        sudo_features[
            "is_privilege_group_change"
        ]
        == 0.0
    )

    assert (
        sudo_features[
            "has_command"
        ]
        == 1.0
    )

    group_alert = SecurityAlertInput(
        alert_id="ALT-ML-SEMANTIC-002",
        source="wazuh",
        event_text="User added to group sudo.",
        metadata={
            "decoder_name": "gpasswd",
            "decoder_parent": "gpasswd",
            "target_user": "backdooruser",
            "target_group": "sudo",
        },
    )

    group_features = extract_ml_features(
        group_alert
    )

    assert (
        group_features[
            "is_sudo_event"
        ]
        == 0.0
    )

    assert (
        group_features[
            "is_account_change_event"
        ]
        == 1.0
    )

    assert (
        group_features[
            "is_privilege_group_change"
        ]
        == 1.0
    )

    assert (
        group_features[
            "has_command"
        ]
        == 0.0
    )

    account_alert = SecurityAlertInput(
        alert_id="ALT-ML-SEMANTIC-003",
        source="wazuh",
        event_text=(
            "New user added to the system."
        ),
        metadata={
            "decoder_name": "useradd",
            "decoder_parent": "useradd",
            "target_user": "backdooruser",
        },
    )

    account_features = extract_ml_features(
        account_alert
    )

    assert (
        account_features[
            "is_account_change_event"
        ]
        == 1.0
    )

    assert (
        account_features[
            "is_privilege_group_change"
        ]
        == 0.0
    )