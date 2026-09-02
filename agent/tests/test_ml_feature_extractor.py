from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
    extract_ml_features,
)
from app.schemas import SecurityAlertInput
from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
    extract_ml_features,
    feature_vector_from_alert,
)

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
            "rule_groups": ["authentication_failed"],
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
    ]

    assert len(vector) == len(
        ML_FEATURE_NAMES
    )