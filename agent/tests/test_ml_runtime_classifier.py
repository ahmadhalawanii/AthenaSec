from app.ml.runtime_classifier import (
    RuntimeMLClassifier,
)
from app.schemas import SecurityAlertInput


class FakeModel:
    classes_ = [
        "benign",
        "brute_force",
        "privilege_misuse",
        "unknown",
    ]

    def __init__(self):
        self.predict_calls = []
        self.probability_calls = []

    def predict(
        self,
        rows,
    ):
        self.predict_calls.append(
            rows
        )

        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        self.probability_calls.append(
            rows
        )

        return [
            [
                0.01,
                0.96,
                0.02,
                0.01,
            ]
        ]


def test_runtime_classifier_returns_attack_prediction():
    model = FakeModel()

    classifier = RuntimeMLClassifier(
        model=model,
        model_version=(
            "athenasec-classifier-v1"
        ),
    )

    alert = SecurityAlertInput(
        alert_id="ALT-RUNTIME-ML-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
        metadata={
            "rule_level": 10,
            "rule_frequency": 148,
            "failed_attempts": 148,
            "privileged_target": True,
            "source_port": 49152,
            "destination_port": 22,
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "agent_id": "007",
            "mitre_ids": [
                "T1110",
            ],
            "rule_groups": [
                "authentication_failed",
                "sshd",
            ],
        },
    )

    prediction = classifier.classify(
        alert
    )

    assert (
        prediction.classification
        == "brute_force"
    )

    assert prediction.confidence == 0.96

    assert (
        prediction.model_version
        == "athenasec-classifier-v1"
    )

    expected_vector = [
        10.0,
        148.0,
        148.0,
        1.0,
        49152.0,
        22.0,
        1.0,
        1.0,
        1.0,
        1.0,
        2.0,
    ]

    assert model.predict_calls == [
        [
            expected_vector,
        ]
    ]

    assert model.probability_calls == [
        [
            expected_vector,
        ]
    ]

import pytest


class UnknownClassModel:
    classes_ = [
        "benign",
        "brute_force",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "privilege_misuse",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.2,
                0.8,
            ]
        ]


def test_runtime_classifier_rejects_prediction_not_in_classes():
    classifier = RuntimeMLClassifier(
        model=UnknownClassModel(),
        model_version="broken-v1",
    )

    alert = SecurityAlertInput(
        alert_id="ALT-RUNTIME-ML-002",
        source="wazuh",
        event_text="Test alert.",
        metadata={},
    )

    with pytest.raises(
        ValueError,
        match="not present in model.classes_",
    ):
        classifier.classify(
            alert
        )


class BadProbabilityModel:
    classes_ = [
        "benign",
        "brute_force",
    ]

    def predict(
        self,
        rows,
    ):
        return [
            "brute_force",
        ]

    def predict_proba(
        self,
        rows,
    ):
        return [
            [
                0.1,
            ]
        ]


def test_runtime_classifier_rejects_invalid_probability_shape():
    classifier = RuntimeMLClassifier(
        model=BadProbabilityModel(),
        model_version="broken-v2",
    )

    alert = SecurityAlertInput(
        alert_id="ALT-RUNTIME-ML-003",
        source="wazuh",
        event_text="Test alert.",
        metadata={},
    )

    with pytest.raises(
        ValueError,
        match="probability output",
    ):
        classifier.classify(
            alert
        )