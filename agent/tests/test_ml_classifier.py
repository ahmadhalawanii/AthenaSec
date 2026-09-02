from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)
from app.services.ml_classifier import MLClassifier


class FakeMLClassifier:
    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        return AttackPrediction(
            classification="brute_force",
            confidence=0.91,
            model_version="fake-v1",
        )


def test_ml_classifier_interface_accepts_classifier():
    classifier: MLClassifier = FakeMLClassifier()

    alert = SecurityAlertInput(
        alert_id="ALT-ML-001",
        source="wazuh",
        event_text=(
            "Repeated SSH login failures."
        ),
        metadata={
            "source_ip": "10.0.0.50",
        },
    )

    prediction = classifier.classify(
        alert
    )

    assert (
        prediction.classification
        == "brute_force"
    )

    assert prediction.confidence == 0.91

    assert (
        prediction.model_version
        == "fake-v1"
    )