import pytest
from pydantic import ValidationError

from app.schemas import AttackPrediction


def test_attack_prediction_accepts_valid_prediction():
    prediction = AttackPrediction(
        classification="brute_force",
        confidence=0.93,
        model_version="athenasec-classifier-v1",
    )

    assert prediction.classification == "brute_force"
    assert prediction.confidence == 0.93
    assert (
        prediction.model_version
        == "athenasec-classifier-v1"
    )


def test_attack_prediction_rejects_confidence_above_one():
    with pytest.raises(
        ValidationError
    ):
        AttackPrediction(
            classification="brute_force",
            confidence=1.1,
            model_version="athenasec-classifier-v1",
        )


def test_attack_prediction_rejects_negative_confidence():
    with pytest.raises(
        ValidationError
    ):
        AttackPrediction(
            classification="privilege_misuse",
            confidence=-0.1,
            model_version="athenasec-classifier-v1",
        )