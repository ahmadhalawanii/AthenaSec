import os

from app.ml.model_loader import (
    load_runtime_classifier,
)
from app.ml.runtime_classifier import (
    RuntimeMLClassifier,
)
from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)


class UnavailableMLClassifier:
    def __init__(
        self,
        reason: str,
    ):
        self.reason = reason

    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        raise RuntimeError(
            self.reason
        )


def build_ml_classifier_from_env() -> RuntimeMLClassifier:
    model_path = os.getenv(
        "ATHENASEC_ML_MODEL_PATH"
    )

    if (
        model_path is None
        or not model_path.strip()
    ):
        raise RuntimeError(
            "ATHENASEC_ML_MODEL_PATH "
            "must be configured."
        )

    return load_runtime_classifier(
        model_path
    )


def build_live_ml_classifier():
    try:
        return build_ml_classifier_from_env()
    except Exception as exc:
        return UnavailableMLClassifier(
            reason=str(
                exc
            )
        )