from typing import Protocol

from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)


class MLClassifier(Protocol):
    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        ...