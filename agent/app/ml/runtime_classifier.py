from typing import Any

from app.ml.feature_extractor import (
    feature_vector_from_alert,
)
from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)


class RuntimeMLClassifier:
    def __init__(
        self,
        model: Any,
        model_version: str,
    ):
        self.model = model
        self.model_version = model_version

    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        vector = feature_vector_from_alert(
            alert
        )

        rows = [
            vector,
        ]

        predicted_class = (
            self.model.predict(
                rows
            )[0]
        )

        probabilities = (
            self.model.predict_proba(
                rows
            )[0]
        )

        classes = list(
            self.model.classes_
        )

        try:
            class_index = classes.index(
                predicted_class
            )
        except ValueError as exc:
            raise ValueError(
                "Model predicted a class that "
                "is not present in model.classes_."
            ) from exc

        if (
            not hasattr(
                probabilities,
                "__len__",
            )
            or len(probabilities)
            != len(classes)
        ):
            raise ValueError(
                "Model probability output "
                "does not match model.classes_."
            )

        try:
            confidence = float(
                probabilities[
                    class_index
                ]
            )
        except (
            TypeError,
            ValueError,
            IndexError,
        ) as exc:
            raise ValueError(
                "Model probability output "
                "is invalid."
            ) from exc

        return AttackPrediction(
            classification=predicted_class,
            confidence=confidence,
            model_version=self.model_version,
        )