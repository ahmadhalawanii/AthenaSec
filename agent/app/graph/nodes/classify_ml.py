from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import (
    AttackPrediction,
    SecurityAlertInput,
)


MLClassifierFunction = Callable[
    [SecurityAlertInput],
    AttackPrediction,
]


def make_ml_classification_node(
    classifier: MLClassifierFunction,
):
    def classify_with_ml(
        state: InvestigationState,
    ) -> InvestigationState:
        alert = state["alert"]

        try:
            prediction = classifier(
                alert
            )

        except Exception as exc:
            return {
                "ml_prediction": AttackPrediction(
                    classification="unknown",
                    confidence=0.0,
                    model_version="unavailable",
                ),
                "ml_error": str(exc),
            }

        return {
            "ml_prediction": prediction,
        }

    return classify_with_ml