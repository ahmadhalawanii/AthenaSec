import numpy as np
from sklearn.ensemble import (
    RandomForestClassifier,
)
from sklearn.linear_model import (
    LogisticRegression,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import (
    StandardScaler,
)

from training.data_contract import (
    TrainingRow,
    training_feature_vector,
)


def build_xy(
    rows: list[TrainingRow],
) -> tuple[
    np.ndarray,
    np.ndarray,
]:
    X = np.asarray(
        [
            training_feature_vector(
                row
            )
            for row in rows
        ],
        dtype=float,
    )

    y = np.asarray(
        [
            row.label
            for row in rows
        ],
        dtype=object,
    )

    return (
        X,
        y,
    )


def build_logistic_pipeline(
    class_weight: dict[str, float],
) -> Pipeline:
    return Pipeline(
        [
            (
                "scaler",
                StandardScaler(),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                    class_weight=class_weight,
                    random_state=42,
                ),
            ),
        ]
    )


def build_random_forest(
    class_weight: dict[str, float],
    random_state: int = 42,
) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300,
        class_weight=class_weight,
        random_state=random_state,
        n_jobs=-1,
    )