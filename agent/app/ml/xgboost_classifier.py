from __future__ import annotations

import numpy as np
from xgboost import XGBClassifier


ATHENASEC_XGB_CLASSES = (
    "benign",
    "brute_force",
    "privilege_misuse",
)

_LABEL_TO_INDEX = {
    label: index
    for index, label
    in enumerate(
        ATHENASEC_XGB_CLASSES
    )
}


class AthenaSecXGBClassifier:
    def __init__(
        self,
        *,
        class_weight: dict[str, float],
        n_estimators: int = 300,
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        self.class_weight = dict(
            class_weight
        )
        self.n_estimators = (
            n_estimators
        )
        self.random_state = (
            random_state
        )
        self.n_jobs = n_jobs

        self.classes_ = np.asarray(
            ATHENASEC_XGB_CLASSES,
            dtype=object,
        )

        self._model = XGBClassifier(
            n_estimators=(
                self.n_estimators
            ),
            random_state=(
                self.random_state
            ),
            n_jobs=self.n_jobs,
            objective="multi:softprob",
            eval_metric="mlogloss",
        )

    def fit(
        self,
        X,
        y,
    ):
        labels = np.asarray(
            y,
            dtype=object,
        )

        unknown_labels = sorted(
            {
                str(label)
                for label in labels
                if str(label)
                not in _LABEL_TO_INDEX
            }
        )

        if unknown_labels:
            raise ValueError(
                "Unsupported AthenaSec "
                "XGBoost label: "
                + ", ".join(
                    unknown_labels
                )
            )

        observed_labels = {
            str(label)
            for label in labels
        }

        missing_labels = [
            label
            for label
            in ATHENASEC_XGB_CLASSES
            if label
            not in observed_labels
        ]

        if missing_labels:
            raise ValueError(
                "AthenaSec XGBoost training "
                "data is missing required "
                "class: "
                + ", ".join(
                    missing_labels
                )
            )

        encoded_y = np.asarray(
            [
                _LABEL_TO_INDEX[
                    str(label)
                ]
                for label in labels
            ],
            dtype=int,
        )

        sample_weight = np.asarray(
            [
                float(
                    self.class_weight.get(
                        str(label),
                        1.0,
                    )
                )
                for label in labels
            ],
            dtype=float,
        )

        self._model.fit(
            X,
            encoded_y,
            sample_weight=sample_weight,
        )

        return self

    def predict(
        self,
        X,
    ) -> np.ndarray:
        encoded_predictions = (
            self._model.predict(
                X
            )
        )

        return np.asarray(
            [
                ATHENASEC_XGB_CLASSES[
                    int(index)
                ]
                for index
                in encoded_predictions
            ],
            dtype=object,
        )

    def predict_proba(
        self,
        X,
    ) -> np.ndarray:
        probabilities = (
            self._model.predict_proba(
                X
            )
        )

        return np.asarray(
            probabilities,
            dtype=float,
        )
