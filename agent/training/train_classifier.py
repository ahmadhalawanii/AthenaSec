from pathlib import Path
from dataclasses import dataclass
from typing import Any

from training.balancing import (
    class_weight_map,
    undersample_benign,
)
from training.data_contract import (
    TrainingRow,
)
from training.deduplication import (
    deduplicate_rows,
)
from training.evaluate import (
    evaluate_predictions,
)
from training.preprocessing import (
    build_logistic_pipeline,
    build_random_forest,
    build_xy,
)
from training.splitting import (
    split_rows,
)
from training.validation import (
    validate_training_rows,
)
from training.wazuh_bridge import (
    training_rows_from_behavior_replay_capture_file,
)


@dataclass(frozen=True)
class TrainingResult:
    logistic_regression_model: Any
    random_forest_model: Any
    model_metrics: dict[
        str,
        dict[str, object],
    ]
    duplicate_count: int


def _evaluate_model(
    model: Any,
    validation_rows: list[TrainingRow],
    test_rows: list[TrainingRow],
) -> dict[str, object]:
    validation_X, validation_y = build_xy(
        validation_rows
    )

    test_X, test_y = build_xy(
        test_rows
    )

    validation_predictions = model.predict(
        validation_X
    )

    test_predictions = model.predict(
        test_X
    )

    return {
        "validation": evaluate_predictions(
            validation_y,
            validation_predictions,
        ),
        "test": evaluate_predictions(
            test_y,
            test_predictions,
        ),
    }


def train_classifier(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> TrainingResult:
    validate_training_rows(
        rows
    )

    deduplicated_rows, duplicate_count = (
        deduplicate_rows(
            rows
        )
    )

    split = split_rows(
        deduplicated_rows,
        random_state=random_state,
    )

    balanced_train_rows = (
        undersample_benign(
            split.train,
            random_state=random_state,
        )
    )

    class_weights = class_weight_map(
        balanced_train_rows
    )

    train_X, train_y = build_xy(
        balanced_train_rows
    )

    logistic_model = (
        build_logistic_pipeline(
            class_weight=class_weights
        )
    )

    logistic_model.fit(
        train_X,
        train_y,
    )

    random_forest_model = (
        build_random_forest(
            class_weight=class_weights,
            random_state=random_state,
        )
    )

    random_forest_model.fit(
        train_X,
        train_y,
    )

    model_metrics = {
        "logistic_regression": (
            _evaluate_model(
                logistic_model,
                split.validation,
                split.test,
            )
        ),
        "random_forest": (
            _evaluate_model(
                random_forest_model,
                split.validation,
                split.test,
            )
        ),
    }

    return TrainingResult(
        logistic_regression_model=(
            logistic_model
        ),
        random_forest_model=(
            random_forest_model
        ),
        model_metrics=model_metrics,
        duplicate_count=duplicate_count,
    )

def fit_deployment_random_forest(
    rows: list[TrainingRow],
    random_state: int = 42,
):
    validate_training_rows(
        rows
    )

    deduplicated_rows, _ = (
        deduplicate_rows(
            rows
        )
    )

    balanced_rows = undersample_benign(
        deduplicated_rows,
        random_state=random_state,
    )

    class_weights = class_weight_map(
        balanced_rows
    )

    train_X, train_y = build_xy(
        balanced_rows
    )

    model = build_random_forest(
        class_weight=class_weights,
        random_state=random_state,
    )

    model.fit(
        train_X,
        train_y,
    )

    return model


def train_classifier_from_behavior_replay_capture_file(
    *,
    captures_path: str | Path,
    random_state: int = 42,
) -> TrainingResult:
    rows = (
        training_rows_from_behavior_replay_capture_file(
            captures_path=captures_path,
        )
    )

    return train_classifier(
        rows=rows,
        random_state=random_state,
    )
