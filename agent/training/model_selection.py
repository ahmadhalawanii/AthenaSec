from statistics import mean

from training.balancing import (
    class_weight_map,
    undersample_benign,
)
from training.data_contract import (
    TRAINING_LABELS,
    TrainingRow,
    training_feature_vector,
)
from training.deduplication import (
    deduplicate_rows,
)
from training.evaluate import (
    evaluate_predictions,
)
from training.preprocessing import (
    build_extra_trees,
    build_logistic_pipeline,
    build_random_forest,
    build_xgboost,
    build_xy,
)
from training.splitting import (
    leave_one_dataset_out,
)
from training.validation import (
    validate_training_rows,
)


MODEL_NAMES = (
    "logistic_regression",
    "random_forest",
    "extra_trees",
    "xgboost",
)


def _feature_vector(
    row: TrainingRow,
) -> tuple[float, ...]:
    return tuple(
        training_feature_vector(
            row
        )
    )


def _present_macro_f1(
    metrics: dict[str, object],
) -> float:
    per_class = metrics[
        "per_class"
    ]

    values = [
        class_metrics["f1"]
        for class_metrics
        in per_class.values()
        if (
            class_metrics["support"]
            > 0
        )
    ]

    if not values:
        return 0.0

    return float(
        sum(values)
        / len(values)
    )


def _build_models(
    *,
    class_weights: dict[
        str,
        float,
    ],
    random_state: int,
):
    return {
        "logistic_regression": (
            build_logistic_pipeline(
                class_weight=class_weights,
            )
        ),
        "random_forest": (
            build_random_forest(
                class_weight=class_weights,
                random_state=random_state,
            )
        ),
        "extra_trees": (
            build_extra_trees(
                class_weight=class_weights,
                random_state=random_state,
            )
        ),
        "xgboost": (
            build_xgboost(
                class_weight=class_weights,
                random_state=random_state,
            )
        ),
    }


def _summarize_model_folds(
    *,
    fold_results: list[
        tuple[
            str,
            dict[str, object],
        ]
    ],
    invalid_fold_count: int,
) -> dict[str, object]:
    worst_accuracy = min(
        fold_results,
        key=lambda item: (
            item[1]["accuracy"]
        ),
    )

    worst_present_f1 = min(
        fold_results,
        key=lambda item: (
            item[1][
                "present_macro_f1"
            ]
        ),
    )

    privilege_results = [
        item
        for item in fold_results
        if (
            item[1][
                "per_class"
            ][
                "privilege_misuse"
            ][
                "support"
            ]
            > 0
        )
    ]

    worst_privilege = (
        min(
            privilege_results,
            key=lambda item: (
                item[1][
                    "per_class"
                ][
                    "privilege_misuse"
                ][
                    "f1"
                ]
            ),
        )
        if privilege_results
        else None
    )

    return {
        "valid_folds": len(
            fold_results
        ),
        "invalid_folds": (
            invalid_fold_count
        ),
        "mean_accuracy": float(
            mean(
                item[1][
                    "accuracy"
                ]
                for item
                in fold_results
            )
        ),
        "mean_present_macro_f1": float(
            mean(
                item[1][
                    "present_macro_f1"
                ]
                for item
                in fold_results
            )
        ),
        "worst_accuracy": float(
            worst_accuracy[
                1
            ][
                "accuracy"
            ]
        ),
        "worst_accuracy_dataset": (
            worst_accuracy[0]
        ),
        "worst_present_macro_f1": float(
            worst_present_f1[
                1
            ][
                "present_macro_f1"
            ]
        ),
        "worst_present_macro_f1_dataset": (
            worst_present_f1[0]
        ),
        "worst_privilege_f1": (
            float(
                worst_privilege[
                    1
                ][
                    "per_class"
                ][
                    "privilege_misuse"
                ][
                    "f1"
                ]
            )
            if worst_privilege
            else None
        ),
        "worst_privilege_f1_dataset": (
            worst_privilege[0]
            if worst_privilege
            else None
        ),
    }


def evaluate_strict_leave_one_dataset_out(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> dict[str, object]:
    validate_training_rows(
        rows
    )

    datasets = sorted(
        {
            row.source_dataset
            for row in rows
        }
    )

    folds = {}

    model_fold_results = {
        model_name: []
        for model_name in MODEL_NAMES
    }

    for dataset in datasets:
        (
            training_rows,
            held_out_rows,
        ) = leave_one_dataset_out(
            rows,
            held_out_dataset=dataset,
        )

        training_rows, _ = (
            deduplicate_rows(
                training_rows
            )
        )

        held_out_rows, _ = (
            deduplicate_rows(
                held_out_rows
            )
        )

        if not training_rows:
            raise ValueError(
                "No training rows remain after "
                f"holding out dataset: {dataset}"
            )

        if not held_out_rows:
            raise ValueError(
                "Held-out dataset contains "
                f"no rows: {dataset}"
            )

        held_out_vectors = {
            _feature_vector(
                row
            )
            for row in held_out_rows
        }

        original_training_count = len(
            training_rows
        )

        strict_training_rows = [
            row
            for row in training_rows
            if (
                _feature_vector(
                    row
                )
                not in held_out_vectors
            )
        ]

        overlap_rows_removed = (
            original_training_count
            - len(
                strict_training_rows
            )
        )

        training_labels = {
            row.label
            for row
            in strict_training_rows
        }

        missing_labels = [
            label
            for label
            in TRAINING_LABELS
            if (
                label
                not in training_labels
            )
        ]

        if missing_labels:
            folds[dataset] = {
                "status": "invalid",
                "reason": (
                    "vector_disjoint_filter_"
                    "removed_required_"
                    "training_classes"
                ),
                "missing_training_labels": (
                    missing_labels
                ),
                "overlap_rows_removed": (
                    overlap_rows_removed
                ),
                "held_out_rows": len(
                    held_out_rows
                ),
            }

            continue

        balanced_training_rows = (
            undersample_benign(
                strict_training_rows,
                random_state=random_state,
            )
        )

        class_weights = (
            class_weight_map(
                balanced_training_rows
            )
        )

        train_X, train_y = build_xy(
            balanced_training_rows
        )

        held_out_X, held_out_y = (
            build_xy(
                held_out_rows
            )
        )

        models = _build_models(
            class_weights=class_weights,
            random_state=random_state,
        )

        fold_model_metrics = {}

        for model_name, model in (
            models.items()
        ):
            model.fit(
                train_X,
                train_y,
            )

            predictions = model.predict(
                held_out_X
            )

            metrics = evaluate_predictions(
                held_out_y,
                predictions,
            )

            metrics[
                "present_macro_f1"
            ] = _present_macro_f1(
                metrics
            )

            fold_model_metrics[
                model_name
            ] = metrics

            model_fold_results[
                model_name
            ].append(
                (
                    dataset,
                    metrics,
                )
            )

        folds[dataset] = {
            "status": "valid",
            "training_rows": len(
                strict_training_rows
            ),
            "held_out_rows": len(
                held_out_rows
            ),
            "overlap_rows_removed": (
                overlap_rows_removed
            ),
            "models": (
                fold_model_metrics
            ),
        }

    valid_fold_count = sum(
        1
        for fold in folds.values()
        if (
            fold["status"]
            == "valid"
        )
    )

    invalid_fold_count = (
        len(folds)
        - valid_fold_count
    )

    model_summaries = {}

    for model_name, fold_results in (
        model_fold_results.items()
    ):
        if not fold_results:
            continue

        model_summaries[
            model_name
        ] = _summarize_model_folds(
            fold_results=fold_results,
            invalid_fold_count=(
                invalid_fold_count
            ),
        )

    return {
        "evaluation": (
            "strict_vector_disjoint_"
            "leave_one_dataset_out"
        ),
        "valid_fold_count": (
            valid_fold_count
        ),
        "invalid_fold_count": (
            invalid_fold_count
        ),
        "folds": folds,
        "models": model_summaries,
    }


def select_deployment_model(
    strict_results: dict[
        str,
        object,
    ],
) -> dict[str, object]:
    models = strict_results.get(
        "models"
    )

    if not isinstance(
        models,
        dict,
    ) or not models:
        raise ValueError(
            "Strict LODO results contain "
            "no valid model summaries."
        )

    ranking = sorted(
        models,
        key=lambda model_name: (
            -float(
                models[
                    model_name
                ][
                    "mean_present_macro_f1"
                ]
            ),
            -float(
                models[
                    model_name
                ][
                    "worst_present_macro_f1"
                ]
            ),
            -float(
                models[
                    model_name
                ][
                    "mean_accuracy"
                ]
            ),
            model_name,
        ),
    )

    selected_model = ranking[0]

    return {
        "selected_model": (
            selected_model
        ),
        "selection_rule": (
            "Highest mean present-class "
            "macro F1 across valid strict "
            "vector-disjoint LODO folds; "
            "ties are broken by worst-fold "
            "present-class macro F1, then "
            "mean accuracy."
        ),
        "ranking": ranking,
        "selected_metrics": (
            models[
                selected_model
            ]
        ),
    }