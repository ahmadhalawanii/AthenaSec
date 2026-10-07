from training.data_contract import (
    TrainingRow,
)
from training.model_selection import (
    evaluate_strict_leave_one_dataset_out,
    select_deployment_model,
)


DATASETS = [
    "dataset_a",
    "dataset_b",
    "dataset_c",
    "cmu_cert_r4_2",
]


def _row(
    *,
    value: float,
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> TrainingRow:
    return TrainingRow(
        rule_level=value,
        rule_frequency=value,
        failed_attempts=(
            value
            if label == "brute_force"
            else 0.0
        ),
        privileged_target=(
            1.0
            if label == "privilege_misuse"
            else 0.0
        ),
        source_port=value,
        destination_port=22.0,
        has_source_ip=1.0,
        has_target_user=1.0,
        has_agent=1.0,
        mitre_id_count=1.0,
        rule_group_count=2.0,
        is_sudo_event=(
            1.0
            if label == "privilege_misuse"
            else 0.0
        ),
        is_account_change_event=0.0,
        is_privilege_group_change=0.0,
        has_command=(
            1.0
            if label == "privilege_misuse"
            else 0.0
        ),
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
    )


def _rows() -> list[TrainingRow]:
    rows = []

    for dataset_index, dataset in enumerate(
        DATASETS
    ):
        for index in range(4):
            rows.append(
                _row(
                    value=(
                        10.0
                        + dataset_index * 10
                        + index
                    ),
                    label="benign",
                    source_dataset=dataset,
                    source_row_id=(
                        f"{dataset}-benign-{index}"
                    ),
                )
            )

            rows.append(
                _row(
                    value=(
                        110.0
                        + dataset_index * 10
                        + index
                    ),
                    label="brute_force",
                    source_dataset=dataset,
                    source_row_id=(
                        f"{dataset}-brute-{index}"
                    ),
                )
            )

    for dataset in DATASETS[:3]:
        for index, value in enumerate(
            (
                200.0,
                201.0,
            )
        ):
            rows.append(
                _row(
                    value=value,
                    label="privilege_misuse",
                    source_dataset=dataset,
                    source_row_id=(
                        f"{dataset}-priv-{index}"
                    ),
                )
            )

    for index, value in enumerate(
        (
            200.0,
            201.0,
            202.0,
        )
    ):
        rows.append(
            _row(
                value=value,
                label="privilege_misuse",
                source_dataset="cmu_cert_r4_2",
                source_row_id=(
                    f"cmu-priv-{index}"
                ),
            )
        )

    return rows


def test_strict_lodo_removes_held_out_vectors_and_marks_invalid_fold():
    results = (
        evaluate_strict_leave_one_dataset_out(
            rows=_rows(),
            random_state=42,
        )
    )

    assert (
        results["valid_fold_count"]
        == 3
    )

    assert (
        results["invalid_fold_count"]
        == 1
    )

    assert (
        results["folds"][
            "cmu_cert_r4_2"
        ]["status"]
        == "invalid"
    )

    assert (
        results["folds"][
            "cmu_cert_r4_2"
        ][
            "missing_training_labels"
        ]
        == [
            "privilege_misuse",
        ]
    )

    assert (
        results["folds"][
            "dataset_a"
        ][
            "overlap_rows_removed"
        ]
        == 2
    )

    assert set(
        results["models"]
    ) == {
        "logistic_regression",
        "random_forest",
        "extra_trees",
        "xgboost",
    }

    for metrics in (
        results["models"].values()
    ):
        assert (
            metrics["valid_folds"]
            == 3
        )

        assert (
            metrics["invalid_folds"]
            == 1
        )

        assert (
            "mean_accuracy"
            in metrics
        )

        assert (
            "mean_present_macro_f1"
            in metrics
        )

        assert (
            "worst_present_macro_f1"
            in metrics
        )


def test_model_selection_prioritizes_cross_dataset_macro_f1():
    strict_results = {
        "models": {
            "logistic_regression": {
                "mean_accuracy": 0.9359,
                "mean_present_macro_f1": 0.9354,
                "worst_present_macro_f1": 0.8667,
            },
            "random_forest": {
                "mean_accuracy": 0.8762,
                "mean_present_macro_f1": 0.8733,
                "worst_present_macro_f1": 0.7500,
            },
            "extra_trees": {
                "mean_accuracy": 0.8762,
                "mean_present_macro_f1": 0.8733,
                "worst_present_macro_f1": 0.7500,
            },
            "xgboost": {
                "mean_accuracy": 0.9452,
                "mean_present_macro_f1": 0.9263,
                "worst_present_macro_f1": 0.5137,
            },
        },
    }

    selection = (
        select_deployment_model(
            strict_results
        )
    )

    assert (
        selection["selected_model"]
        == "logistic_regression"
    )

    assert (
        selection["ranking"][0]
        == "logistic_regression"
    )