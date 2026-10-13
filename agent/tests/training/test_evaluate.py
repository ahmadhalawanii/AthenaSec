from training.data_contract import TrainingRow
from training.evaluate import (
    evaluate_by_dataset,
    evaluate_predictions,
)


LABELS = [
    "benign",
    "brute_force",
    "privilege_misuse",
]


def make_row(
    *,
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> TrainingRow:
    return TrainingRow(
        rule_level=5,
        rule_frequency=3,
        failed_attempts=(
            5
            if label == "brute_force"
            else 0
        ),
        privileged_target=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        source_port=12345,
        destination_port=22,
        has_source_ip=1,
        has_target_user=1,
        has_agent=1,
        mitre_id_count=1,
        rule_group_count=2,
        is_sudo_event=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        is_account_change_event=0,
        is_privilege_group_change=0,
        has_command=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
    )


def test_evaluate_predictions_returns_required_metrics():
    y_true = [
        "benign",
        "benign",
        "brute_force",
        "brute_force",
        "privilege_misuse",
        "privilege_misuse",
    ]

    y_pred = [
        "benign",
        "brute_force",
        "brute_force",
        "brute_force",
        "privilege_misuse",
        "benign",
    ]

    metrics = evaluate_predictions(
        y_true,
        y_pred,
    )

    assert set(
        metrics
    ) == {
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
        "per_class",
        "confusion_matrix",
        "support",
    }


def test_per_class_metrics_use_fixed_label_order():
    y_true = [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    y_pred = [
        "benign",
        "brute_force",
        "benign",
    ]

    metrics = evaluate_predictions(
        y_true,
        y_pred,
    )

    assert list(
        metrics["per_class"]
    ) == LABELS


def test_confusion_matrix_is_serializable_list():
    metrics = evaluate_predictions(
        [
            "benign",
            "brute_force",
            "privilege_misuse",
        ],
        [
            "benign",
            "brute_force",
            "privilege_misuse",
        ],
    )

    assert metrics[
        "confusion_matrix"
    ] == [
        [1, 0, 0],
        [0, 1, 0],
        [0, 0, 1],
    ]


def test_support_contains_counts_for_each_class():
    metrics = evaluate_predictions(
        [
            "benign",
            "benign",
            "brute_force",
            "privilege_misuse",
        ],
        [
            "benign",
            "benign",
            "brute_force",
            "privilege_misuse",
        ],
    )

    assert metrics["support"] == {
        "benign": 2,
        "brute_force": 1,
        "privilege_misuse": 1,
    }


def test_evaluate_by_dataset_returns_metrics_for_each_source():
    rows = [
        make_row(
            label="benign",
            source_dataset="cic_ids_2017",
            source_row_id="1",
        ),
        make_row(
            label="brute_force",
            source_dataset="cic_ids_2017",
            source_row_id="2",
        ),
        make_row(
            label="benign",
            source_dataset="adfa_ld",
            source_row_id="3",
        ),
        make_row(
            label="privilege_misuse",
            source_dataset="adfa_ld",
            source_row_id="4",
        ),
    ]

    y_pred = [
        "benign",
        "brute_force",
        "benign",
        "privilege_misuse",
    ]

    results = evaluate_by_dataset(
        rows,
        y_pred,
    )

    assert set(
        results
    ) == {
        "cic_ids_2017",
        "adfa_ld",
    }

    assert (
        results["cic_ids_2017"]
        ["accuracy"]
        == 1.0
    )

    assert (
        results["adfa_ld"]
        ["accuracy"]
        == 1.0
    )