from training.cross_dataset import (
    evaluate_leave_one_dataset_out,
)
from training.data_contract import (
    TrainingRow,
)


DATASETS = [
    "cic_ids_2017",
    "cic_ids_2018",
    "adfa_ld",
    "cmu_insider",
]

LABELS = [
    "benign",
    "brute_force",
    "privilege_misuse",
]


def _row(
    value: float,
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> TrainingRow:
    return TrainingRow(
        rule_level=value,
        rule_frequency=value,
        failed_attempts=value,
        privileged_target=(
            1.0
            if label == "privilege_misuse"
            else 0.0
        ),
        source_port=value,
        destination_port=value,
        has_source_ip=1.0,
        has_target_user=1.0,
        has_agent=1.0,
        mitre_id_count=value,
        rule_group_count=value,
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

    label_offsets = {
        "benign": 0.0,
        "brute_force": 100.0,
        "privilege_misuse": 200.0,
    }

    for dataset_index, dataset in enumerate(
        DATASETS
    ):
        for label in LABELS:
            for row_index in range(10):
                value = (
                    label_offsets[label]
                    + float(row_index)
                    + float(dataset_index) / 100.0
                )

                rows.append(
                    _row(
                        value=value,
                        label=label,
                        source_dataset=dataset,
                        source_row_id=(
                            f"{dataset}-"
                            f"{label}-"
                            f"{row_index}"
                        ),
                    )
                )

    return rows


def test_each_dataset_is_evaluated_as_held_out():
    results = evaluate_leave_one_dataset_out(
        rows=_rows(),
        random_state=42,
    )

    assert set(
        results
    ) == set(
        DATASETS
    )


def test_held_out_results_include_required_metrics():
    results = evaluate_leave_one_dataset_out(
        rows=_rows(),
        random_state=42,
    )

    for dataset in DATASETS:
        metrics = results[
            dataset
        ]

        assert "accuracy" in metrics
        assert "macro_f1" in metrics
        assert "per_class" in metrics
        assert "confusion_matrix" in metrics

        assert metrics[
            "support"
        ] == {
            "benign": 10,
            "brute_force": 10,
            "privilege_misuse": 10,
        }