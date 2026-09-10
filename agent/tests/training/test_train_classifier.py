from pathlib import Path

import training.train_classifier as train_classifier_module

from training.data_contract import (
    TrainingRow,
)
from training.train_classifier import (
    train_classifier,
)


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


def _training_rows() -> list[TrainingRow]:
    rows = []

    for index in range(40):
        rows.append(
            _row(
                value=float(index + 1),
                label="benign",
                source_dataset="cic_ids_2017",
                source_row_id=f"benign-{index}",
            )
        )

    for index in range(40):
        rows.append(
            _row(
                value=float(index + 101),
                label="brute_force",
                source_dataset="cic_ids_2018",
                source_row_id=f"brute-{index}",
            )
        )

    for index in range(40):
        rows.append(
            _row(
                value=float(index + 201),
                label="privilege_misuse",
                source_dataset="adfa_ld",
                source_row_id=f"privilege-{index}",
            )
        )

    return rows


def test_training_runs_both_models():
    result = train_classifier(
        rows=_training_rows(),
        random_state=42,
    )

    assert (
        "logistic_regression"
        in result.model_metrics
    )

    assert (
        "random_forest"
        in result.model_metrics
    )


def test_training_returns_fitted_random_forest():
    result = train_classifier(
        rows=_training_rows(),
        random_state=42,
    )

    assert hasattr(
        result.random_forest_model,
        "classes_",
    )

    assert set(
        result.random_forest_model.classes_
    ) == {
        "benign",
        "brute_force",
        "privilege_misuse",
    }


def test_training_reports_test_metrics():
    result = train_classifier(
        rows=_training_rows(),
        random_state=42,
    )

    random_forest_metrics = (
        result.model_metrics[
            "random_forest"
        ]
    )

    assert "validation" in (
        random_forest_metrics
    )

    assert "test" in (
        random_forest_metrics
    )

    assert "macro_f1" in (
        random_forest_metrics[
            "test"
        ]
    )


def test_training_tracks_duplicate_count():
    rows = _training_rows()

    rows.append(
        rows[0]
    )

    result = train_classifier(
        rows=rows,
        random_state=42,
    )

    assert (
        result.duplicate_count
        == 1
    )


def test_training_from_replay_capture_file_uses_loaded_rows(
    tmp_path: Path,
    monkeypatch,
):
    captures_path = (
        tmp_path
        / "replay_captures.jsonl"
    )

    loaded_paths = []

    def fake_load_capture_rows(
        *,
        captures_path,
    ):
        loaded_paths.append(
            captures_path
        )

        return _training_rows()

    monkeypatch.setattr(
        train_classifier_module,
        "training_rows_from_behavior_replay_capture_file",
        fake_load_capture_rows,
        raising=False,
    )

    result = (
        train_classifier_module
        .train_classifier_from_behavior_replay_capture_file(
            captures_path=captures_path,
            random_state=42,
        )
    )

    assert loaded_paths == [
        captures_path
    ]

    assert set(
        result.random_forest_model.classes_
    ) == {
        "benign",
        "brute_force",
        "privilege_misuse",
    }

    assert (
        "random_forest"
        in result.model_metrics
    )

    assert (
        "logistic_regression"
        in result.model_metrics
    )


def test_deployment_random_forest_uses_all_deduplicated_rows(
    monkeypatch,
):
    rows = _training_rows()

    rows.append(
        rows[0]
    )

    observed = {}

    original_build_xy = (
        train_classifier_module.build_xy
    )

    def recording_build_xy(
        rows,
    ):
        observed["row_count"] = len(
            rows
        )

        return original_build_xy(
            rows
        )

    monkeypatch.setattr(
        train_classifier_module,
        "build_xy",
        recording_build_xy,
    )

    model = (
        train_classifier_module
        .fit_deployment_random_forest(
            rows=rows,
            random_state=42,
        )
    )

    assert observed["row_count"] == 120

    assert set(
        model.classes_
    ) == {
        "benign",
        "brute_force",
        "privilege_misuse",
    }