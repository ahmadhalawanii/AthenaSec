from dataclasses import dataclass
from pathlib import Path

from training.artifact_export import (
    export_model_artifact,
)
from training.data_contract import (
    TrainingRow,
)
from training.reporting import (
    write_training_reports,
)
from training.train_classifier import (
    fit_deployment_logistic_regression,
    train_classifier,
)
from training.wazuh_bridge import (
    training_rows_from_behavior_replay_capture_file,
)
from training.wazuh_dataset_loader import (
    load_labeled_wazuh_events,
)


@dataclass(frozen=True)
class TrainingPipelineResult:
    artifact_path: Path
    model_metrics: dict[
        str,
        dict[str, object],
    ]
    duplicate_count: int


def _run_training_pipeline_from_rows(
    *,
    rows: list[TrainingRow],
    output_dir: str | Path,
    model_version: str,
    random_state: int,
) -> TrainingPipelineResult:
    training_result = train_classifier(
        rows=rows,
        random_state=random_state,
    )

    output_path = Path(
        output_dir
    )

    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact_path = (
        output_path
        / f"{model_version}.pkl"
    )

    deployment_model = (
        fit_deployment_logistic_regression(
            rows=rows,
            random_state=random_state,
        )
    )

    export_model_artifact(
        model=deployment_model,
        artifact_path=artifact_path,
        model_version=model_version,
    )

    write_training_reports(
        output_dir=output_path,
        model_metrics=(
            training_result.model_metrics
        ),
        duplicate_count=(
            training_result.duplicate_count
        ),
    )

    return TrainingPipelineResult(
        artifact_path=artifact_path,
        model_metrics=(
            training_result.model_metrics
        ),
        duplicate_count=(
            training_result.duplicate_count
        ),
    )


def run_training_pipeline(
    dataset_path: str | Path,
    output_dir: str | Path,
    model_version: str,
    random_state: int = 42,
) -> TrainingPipelineResult:
    rows = load_labeled_wazuh_events(
        dataset_path
    )

    return _run_training_pipeline_from_rows(
        rows=rows,
        output_dir=output_dir,
        model_version=model_version,
        random_state=random_state,
    )


def run_training_pipeline_from_behavior_replay_capture_file(
    captures_path: str | Path,
    output_dir: str | Path,
    model_version: str,
    random_state: int = 42,
) -> TrainingPipelineResult:
    rows = (
        training_rows_from_behavior_replay_capture_file(
            captures_path=captures_path,
        )
    )

    return _run_training_pipeline_from_rows(
        rows=rows,
        output_dir=output_dir,
        model_version=model_version,
        random_state=random_state,
    )
