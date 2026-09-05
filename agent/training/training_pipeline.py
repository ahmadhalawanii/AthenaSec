from dataclasses import dataclass
from pathlib import Path

from training.artifact_export import (
    export_model_artifact,
)
from training.reporting import (
    write_training_reports,
)
from training.train_classifier import (
    train_classifier,
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


def run_training_pipeline(
    dataset_path: str | Path,
    output_dir: str | Path,
    model_version: str,
    random_state: int = 42,
) -> TrainingPipelineResult:
    rows = load_labeled_wazuh_events(
        dataset_path
    )

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

    export_model_artifact(
        model=(
            training_result.random_forest_model
        ),
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