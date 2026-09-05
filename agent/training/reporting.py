import json
from pathlib import Path
from typing import Any

from training.data_contract import (
    training_feature_names,
)


def write_training_reports(
    output_dir: str | Path,
    model_metrics: dict[
        str,
        dict[str, object],
    ],
    duplicate_count: int,
) -> None:
    path = Path(
        output_dir
    )

    path.mkdir(
        parents=True,
        exist_ok=True,
    )

    metrics_report = {
        "duplicate_count": (
            duplicate_count
        ),
        "models": model_metrics,
    }

    feature_mapping_report = {
        "feature_names": (
            training_feature_names()
        ),
        "feature_source": (
            "AthenaSec Wazuh runtime "
            "feature extractor"
        ),
    }

    metrics_path = (
        path
        / "metrics.json"
    )

    feature_mapping_path = (
        path
        / "feature_mapping.json"
    )

    metrics_path.write_text(
        json.dumps(
            metrics_report,
            indent=2,
        ),
        encoding="utf-8",
    )

    feature_mapping_path.write_text(
        json.dumps(
            feature_mapping_report,
            indent=2,
        ),
        encoding="utf-8",
    )