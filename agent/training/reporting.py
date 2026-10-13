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


def write_model_selection_report(
    output_dir: str | Path,
    strict_lodo_results: dict[
        str,
        object,
    ],
    selection: dict[
        str,
        object,
    ],
) -> Path:
    path = Path(
        output_dir
    )

    path.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "evaluation": (
            "strict_vector_disjoint_"
            "leave_one_dataset_out"
        ),
        "selected_model": (
            selection[
                "selected_model"
            ]
        ),
        "selection_rule": (
            selection[
                "selection_rule"
            ]
        ),
        "ranking": (
            selection[
                "ranking"
            ]
        ),
        "selected_metrics": (
            selection[
                "selected_metrics"
            ]
        ),
        "strict_lodo": (
            strict_lodo_results
        ),
    }

    report_path = (
        path
        / "model_selection.json"
    )

    report_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    return report_path
