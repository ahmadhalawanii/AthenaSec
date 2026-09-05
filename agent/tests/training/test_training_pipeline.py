import json
from pathlib import Path

from app.ml.model_loader import (
    load_runtime_classifier,
)
from training.training_pipeline import (
    run_training_pipeline,
)


def _event(
    identifier: str,
    label: str,
    index: int,
) -> dict:
    if label == "benign":
        return {
            "id": identifier,
            "rule": {
                "level": 3 + (index % 2),
                "frequency": index + 1,
                "groups": [
                    "syslog",
                ],
            },
            "agent": {
                "id": "001",
                "name": "test-agent",
            },
        }

    if label == "brute_force":
        return {
            "id": identifier,
            "rule": {
                "level": 10,
                "frequency": 5 + index,
                "groups": [
                    "authentication_failed",
                    "sshd",
                ],
                "mitre": {
                    "id": [
                        "T1110",
                    ],
                },
            },
            "data": {
                "srcip": (
                    f"192.0.2.{index + 1}"
                ),
                "srcport": str(
                    40000 + index
                ),
                "dstport": "22",
                "dstuser": "root",
            },
            "agent": {
                "id": "002",
                "name": "ssh-server",
            },
        }

    return {
        "id": identifier,
        "rule": {
            "level": 12,
            "groups": [
                "authentication_success",
                "privilege",
            ],
            "mitre": {
                "id": [
                    "T1078",
                ],
            },
        },
        "data": {
            "srcip": (
                f"198.51.100.{index + 1}"
            ),
            "srcport": str(
                50000 + index
            ),
            "dstport": "22",
            "dstuser": "administrator",
        },
        "agent": {
            "id": "003",
            "name": "admin-server",
        },
    }


def _write_dataset(
    path: Path,
) -> None:
    records = []

    configuration = [
        (
            "benign",
            "cic_ids_2017",
        ),
        (
            "brute_force",
            "cic_ids_2018",
        ),
        (
            "privilege_misuse",
            "adfa_ld",
        ),
    ]

    for label, source_dataset in configuration:
        for index in range(30):
            records.append(
                {
                    "label": label,
                    "source_dataset": (
                        source_dataset
                    ),
                    "source_row_id": (
                        f"{label}-{index}"
                    ),
                    "event": _event(
                        identifier=(
                            f"{label}-{index}"
                        ),
                        label=label,
                        index=index,
                    ),
                }
            )

    path.write_text(
        "\n".join(
            json.dumps(record)
            for record in records
        ),
        encoding="utf-8",
    )


def test_training_pipeline_exports_runtime_model_and_reports(
    tmp_path: Path,
):
    dataset_path = (
        tmp_path
        / "events.jsonl"
    )

    output_dir = (
        tmp_path
        / "output"
    )

    _write_dataset(
        dataset_path
    )

    result = run_training_pipeline(
        dataset_path=dataset_path,
        output_dir=output_dir,
        model_version=(
            "athenasec-classifier-v1"
        ),
        random_state=42,
    )

    artifact_path = (
        output_dir
        / "athenasec-classifier-v1.pkl"
    )

    assert artifact_path.exists()

    assert (
        output_dir
        / "metrics.json"
    ).exists()

    assert (
        output_dir
        / "feature_mapping.json"
    ).exists()

    classifier = (
        load_runtime_classifier(
            artifact_path
        )
    )

    assert (
        classifier.model_version
        == "athenasec-classifier-v1"
    )

    assert set(
        classifier.model.classes_
    ) == {
        "benign",
        "brute_force",
        "privilege_misuse",
    }

    assert (
        result.artifact_path
        == artifact_path
    )

    assert (
        "random_forest"
        in result.model_metrics
    )