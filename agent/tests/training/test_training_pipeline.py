import json
from pathlib import Path

from training import (
    training_pipeline as training_pipeline_module,
)

from app.ml.model_loader import (
    load_runtime_classifier,
)
from training.training_pipeline import (
    run_training_pipeline,
)
from training.wazuh_dataset_loader import (
    load_labeled_wazuh_events,
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
        classifier.model.named_steps[
            "classifier"
        ].__class__.__name__
        == "LogisticRegression"
    )

    assert (
        result.artifact_path
        == artifact_path
    )

    assert (
        "random_forest"
        in result.model_metrics
    )


def test_behavior_replay_capture_pipeline_exports_runtime_model_and_reports(
    tmp_path: Path,
    monkeypatch,
):
    dataset_path = (
        tmp_path
        / "events.jsonl"
    )

    captures_path = (
        tmp_path
        / "replay_captures_v3.jsonl"
    )

    output_dir = (
        tmp_path
        / "capture-output"
    )

    _write_dataset(
        dataset_path
    )

    rows = load_labeled_wazuh_events(
        dataset_path
    )

    captures_path.write_text(
        "{}\n",
        encoding="utf-8",
    )

    observed = {}

    def fake_capture_loader(
        *,
        captures_path,
    ):
        observed[
            "captures_path"
        ] = Path(
            captures_path
        )

        return rows

    monkeypatch.setattr(
        training_pipeline_module,
        (
            "training_rows_from_"
            "behavior_replay_capture_file"
        ),
        fake_capture_loader,
        raising=False,
    )

    result = (
        training_pipeline_module
        .run_training_pipeline_from_behavior_replay_capture_file(
            captures_path=captures_path,
            output_dir=output_dir,
            model_version=(
                "athenasec-classifier-v3"
            ),
            random_state=42,
        )
    )

    assert (
        observed[
            "captures_path"
        ]
        == captures_path
    )

    artifact_path = (
        output_dir
        / "athenasec-classifier-v3.pkl"
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
        == "athenasec-classifier-v3"
    )

    assert set(
        classifier.model.classes_
    ) == {
        "benign",
        "brute_force",
        "privilege_misuse",
    }

    assert (
        classifier.model.named_steps[
            "classifier"
        ].__class__.__name__
        == "LogisticRegression"
    )

    assert (
        classifier.model.named_steps[
            "classifier"
        ].C
        == 10.0
    )

    assert (
        result.artifact_path
        == artifact_path
    )

    assert (
        "random_forest"
        in result.model_metrics
    )