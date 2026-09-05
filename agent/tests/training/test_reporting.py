import json
from pathlib import Path

from training.reporting import (
    write_training_reports,
)


def test_metrics_report_is_written(
    tmp_path: Path,
):
    metrics = {
        "logistic_regression": {
            "test": {
                "macro_f1": 0.80,
            },
        },
        "random_forest": {
            "test": {
                "macro_f1": 0.90,
            },
        },
    }

    write_training_reports(
        output_dir=tmp_path,
        model_metrics=metrics,
        duplicate_count=7,
    )

    metrics_path = (
        tmp_path
        / "metrics.json"
    )

    assert metrics_path.exists()

    report = json.loads(
        metrics_path.read_text(
            encoding="utf-8"
        )
    )

    assert (
        report["duplicate_count"]
        == 7
    )

    assert (
        report["models"]
        == metrics
    )


def test_feature_mapping_report_matches_runtime_contract(
    tmp_path: Path,
):
    write_training_reports(
        output_dir=tmp_path,
        model_metrics={},
        duplicate_count=0,
    )

    mapping_path = (
        tmp_path
        / "feature_mapping.json"
    )

    assert mapping_path.exists()

    report = json.loads(
        mapping_path.read_text(
            encoding="utf-8"
        )
    )

    assert report[
        "feature_names"
    ] == [
        "rule_level",
        "rule_frequency",
        "failed_attempts",
        "privileged_target",
        "source_port",
        "destination_port",
        "has_source_ip",
        "has_target_user",
        "has_agent",
        "mitre_id_count",
        "rule_group_count",
        "is_sudo_event",
        "is_account_change_event",
        "is_privilege_group_change",
        "has_command",
    ]

    assert (
        report[
            "feature_source"
        ]
        == "AthenaSec Wazuh runtime feature extractor"
    )