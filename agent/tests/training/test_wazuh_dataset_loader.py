import json

from training.wazuh_dataset_loader import (
    load_labeled_wazuh_events,
)


def _sample_record() -> dict:
    return {
        "event": {
            "id": "test-alert-1",
            "rule": {
                "id": "5712",
                "level": 10,
                "frequency": 8,
                "groups": [
                    "syslog",
                    "sshd",
                    "authentication_failures",
                ],
                "mitre": {
                    "id": [
                        "T1110",
                    ],
                },
            },
            "agent": {
                "id": "000",
                "name": "wazuh.manager",
            },
            "data": {
                "srcip": "203.0.113.50",
            },
        },
        "label": "brute_force",
        "source_dataset": "wazuh_lab",
        "source_row_id": "sample-1",
    }


def test_load_labeled_wazuh_events_reads_jsonl(tmp_path):
    dataset_path = tmp_path / "dataset.jsonl"

    dataset_path.write_text(
        json.dumps(
            _sample_record()
        )
        + "\n",
        encoding="utf-8",
    )

    rows = load_labeled_wazuh_events(
        dataset_path
    )

    assert len(rows) == 1
    assert rows[0].label == "brute_force"
    assert rows[0].source_dataset == "wazuh_lab"
    assert rows[0].source_row_id == "sample-1"


def test_load_labeled_wazuh_events_accepts_utf8_bom(tmp_path):
    dataset_path = tmp_path / "dataset-with-bom.jsonl"

    dataset_path.write_text(
        json.dumps(
            _sample_record()
        )
        + "\n",
        encoding="utf-8-sig",
    )

    rows = load_labeled_wazuh_events(
        dataset_path
    )

    assert len(rows) == 1
    assert rows[0].label == "brute_force"