import json

import pytest

from training.wazuh_lab_capture import (
    build_labeled_record,
    export_latest_matching_alert,
    find_latest_matching_alert,
)


def _alert(
    *,
    alert_id: str,
    rule_id: str,
    source_ip: str,
) -> dict:
    return {
        "id": alert_id,
        "rule": {
            "id": rule_id,
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
            "srcip": source_ip,
        },
    }


def test_find_latest_matching_alert_returns_latest_match():
    alerts = [
        _alert(
            alert_id="first",
            rule_id="5712",
            source_ip="203.0.113.50",
        ),
        _alert(
            alert_id="unrelated",
            rule_id="5763",
            source_ip="198.51.100.25",
        ),
        _alert(
            alert_id="latest",
            rule_id="5712",
            source_ip="203.0.113.50",
        ),
    ]

    result = find_latest_matching_alert(
        alerts=alerts,
        rule_id="5712",
        source_ip="203.0.113.50",
    )

    assert result["id"] == "latest"


def test_find_latest_matching_alert_rejects_missing_match():
    alerts = [
        _alert(
            alert_id="only",
            rule_id="5712",
            source_ip="203.0.113.50",
        ),
    ]

    with pytest.raises(
        ValueError,
        match="No matching Wazuh alert",
    ):
        find_latest_matching_alert(
            alerts=alerts,
            rule_id="5763",
            source_ip="198.51.100.25",
        )


def test_build_labeled_record_preserves_raw_wazuh_event():
    alert = _alert(
        alert_id="alert-1",
        rule_id="5763",
        source_ip="198.51.100.25",
    )

    result = build_labeled_record(
        event=alert,
        label="brute_force",
        source_dataset="wazuh_lab",
        source_row_id="sample-002",
    )

    assert result == {
        "event": alert,
        "label": "brute_force",
        "source_dataset": "wazuh_lab",
        "source_row_id": "sample-002",
    }

    assert json.dumps(result)


def test_export_latest_matching_alert_writes_latest_match(
    tmp_path,
):
    alerts_path = tmp_path / "alerts.json"
    output_path = tmp_path / "training.jsonl"

    alerts = [
        _alert(
            alert_id="old",
            rule_id="5763",
            source_ip="198.51.100.25",
        ),
        _alert(
            alert_id="other",
            rule_id="5712",
            source_ip="203.0.113.50",
        ),
        _alert(
            alert_id="latest",
            rule_id="5763",
            source_ip="198.51.100.25",
        ),
    ]

    alerts_path.write_text(
        "\n".join(
            json.dumps(alert)
            for alert in alerts
        )
        + "\n",
        encoding="utf-8",
    )

    export_latest_matching_alert(
        alerts_path=alerts_path,
        output_path=output_path,
        rule_id="5763",
        source_ip="198.51.100.25",
        label="brute_force",
        source_dataset="wazuh_lab",
        source_row_id="sample-002",
    )

    record = json.loads(
        output_path.read_text(
            encoding="utf-8",
        )
    )

    assert record["event"]["id"] == "latest"
    assert record["label"] == "brute_force"
    assert record["source_dataset"] == "wazuh_lab"
    assert record["source_row_id"] == "sample-002"


def test_export_latest_matching_alert_writes_utf8_without_bom(
    tmp_path,
):
    alerts_path = tmp_path / "alerts.json"
    output_path = tmp_path / "training.jsonl"

    alerts_path.write_text(
        json.dumps(
            _alert(
                alert_id="match",
                rule_id="5720",
                source_ip="192.0.2.80",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    export_latest_matching_alert(
        alerts_path=alerts_path,
        output_path=output_path,
        rule_id="5720",
        source_ip="192.0.2.80",
        label="brute_force",
        source_dataset="wazuh_lab",
        source_row_id="sample-003",
    )

    raw = output_path.read_bytes()

    assert not raw.startswith(
        b"\xef\xbb\xbf"
    )
    assert raw.endswith(
        b"\n"
    )


def test_find_latest_matching_alert_allows_empty_source_ip_filter():
    alerts = [
        _alert(
            alert_id="old",
            rule_id="5405",
            source_ip="",
        ),
        _alert(
            alert_id="latest",
            rule_id="5405",
            source_ip="",
        ),
    ]

    result = find_latest_matching_alert(
        alerts=alerts,
        rule_id="5405",
        source_ip="",
    )

    assert result["id"] == "latest"