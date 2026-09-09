import json

import pytest
from training import wazuh_lab_capture
from training.behavior_manifest import (
    BehaviorReplay,
    behavior_replay_variation,
)
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


def test_export_behavior_replay_capture_preserves_raw_alert_and_provenance(
    tmp_path,
):
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id=(
            "Tuesday-WorkingHours."
            "pcap_ISCX.csv:12345"
        ),
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    alerts_path = (
        tmp_path
        / "alerts.json"
    )

    output_path = (
        tmp_path
        / "replay_capture.jsonl"
    )

    alerts = [
        _alert(
            alert_id="unrelated",
            rule_id="5712",
            source_ip="203.0.113.50",
        ),
        _alert(
            alert_id="matching",
            rule_id="5763",
            source_ip=(
                __import__(
                    "training.behavior_manifest",
                    fromlist=[
                        "behavior_replay_variation"
                    ],
                )
                .behavior_replay_variation(
                    replay
                )["source_ip"]
            ),
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

    (
        wazuh_lab_capture
        .export_behavior_replay_capture(
            replay=replay,
            alerts_path=alerts_path,
            output_path=output_path,
        )
    )

    record = json.loads(
        output_path.read_text(
            encoding="utf-8",
        )
    )

    assert (
        record["event"]["id"]
        == "matching"
    )

    assert (
        record["label"]
        == "brute_force"
    )

    assert (
        record["source_dataset"]
        == "cic_ids_2017"
    )

    assert (
        record["source_row_id"]
        == replay.source_row_id
    )

    assert (
        record["source_behavior"]
        == "SSH-Patator"
    )

    assert (
        record["scenario_name"]
        == "ssh_root_password_bruteforce"
    )

    assert (
        record["wazuh_source_dataset"]
        == "wazuh_lab"
    )

    assert (
        record["wazuh_source_row_id"]
        == (
            "ssh_root_password_"
            "bruteforce_002"
        )
    )


def test_export_behavior_replay_capture_rejects_scenario_label_mismatch(
    tmp_path,
):
    replay = BehaviorReplay(
        label="benign",
        source_dataset="cic_ids_2017",
        source_row_id="cic2017:mismatch",
        source_behavior="BENIGN",
        scenario_name=(
            "ssh_root_password_bruteforce"
        ),
    )

    alerts_path = (
        tmp_path
        / "alerts.json"
    )

    output_path = (
        tmp_path
        / "replay_capture.jsonl"
    )

    alerts_path.write_text(
        json.dumps(
            _alert(
                alert_id="matching",
                rule_id="5763",
                source_ip="198.51.100.25",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=(
            "Wazuh scenario label mismatch"
        ),
    ):
        (
            wazuh_lab_capture
            .export_behavior_replay_capture(
                replay=replay,
                alerts_path=alerts_path,
                output_path=output_path,
            )
        )

    assert not output_path.exists()


def test_export_behavior_replay_capture_uses_deterministic_ssh_variation(
    tmp_path,
):
    replay = BehaviorReplay(
        label="brute_force",
        source_dataset="cic_ids_2017",
        source_row_id="sample.csv:100",
        source_behavior="SSH-Patator",
        scenario_name=(
            "ssh_invalid_user_bruteforce"
        ),
    )

    variation = (
        behavior_replay_variation(
            replay
        )
    )

    alerts_path = (
        tmp_path
        / "alerts.json"
    )

    output_path = (
        tmp_path
        / "replay_capture.jsonl"
    )

    varied_source_ip = (
        variation["source_ip"]
    )

    alerts_path.write_text(
        json.dumps(
            _alert(
                alert_id="varied-match",
                rule_id="5712",
                source_ip=(
                    varied_source_ip
                ),
            )
        )
        + "\n",
        encoding="utf-8",
    )

    (
        wazuh_lab_capture
        .export_behavior_replay_capture(
            replay=replay,
            alerts_path=alerts_path,
            output_path=output_path,
        )
    )

    record = json.loads(
        output_path.read_text(
            encoding="utf-8",
        )
    )

    assert (
        record["event"]["id"]
        == "varied-match"
    )

    assert (
        record["event"]["data"]["srcip"]
        == varied_source_ip
    )

def test_wazuh_replay_rule_cooldown_matches_known_lab_rules():
    from training.wazuh_lab_capture import (
        wazuh_replay_rule_cooldown_seconds,
    )

    assert (
        wazuh_replay_rule_cooldown_seconds("5712")
        == 60
    )
    assert (
        wazuh_replay_rule_cooldown_seconds("5763")
        == 60
    )
    assert (
        wazuh_replay_rule_cooldown_seconds("5720")
        == 0
    )


def test_wazuh_replay_remaining_cooldown_seconds():
    from training.wazuh_lab_capture import (
        wazuh_replay_remaining_cooldown_seconds,
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5712",
            elapsed_seconds=0,
        )
        == 60
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5712",
            elapsed_seconds=25,
        )
        == 35
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5763",
            elapsed_seconds=59,
        )
        == 1
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5763",
            elapsed_seconds=60,
        )
        == 0
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5720",
            elapsed_seconds=0,
        )
        == 0
    )

    assert (
        wazuh_replay_remaining_cooldown_seconds(
            rule_id="5712",
            elapsed_seconds=90,
        )
        == 0
    )
