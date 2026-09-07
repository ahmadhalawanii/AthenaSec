import json
from pathlib import Path
from typing import Any

from training.behavior_manifest import (
    BehaviorReplay,
)
from training.wazuh_lab_scenarios import (
    get_scenario_by_name,
)


def find_latest_matching_alert(
    alerts: list[dict[str, Any]],
    rule_id: str,
    source_ip: str,
) -> dict[str, Any]:
    for alert in reversed(
        alerts
    ):
        current_rule_id = str(
            alert.get(
                "rule",
                {},
            ).get(
                "id",
                "",
            )
        )

        current_source_ip = str(
            alert.get(
                "data",
                {},
            ).get(
                "srcip",
                "",
            )
        )

        if (
            current_rule_id == rule_id
            and current_source_ip == source_ip
        ):
            return alert

    raise ValueError(
        "No matching Wazuh alert found"
    )


def build_labeled_record(
    event: dict[str, Any],
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> dict[str, Any]:
    return {
        "event": event,
        "label": label,
        "source_dataset": source_dataset,
        "source_row_id": source_row_id,
    }


def export_latest_matching_alert(
    alerts_path: str | Path,
    output_path: str | Path,
    rule_id: str,
    source_ip: str,
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> None:
    input_path = Path(
        alerts_path
    )

    output = Path(
        output_path
    )

    alerts: list[dict[str, Any]] = []

    with input_path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for line in file:
            stripped = line.strip()

            if not stripped:
                continue

            alerts.append(
                json.loads(
                    stripped
                )
            )

    event = find_latest_matching_alert(
        alerts=alerts,
        rule_id=rule_id,
        source_ip=source_ip,
    )

    record = build_labeled_record(
        event=event,
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write(
            json.dumps(
                record,
                separators=(
                    ",",
                    ":",
                ),
            )
        )
        file.write(
            "\n"
        )


def export_behavior_replay_capture(
    *,
    replay: BehaviorReplay,
    alerts_path: str | Path,
    output_path: str | Path,
) -> None:
    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    if scenario.label != replay.label:
        raise ValueError(
            "Wazuh scenario label mismatch: "
            f"manifest label={replay.label}, "
            f"scenario label={scenario.label}"
        )

    input_path = Path(
        alerts_path
    )

    output = Path(
        output_path
    )

    alerts: list[
        dict[str, Any]
    ] = []

    with input_path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for line in file:
            stripped = line.strip()

            if not stripped:
                continue

            alerts.append(
                json.loads(
                    stripped
                )
            )

    event = find_latest_matching_alert(
        alerts=alerts,
        rule_id=(
            scenario.expected_rule_id
        ),
        source_ip=(
            scenario.source_ip
        ),
    )

    record = {
        "event": event,
        "label": replay.label,
        "source_dataset": (
            replay.source_dataset
        ),
        "source_row_id": (
            replay.source_row_id
        ),
        "source_behavior": (
            replay.source_behavior
        ),
        "scenario_name": (
            replay.scenario_name
        ),
        "wazuh_source_dataset": (
            scenario.source_dataset
        ),
        "wazuh_source_row_id": (
            scenario.source_row_id
        ),
    }

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write(
            json.dumps(
                record,
                separators=(
                    ",",
                    ":",
                ),
            )
        )
        file.write(
            "\n"
        )