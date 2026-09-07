from typing import Any

from app.ml.feature_extractor import (
    extract_ml_features,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)
from training.behavior_manifest import (
    BehaviorReplay,
)
from training.data_contract import (
    TrainingRow,
)
from training.wazuh_lab_capture import (
    find_latest_matching_alert,
)
from training.wazuh_lab_scenarios import (
    get_scenario_by_name,
)


def training_row_from_wazuh_event(
    event: dict[str, Any],
    label: str,
    source_dataset: str,
    source_row_id: str,
) -> TrainingRow:
    alert = parse_wazuh_alert(
        event
    )

    features = extract_ml_features(
        alert
    )

    return TrainingRow(
        rule_level=features[
            "rule_level"
        ],
        rule_frequency=features[
            "rule_frequency"
        ],
        failed_attempts=features[
            "failed_attempts"
        ],
        privileged_target=features[
            "privileged_target"
        ],
        source_port=features[
            "source_port"
        ],
        destination_port=features[
            "destination_port"
        ],
        has_source_ip=features[
            "has_source_ip"
        ],
        has_target_user=features[
            "has_target_user"
        ],
        has_agent=features[
            "has_agent"
        ],
        mitre_id_count=features[
            "mitre_id_count"
        ],
        rule_group_count=features[
            "rule_group_count"
        ],
        is_sudo_event=features[
            "is_sudo_event"
        ],
        is_account_change_event=features[
            "is_account_change_event"
        ],
        is_privilege_group_change=features[
            "is_privilege_group_change"
        ],
        has_command=features[
            "has_command"
        ],
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
    )


def training_row_from_behavior_replay_alerts(
    *,
    replay: BehaviorReplay,
    alerts: list[dict[str, Any]],
) -> TrainingRow:
    scenario = get_scenario_by_name(
        replay.scenario_name
    )

    if scenario.label != replay.label:
        raise ValueError(
            "Wazuh scenario label mismatch: "
            f"manifest label={replay.label}, "
            f"scenario label={scenario.label}"
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

    return training_row_from_wazuh_event(
        event=event,
        label=replay.label,
        source_dataset=(
            replay.source_dataset
        ),
        source_row_id=(
            replay.source_row_id
        ),
    )

def training_rows_from_behavior_replay_alert_batches(
    *,
    replay_alert_batches: list[
        tuple[
            BehaviorReplay,
            list[dict[str, Any]],
        ]
    ],
) -> list[TrainingRow]:
    rows: list[TrainingRow] = []

    for replay, alerts in replay_alert_batches:
        try:
            row = (
                training_row_from_behavior_replay_alerts(
                    replay=replay,
                    alerts=alerts,
                )
            )
        except ValueError as exc:
            raise ValueError(
                "Failed behavior replay "
                f"{replay.source_dataset} "
                f"{replay.source_row_id}: "
                f"{exc}"
            ) from exc

        rows.append(
            row
        )

    return rows