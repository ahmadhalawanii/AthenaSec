from typing import Any

from app.ml.feature_extractor import (
    extract_ml_features,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)
from training.data_contract import (
    TrainingRow,
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