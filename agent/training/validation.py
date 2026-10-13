import math

from training.data_contract import (
    TRAINING_LABELS,
    TrainingRow,
    training_feature_vector,
)


_BINARY_FIELDS = {
    "privileged_target",
    "has_source_ip",
    "has_target_user",
    "has_agent",
    "is_sudo_event",
    "is_account_change_event",
    "is_privilege_group_change",
    "has_command",
}

_NON_NEGATIVE_FIELDS = {
    "rule_level",
    "rule_frequency",
    "failed_attempts",
    "source_port",
    "destination_port",
    "mitre_id_count",
    "rule_group_count",
}


def validate_training_row(
    row: TrainingRow,
) -> None:
    for value in training_feature_vector(
        row
    ):
        if not math.isfinite(
            value
        ):
            raise ValueError(
                "Training feature values "
                "must be finite."
            )

    if row.label not in TRAINING_LABELS:
        raise ValueError(
            f"Unsupported label: "
            f"{row.label}"
        )

    if not row.source_dataset.strip():
        raise ValueError(
            "source_dataset "
            "must not be empty."
        )

    for field_name in _BINARY_FIELDS:
        value = getattr(
            row,
            field_name,
        )

        if value not in {
            0,
            1,
            0.0,
            1.0,
        }:
            raise ValueError(
                f"{field_name} "
                "must be binary."
            )

    for field_name in _NON_NEGATIVE_FIELDS:
        value = getattr(
            row,
            field_name,
        )

        if value < 0:
            raise ValueError(
                f"{field_name} "
                "must not be negative."
            )


def validate_training_rows(
    rows: list[TrainingRow],
) -> None:
    for row in rows:
        validate_training_row(
            row
        )