import math

import pytest

from training.data_contract import TrainingRow
from training.validation import validate_training_row


def build_valid_row(
    **overrides,
) -> TrainingRow:
    values = {
        "rule_level": 5,
        "rule_frequency": 3,
        "failed_attempts": 2,
        "privileged_target": 0,
        "source_port": 12345,
        "destination_port": 22,
        "has_source_ip": 1,
        "has_target_user": 1,
        "has_agent": 1,
        "mitre_id_count": 1,
        "rule_group_count": 2,
        "is_sudo_event": 0,
        "is_account_change_event": 0,
        "is_privilege_group_change": 0,
        "has_command": 0,
        "label": "brute_force",
        "source_dataset": "fixture",
        "source_row_id": "1",
    }

    values.update(
        overrides
    )

    return TrainingRow(
        **values
    )


def test_valid_training_row_passes_validation():
    row = build_valid_row()

    validate_training_row(
        row
    )


def test_validation_rejects_nan():
    row = build_valid_row(
        rule_level=math.nan
    )

    with pytest.raises(
        ValueError,
        match="finite",
    ):
        validate_training_row(
            row
        )


def test_validation_rejects_infinity():
    row = build_valid_row(
        failed_attempts=math.inf
    )

    with pytest.raises(
        ValueError,
        match="finite",
    ):
        validate_training_row(
            row
        )


def test_validation_rejects_unsupported_label():
    row = build_valid_row(
        label="malware"
    )

    with pytest.raises(
        ValueError,
        match="label",
    ):
        validate_training_row(
            row
        )


def test_validation_rejects_empty_source_dataset():
    row = build_valid_row(
        source_dataset="   "
    )

    with pytest.raises(
        ValueError,
        match="source_dataset",
    ):
        validate_training_row(
            row
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "privileged_target",
        "has_source_ip",
        "has_target_user",
        "has_agent",
        "is_sudo_event",
        "is_account_change_event",
        "is_privilege_group_change",
        "has_command",
    ],
)
def test_validation_rejects_non_binary_flags(
    field_name,
):
    row = build_valid_row(
        **{
            field_name: 2,
        }
    )

    with pytest.raises(
        ValueError,
        match=field_name,
    ):
        validate_training_row(
            row
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "rule_level",
        "rule_frequency",
        "failed_attempts",
        "source_port",
        "destination_port",
        "mitre_id_count",
        "rule_group_count",
    ],
)
def test_validation_rejects_negative_numeric_values(
    field_name,
):
    row = build_valid_row(
        **{
            field_name: -1,
        }
    )

    with pytest.raises(
        ValueError,
        match=field_name,
    ):
        validate_training_row(
            row
        )