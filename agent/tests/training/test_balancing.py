from training.balancing import (
    class_weight_map,
    undersample_benign,
)
from training.data_contract import TrainingRow


def make_row(
    *,
    label: str,
    source_row_id: str,
) -> TrainingRow:
    return TrainingRow(
        rule_level=5,
        rule_frequency=3,
        failed_attempts=(
            5
            if label == "brute_force"
            else 0
        ),
        privileged_target=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        source_port=12345,
        destination_port=22,
        has_source_ip=1,
        has_target_user=1,
        has_agent=1,
        mitre_id_count=1,
        rule_group_count=2,
        is_sudo_event=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        is_account_change_event=0,
        is_privilege_group_change=0,
        has_command=(
            1
            if label == "privilege_misuse"
            else 0
        ),
        label=label,
        source_dataset="fixture",
        source_row_id=source_row_id,
    )


def test_minority_classes_receive_larger_weight():
    rows = []

    for index in range(30):
        rows.append(
            make_row(
                label="benign",
                source_row_id=f"b-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="brute_force",
                source_row_id=f"bf-{index}",
            )
        )

    for index in range(5):
        rows.append(
            make_row(
                label="privilege_misuse",
                source_row_id=f"pm-{index}",
            )
        )

    weights = class_weight_map(
        rows
    )

    assert (
        weights["privilege_misuse"]
        > weights["brute_force"]
        > weights["benign"]
    )


def test_undersampling_is_deterministic():
    rows = []

    for index in range(50):
        rows.append(
            make_row(
                label="benign",
                source_row_id=f"b-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="brute_force",
                source_row_id=f"bf-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="privilege_misuse",
                source_row_id=f"pm-{index}",
            )
        )

    first = undersample_benign(
        rows,
        max_ratio=2.0,
        random_state=42,
    )

    second = undersample_benign(
        rows,
        max_ratio=2.0,
        random_state=42,
    )

    assert first == second


def test_attack_rows_are_never_removed():
    rows = []

    attack_rows = []

    for index in range(40):
        rows.append(
            make_row(
                label="benign",
                source_row_id=f"b-{index}",
            )
        )

    for index in range(5):
        row = make_row(
            label="brute_force",
            source_row_id=f"bf-{index}",
        )

        rows.append(
            row
        )

        attack_rows.append(
            row
        )

    for index in range(5):
        row = make_row(
            label="privilege_misuse",
            source_row_id=f"pm-{index}",
        )

        rows.append(
            row
        )

        attack_rows.append(
            row
        )

    balanced = undersample_benign(
        rows,
        max_ratio=2.0,
        random_state=42,
    )

    for row in attack_rows:
        assert row in balanced


def test_benign_is_reduced_to_configured_ratio():
    rows = []

    for index in range(100):
        rows.append(
            make_row(
                label="benign",
                source_row_id=f"b-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="brute_force",
                source_row_id=f"bf-{index}",
            )
        )

    for index in range(5):
        rows.append(
            make_row(
                label="privilege_misuse",
                source_row_id=f"pm-{index}",
            )
        )

    balanced = undersample_benign(
        rows,
        max_ratio=3.0,
        random_state=42,
    )

    benign_count = sum(
        1
        for row in balanced
        if row.label == "benign"
    )

    assert benign_count == 30


def test_benign_is_not_reduced_when_already_within_ratio():
    rows = []

    for index in range(20):
        rows.append(
            make_row(
                label="benign",
                source_row_id=f"b-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="brute_force",
                source_row_id=f"bf-{index}",
            )
        )

    for index in range(10):
        rows.append(
            make_row(
                label="privilege_misuse",
                source_row_id=f"pm-{index}",
            )
        )

    balanced = undersample_benign(
        rows,
        max_ratio=3.0,
        random_state=42,
    )

    assert balanced == rows