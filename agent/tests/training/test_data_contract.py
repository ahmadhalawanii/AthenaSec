from app.ml.feature_extractor import ML_FEATURE_NAMES
from training.data_contract import (
    TRAINING_LABELS,
    TrainingRow,
    training_feature_names,
    training_feature_vector,
)


def test_training_feature_names_match_runtime_contract():
    assert training_feature_names() == ML_FEATURE_NAMES


def test_training_labels_are_exact():
    assert TRAINING_LABELS == (
        "benign",
        "brute_force",
        "privilege_misuse",
    )


def test_training_row_produces_runtime_feature_order():
    row = TrainingRow(
        rule_level=10,
        rule_frequency=12,
        failed_attempts=11,
        privileged_target=1,
        source_port=54321,
        destination_port=22,
        has_source_ip=1,
        has_target_user=1,
        has_agent=1,
        mitre_id_count=2,
        rule_group_count=3,
        is_sudo_event=1,
        is_account_change_event=0,
        is_privilege_group_change=0,
        has_command=1,
        label="brute_force",
        source_dataset="fixture",
        source_row_id="row-1",
    )

    assert training_feature_vector(row) == [
        10.0,
        12.0,
        11.0,
        1.0,
        54321.0,
        22.0,
        1.0,
        1.0,
        1.0,
        2.0,
        3.0,
        1.0,
        0.0,
        0.0,
        1.0,
    ]


def test_source_metadata_is_not_part_of_feature_vector():
    row = TrainingRow(
        rule_level=1,
        rule_frequency=1,
        failed_attempts=0,
        privileged_target=0,
        source_port=0,
        destination_port=0,
        has_source_ip=0,
        has_target_user=0,
        has_agent=1,
        mitre_id_count=0,
        rule_group_count=1,
        is_sudo_event=0,
        is_account_change_event=0,
        is_privilege_group_change=0,
        has_command=0,
        label="benign",
        source_dataset="cmu",
        source_row_id="abc",
    )

    assert len(
        training_feature_vector(row)
    ) == len(
        ML_FEATURE_NAMES
    )