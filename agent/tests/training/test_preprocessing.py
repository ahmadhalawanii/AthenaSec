import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from training.data_contract import TrainingRow
from training.preprocessing import (
    build_logistic_pipeline,
    build_random_forest,
    build_xy,
)


def make_rows():
    return [
        TrainingRow(
            rule_level=1,
            rule_frequency=2,
            failed_attempts=0,
            privileged_target=0,
            source_port=10001,
            destination_port=443,
            has_source_ip=1,
            has_target_user=0,
            has_agent=1,
            mitre_id_count=0,
            rule_group_count=1,
            is_sudo_event=0,
            is_account_change_event=0,
            is_privilege_group_change=0,
            has_command=0,
            label="benign",
            source_dataset="fixture",
            source_row_id="1",
        ),
        TrainingRow(
            rule_level=8,
            rule_frequency=20,
            failed_attempts=18,
            privileged_target=1,
            source_port=10002,
            destination_port=22,
            has_source_ip=1,
            has_target_user=1,
            has_agent=1,
            mitre_id_count=1,
            rule_group_count=2,
            is_sudo_event=0,
            is_account_change_event=0,
            is_privilege_group_change=0,
            has_command=0,
            label="brute_force",
            source_dataset="fixture",
            source_row_id="2",
        ),
        TrainingRow(
            rule_level=12,
            rule_frequency=3,
            failed_attempts=0,
            privileged_target=1,
            source_port=10003,
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
            label="privilege_misuse",
            source_dataset="fixture",
            source_row_id="3",
        ),
    ]


def test_build_xy_returns_15_feature_columns():
    rows = make_rows()

    X, y = build_xy(
        rows
    )

    assert isinstance(
        X,
        np.ndarray,
    )

    assert X.shape == (
        3,
        15,
    )

    assert y.tolist() == [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]


def test_logistic_pipeline_contains_scaler():
    weights = {
        "benign": 1.0,
        "brute_force": 2.0,
        "privilege_misuse": 3.0,
    }

    pipeline = build_logistic_pipeline(
        weights
    )

    assert isinstance(
        pipeline,
        Pipeline,
    )

    assert isinstance(
        pipeline.named_steps[
            "scaler"
        ],
        StandardScaler,
    )

    assert (
        pipeline.named_steps[
            "classifier"
        ].class_weight
        == weights
    )


def test_random_forest_uses_class_weights():
    weights = {
        "benign": 1.0,
        "brute_force": 2.0,
        "privilege_misuse": 3.0,
    }

    model = build_random_forest(
        weights,
        random_state=42,
    )

    assert isinstance(
        model,
        RandomForestClassifier,
    )

    assert model.class_weight == weights

    assert model.random_state == 42


def test_random_forest_does_not_use_scaling_pipeline():
    weights = {
        "benign": 1.0,
        "brute_force": 1.0,
        "privilege_misuse": 1.0,
    }

    model = build_random_forest(
        weights
    )

    assert not isinstance(
        model,
        Pipeline,
    )