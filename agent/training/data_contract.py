from dataclasses import dataclass

from app.ml.feature_extractor import (
    ML_FEATURE_NAMES,
)


TRAINING_LABELS = (
    "benign",
    "brute_force",
    "privilege_misuse",
)


@dataclass(frozen=True)
class TrainingRow:
    rule_level: float
    rule_frequency: float
    failed_attempts: float
    privileged_target: float
    source_port: float
    destination_port: float
    has_source_ip: float
    has_target_user: float
    has_agent: float
    mitre_id_count: float
    rule_group_count: float
    is_sudo_event: float
    is_account_change_event: float
    is_privilege_group_change: float
    has_command: float
    label: str
    source_dataset: str
    source_row_id: str


def training_feature_names() -> list[str]:
    return list(
        ML_FEATURE_NAMES
    )


def training_feature_vector(
    row: TrainingRow,
) -> list[float]:
    return [
        float(row.rule_level),
        float(row.rule_frequency),
        float(row.failed_attempts),
        float(row.privileged_target),
        float(row.source_port),
        float(row.destination_port),
        float(row.has_source_ip),
        float(row.has_target_user),
        float(row.has_agent),
        float(row.mitre_id_count),
        float(row.rule_group_count),
        float(row.is_sudo_event),
        float(
            row.is_account_change_event
        ),
        float(
            row.is_privilege_group_change
        ),
        float(row.has_command),
    ]