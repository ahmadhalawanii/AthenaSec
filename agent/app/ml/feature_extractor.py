from typing import Any

from app.schemas import SecurityAlertInput


ML_FEATURE_NAMES = [
    "rule_level",
    "rule_frequency",
    "failed_attempts",
    "privileged_target",
    "source_port",
    "destination_port",
    "has_source_ip",
    "has_target_user",
    "has_agent",
    "mitre_id_count",
    "rule_group_count",
]


def _number(
    value: Any,
) -> float:
    if value is None:
        return 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _flag(
    value: Any,
) -> float:
    return 1.0 if bool(value) else 0.0


def _count(
    value: Any,
) -> float:
    if not isinstance(value, list):
        return 0.0

    return float(
        len(value)
    )


def extract_ml_features(
    alert: SecurityAlertInput,
) -> dict[str, float]:
    metadata = alert.metadata

    values = {
        "rule_level": _number(
            metadata.get("rule_level")
        ),
        "rule_frequency": _number(
            metadata.get("rule_frequency")
        ),
        "failed_attempts": _number(
            metadata.get("failed_attempts")
        ),
        "privileged_target": _flag(
            metadata.get("privileged_target")
        ),
        "source_port": _number(
            metadata.get("source_port")
        ),
        "destination_port": _number(
            metadata.get("destination_port")
        ),
        "has_source_ip": _flag(
            metadata.get("source_ip")
        ),
        "has_target_user": _flag(
            metadata.get("target_user")
        ),
        "has_agent": _flag(
            metadata.get("agent_id")
        ),
        "mitre_id_count": _count(
            metadata.get("mitre_ids")
        ),
        "rule_group_count": _count(
            metadata.get("rule_groups")
        ),
    }

    return {
        feature_name: values[
            feature_name
        ]
        for feature_name in ML_FEATURE_NAMES
    }

def feature_vector_from_alert(
    alert: SecurityAlertInput,
) -> list[float]:
    features = extract_ml_features(
        alert
    )

    return [
        features[
            feature_name
        ]
        for feature_name in ML_FEATURE_NAMES
    ]