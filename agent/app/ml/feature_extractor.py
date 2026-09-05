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
    "is_sudo_event",
    "is_account_change_event",
    "is_privilege_group_change",
    "has_command",
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


def _normalized_text(
    value: Any,
) -> str:
    if not isinstance(value, str):
        return ""

    return value.strip().lower()


def _is_sudo_event(
    metadata: dict[str, Any],
) -> float:
    decoder_name = _normalized_text(
        metadata.get("decoder_name")
    )

    decoder_parent = _normalized_text(
        metadata.get("decoder_parent")
    )

    return _flag(
        decoder_name == "sudo"
        or decoder_parent == "sudo"
    )


def _is_account_change_event(
    metadata: dict[str, Any],
) -> float:
    decoder_name = _normalized_text(
        metadata.get("decoder_name")
    )

    decoder_parent = _normalized_text(
        metadata.get("decoder_parent")
    )

    account_change_decoders = {
        "useradd",
        "usermod",
        "userdel",
        "gpasswd",
        "groupadd",
        "groupmod",
        "groupdel",
    }

    return _flag(
        decoder_name in account_change_decoders
        or decoder_parent
        in account_change_decoders
    )


def _is_privilege_group_change(
    metadata: dict[str, Any],
) -> float:
    target_group = _normalized_text(
        metadata.get("target_group")
    )

    privileged_groups = {
        "sudo",
        "wheel",
        "administrators",
        "admin",
    }

    return _flag(
        target_group
        in privileged_groups
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
        "is_sudo_event": (
            _is_sudo_event(
                metadata
            )
        ),
        "is_account_change_event": (
            _is_account_change_event(
                metadata
            )
        ),
        "is_privilege_group_change": (
            _is_privilege_group_change(
                metadata
            )
        ),
        "has_command": _flag(
            metadata.get("command")
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