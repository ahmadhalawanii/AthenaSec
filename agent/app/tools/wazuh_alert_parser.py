from typing import Any

from app.schemas import SecurityAlertInput


PRIVILEGED_USERS = {
    "root",
    "administrator",
    "admin",
}


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    if value is None:
        return []

    return [value]


def _as_int(value: Any) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _derive_failed_attempts(
    rule: dict[str, Any],
) -> int | None:
    rule_id = str(
        rule.get("id") or ""
    )

    groups = {
        str(group)
        for group in _as_list(
            rule.get("groups")
        )
    }

    frequency = _as_int(
        rule.get("frequency")
    )

    authentication_failure_groups = {
        "authentication_failed",
        "authentication_failures",
    }

    is_authentication_failure = bool(
        groups
        & authentication_failure_groups
    )

    known_brute_force_rules = {
        "5712",
        "5720",
    }

    if (
        frequency is not None
        and (
            is_authentication_failure
            or rule_id in known_brute_force_rules
        )
    ):
        return frequency

    return None


def _derive_privileged_target(
    target_user: Any,
) -> bool:
    if not isinstance(target_user, str):
        return False

    return (
        target_user.strip().lower()
        in PRIVILEGED_USERS
    )


def parse_wazuh_alert(
    payload: dict[str, Any],
) -> SecurityAlertInput:
    index_source = payload.get("_source")

    if isinstance(index_source, dict):
        alert_data = index_source
    else:
        alert_data = payload

    rule = _as_dict(
        alert_data.get("rule")
    )

    agent = _as_dict(
        alert_data.get("agent")
    )

    data = _as_dict(
        alert_data.get("data")
    )

    decoder = _as_dict(
        alert_data.get("decoder")
    )

    mitre = _as_dict(
        rule.get("mitre")
    )

    index_document_id = payload.get("_id")
    raw_alert_id = alert_data.get("id")

    identifier = (
        index_document_id
        or raw_alert_id
    )

    if not identifier:
        raise ValueError(
            "Wazuh alert requires an identifier."
        )

    index_name = payload.get("_index")

    if (
        index_document_id
        and index_name
    ):
        alert_id = (
            f"{index_name}:"
            f"{index_document_id}"
        )
    else:
        alert_id = (
            f"wazuh:{identifier}"
        )

    full_log = alert_data.get("full_log")
    description = rule.get("description")

    event_text = (
        full_log
        or description
        or "Wazuh security alert"
    )

    target_user = (
        data.get("dstuser")
        or data.get("user")
    )

    failed_attempts = (
        _derive_failed_attempts(rule)
    )

    privileged_target = (
        _derive_privileged_target(
            target_user
        )
    )

    metadata = {
        "wazuh_alert_id": raw_alert_id,
        "wazuh_document_id": (
            index_document_id
        ),
        "wazuh_index": index_name,

        "timestamp": alert_data.get(
            "timestamp"
        ),

        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": (
            rule.get("description")
        ),
        "rule_frequency": (
            _as_int(
                rule.get("frequency")
            )
        ),
        "rule_groups": (
            _as_list(
                rule.get("groups")
            )
        ),

        "previous_output": (
            alert_data.get(
                "previous_output"
            )
        ),

        "decoder_name": (
            decoder.get("name")
        ),
        "decoder_parent": (
            decoder.get("parent")
        ),

        "mitre_ids": (
            _as_list(
                mitre.get("id")
            )
        ),
        "mitre_tactics": (
            _as_list(
                mitre.get("tactic")
            )
        ),
        "mitre_techniques": (
            _as_list(
                mitre.get("technique")
            )
        ),

        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "agent_ip": agent.get("ip"),

        "source_ip": data.get("srcip"),
        "source_user": data.get("srcuser"),
        "target_user": target_user,

        "source_port": data.get("srcport"),
        "destination_ip": data.get("dstip"),
        "destination_port": data.get(
            "dstport"
        ),

        "failed_attempts": failed_attempts,
        "privileged_target": (
            privileged_target
        ),

        "location": alert_data.get(
            "location"
        ),
    }

    return SecurityAlertInput(
        alert_id=alert_id,
        source="wazuh",
        event_text=str(event_text),
        metadata=metadata,
    )