from typing import Any

from app.schemas import (
    SecurityAlertInput,
)


def _as_dict(
    value: Any,
) -> dict[str, Any]:
    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def parse_wazuh_alert(
    payload: dict[str, Any],
) -> SecurityAlertInput:
    index_source = payload.get(
        "_source"
    )

    if isinstance(
        index_source,
        dict,
    ):
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

    index_document_id = payload.get(
        "_id"
    )

    raw_alert_id = alert_data.get(
        "id"
    )

    identifier = (
        index_document_id
        or raw_alert_id
    )

    if not identifier:
        raise ValueError(
            "Wazuh alert requires an identifier."
        )

    index_name = payload.get(
        "_index"
    )

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

    full_log = alert_data.get(
        "full_log"
    )

    description = rule.get(
        "description"
    )

    event_text = (
        full_log
        or description
        or "Wazuh security alert"
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
        "rule_level": rule.get(
            "level"
        ),
        "rule_groups": (
            rule.get("groups")
            or []
        ),
        "agent_id": agent.get("id"),
        "agent_name": agent.get(
            "name"
        ),
        "agent_ip": agent.get("ip"),
        "source_ip": (
            data.get("srcip")
        ),
        "source_user": (
            data.get("srcuser")
        ),
        "target_user": (
            data.get("dstuser")
            or data.get("user")
        ),
        "source_port": (
            data.get("srcport")
        ),
        "destination_ip": (
            data.get("dstip")
        ),
        "destination_port": (
            data.get("dstport")
        ),
        "location": alert_data.get(
            "location"
        ),
    }

    return SecurityAlertInput(
        alert_id=alert_id,
        source="wazuh",
        event_text=str(
            event_text
        ),
        metadata=metadata,
    )