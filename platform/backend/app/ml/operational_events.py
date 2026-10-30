from app.schemas import SecurityAlertInput


def operational_event_reason(
    alert: SecurityAlertInput,
) -> str | None:
    """Identify narrowly recognized Wazuh operational events.

    This is not an ML prediction or permission to execute an action.
    """
    if alert.source != "wazuh":
        return None

    metadata = alert.metadata

    expected = {
        "rule_id": "502",
        "rule_level": 3,
        "rule_description": "Wazuh server started.",
        "decoder_name": "ossec",
        "agent_id": "000",
        "location": "wazuh-monitord",
    }

    for key, value in expected.items():
        if metadata.get(key) != value:
            return None

    if metadata.get("rule_groups") != ["ossec"]:
        return None

    unexpected_indicators = (
        "source_ip",
        "target_user",
        "source_user",
        "target_group",
        "command",
        "mitre_ids",
        "failed_attempts",
        "privileged_target",
        "source_port",
        "destination_port",
    )

    if any(
        metadata.get(field)
        for field in unexpected_indicators
    ):
        return None

    return "wazuh_manager_startup"
