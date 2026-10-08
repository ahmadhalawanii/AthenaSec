WAZUH_MAX_INVESTIGATION_ITERATIONS = 3

DEFAULT_MAX_INVESTIGATION_ITERATIONS = 1


def max_investigation_iterations(
    alert_source: str,
) -> int:
    if alert_source == "wazuh":
        return (
            WAZUH_MAX_INVESTIGATION_ITERATIONS
        )

    return (
        DEFAULT_MAX_INVESTIGATION_ITERATIONS
    )