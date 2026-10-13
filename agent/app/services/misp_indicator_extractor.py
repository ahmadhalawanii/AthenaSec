from app.schemas import SecurityAlertInput


def extract_misp_indicators(
    alert: SecurityAlertInput,
) -> list[tuple[str, str]]:
    indicators: list[
        tuple[str, str]
    ] = []

    source_ip = alert.metadata.get(
        "source_ip"
    )

    if isinstance(
        source_ip,
        str,
    ) and source_ip.strip():
        indicators.append(
            (
                "ip-src",
                source_ip.strip(),
            )
        )

    destination_ip = alert.metadata.get(
        "destination_ip"
    )

    if isinstance(
        destination_ip,
        str,
    ) and destination_ip.strip():
        indicators.append(
            (
                "ip-dst",
                destination_ip.strip(),
            )
        )

    return indicators