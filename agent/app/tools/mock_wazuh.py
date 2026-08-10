from app.schemas import SecurityAlertInput


def search_related_security_events(
    alert: SecurityAlertInput,
) -> list[str]:
    return [
        (
            "151 failed SSH authentication events "
            "were recorded from 192.168.1.45 "
            "during the surrounding ten-minute window"
        ),
        (
            "No successful SSH authentication from "
            "192.168.1.45 was found during that window"
        ),
        (
            "The source IP 192.168.1.45 is assigned "
            "to internal endpoint workstation-07"
        ),
    ]