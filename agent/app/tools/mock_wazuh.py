from collections.abc import Callable

from app.schemas import (
    EvidenceObservation,
    EvidenceRequest,
    SecurityAlertInput,
)


EvidenceTool = Callable[
    [SecurityAlertInput],
    list[EvidenceObservation],
]


def search_authentication_history(
    alert: SecurityAlertInput,
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "151 failed SSH authentication events "
                "were recorded from 192.168.1.45 "
                "during the surrounding ten-minute window"
            ),
        ),
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "No successful SSH authentication from "
                "192.168.1.45 was found during that window"
            ),
        ),
    ]


def get_source_endpoint_context(
    alert: SecurityAlertInput,
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "The source IP 192.168.1.45 is assigned "
                "to internal endpoint workstation-07"
            ),
        ),
    ]


def search_privilege_activity(
    alert: SecurityAlertInput,
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "No sudo, account elevation, or privilege "
                "escalation events were recorded for "
                "workstation-07 during the surrounding window"
            ),
        ),
    ]


def search_related_security_events(
    alert: SecurityAlertInput,
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "No additional high-severity security alerts "
                "linked to workstation-07 were observed in "
                "the surrounding thirty-minute window"
            ),
        ),
    ]


TOOL_REGISTRY: dict[
    EvidenceRequest,
    EvidenceTool,
] = {
    "authentication_history": (
        search_authentication_history
    ),
    "source_endpoint_context": (
        get_source_endpoint_context
    ),
    "privilege_activity": (
        search_privilege_activity
    ),
    "related_security_events": (
        search_related_security_events
    ),
}


def gather_requested_evidence(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[EvidenceObservation]:
    observations: list[EvidenceObservation] = []

    unique_requests = list(
        dict.fromkeys(requests)
    )

    for request in unique_requests:
        tool = TOOL_REGISTRY[request]

        observations.extend(
            tool(alert)
        )

    return observations