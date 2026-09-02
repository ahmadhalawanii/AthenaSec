from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import (
    EvidenceObservation,
    EvidenceRecord,
    EvidenceRequest,
    SecurityAlertInput,
)


EvidenceProvider = Callable[
    [
        SecurityAlertInput,
        list[EvidenceRequest],
    ],
    list[EvidenceObservation],
]


DEFAULT_WAZUH_EVIDENCE: dict[
    str,
    list[EvidenceRequest],
] = {
    "brute_force": [
        "authentication_history",
        "source_endpoint_context",
        "related_security_events",
    ],
    "privilege_misuse": [
        "privilege_activity",
        "authentication_history",
        "related_security_events",
    ],
    "privilege_escalation": [
        "privilege_activity",
        "authentication_history",
        "related_security_events",
    ],
}


def _resolve_evidence_requests(
    state: InvestigationState,
) -> list[EvidenceRequest]:
    analysis = state["analysis"]
    alert = state["alert"]

    if analysis.requested_evidence:
        return list(
            analysis.requested_evidence
        )

    if alert.source != "wazuh":
        return []

    return list(
        DEFAULT_WAZUH_EVIDENCE.get(
            analysis.classification,
            [],
        )
    )


def make_gather_evidence_node(
    evidence_provider: EvidenceProvider,
):
    def gather_evidence(
        state: InvestigationState,
    ) -> InvestigationState:
        requests = _resolve_evidence_requests(
            state
        )

        observations = evidence_provider(
            state["alert"],
            requests,
        )

        existing_records = state.get(
            "evidence_records",
            [],
        )

        next_number = (
            len(existing_records) + 1
        )

        new_records: list[EvidenceRecord] = []

        for observation in observations:
            record = EvidenceRecord(
                evidence_id=(
                    f"E{next_number:03d}"
                ),
                source=observation.source,
                content=observation.content,
            )

            new_records.append(record)

            next_number += 1

        iteration = state.get(
            "investigation_iteration",
            0,
        )

        return {
            "evidence_records": (
                existing_records
                + new_records
            ),
            "investigation_iteration": (
                iteration + 1
            ),
            "status": "evidence_gathered",
        }

    return gather_evidence