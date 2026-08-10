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


def make_gather_evidence_node(
    evidence_provider: EvidenceProvider,
):
    def gather_evidence(
        state: InvestigationState,
    ) -> InvestigationState:
        analysis = state["analysis"]

        observations = evidence_provider(
            state["alert"],
            analysis.requested_evidence,
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