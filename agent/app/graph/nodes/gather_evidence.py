from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import (
    EvidenceRequest,
    SecurityAlertInput,
)


EvidenceProvider = Callable[
    [
        SecurityAlertInput,
        list[EvidenceRequest],
    ],
    list[str],
]


def make_gather_evidence_node(
    evidence_provider: EvidenceProvider,
):
    def gather_evidence(
        state: InvestigationState,
    ) -> InvestigationState:
        analysis = state["analysis"]

        requested_evidence = (
            analysis.requested_evidence
        )

        evidence = evidence_provider(
            state["alert"],
            requested_evidence,
        )

        existing_evidence = state.get(
            "gathered_evidence",
            [],
        )

        iteration = state.get(
            "investigation_iteration",
            0,
        )

        return {
            "gathered_evidence": (
                existing_evidence
                + evidence
            ),
            "investigation_iteration": (
                iteration + 1
            ),
            "status": "evidence_gathered",
        }

    return gather_evidence