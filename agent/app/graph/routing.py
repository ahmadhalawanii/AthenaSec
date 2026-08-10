from typing import Literal

from app.graph.state import InvestigationState


MAX_INVESTIGATION_ITERATIONS = 1


def route_after_analysis(
    state: InvestigationState,
) -> Literal[
    "gather_evidence",
    "finalize_investigation",
]:
    analysis = state["analysis"]

    iteration = state.get(
        "investigation_iteration",
        0,
    )

    if (
        analysis.needs_more_evidence
        and analysis.requested_evidence
        and iteration
        < MAX_INVESTIGATION_ITERATIONS
    ):
        return "gather_evidence"

    return "finalize_investigation"