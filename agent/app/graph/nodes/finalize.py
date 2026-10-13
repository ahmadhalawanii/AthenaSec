from app.graph.state import InvestigationState


def finalize_investigation(
    state: InvestigationState,
) -> InvestigationState:
    return {
        "status": "complete",
    }