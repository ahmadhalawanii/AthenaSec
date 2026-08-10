from app.graph.state import InvestigationState


def normalize_alert(
    state: InvestigationState,
) -> InvestigationState:
    alert = state["alert"]

    normalized_event = " ".join(
        alert.event_text.split()
    )

    return {
        "normalized_event": normalized_event,
        "gathered_evidence": [],
        "investigation_iteration": 0,
        "status": "normalized",
    }