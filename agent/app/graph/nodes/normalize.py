from app.graph.state import InvestigationState
from app.schemas import EvidenceRecord


def normalize_alert(
    state: InvestigationState,
) -> InvestigationState:
    alert = state["alert"]

    normalized_event = " ".join(
        alert.event_text.split()
    )

    initial_evidence = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content=normalized_event,
    )

    return {
        "normalized_event": normalized_event,
        "evidence_records": [
            initial_evidence,
        ],
        "investigation_iteration": 0,
        "status": "normalized",
    }