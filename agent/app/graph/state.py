from typing import Literal, TypedDict

from app.schemas import AlertAnalysis, SecurityAlertInput


InvestigationStatus = Literal[
    "received",
    "normalized",
    "analyzing",
    "analyzed",
    "needs_evidence",
    "complete",
    "failed",
]

class InvestigationState(TypedDict, total=False):
    alert: SecurityAlertInput

    normalized_event: str

    gathered_evidence: list[str]

    analysis: AlertAnalysis

    investigation_iteration: int

    status: InvestigationStatus