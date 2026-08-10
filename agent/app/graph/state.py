from typing import Literal, TypedDict

from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    SecurityAlertInput,
)


InvestigationStatus = Literal[
    "received",
    "normalized",
    "analyzing",
    "analyzed",
    "needs_evidence",
    "evidence_gathered",
    "complete",
    "failed",
]


class InvestigationState(TypedDict, total=False):
    alert: SecurityAlertInput

    normalized_event: str

    evidence_records: list[EvidenceRecord]

    analysis: AlertAnalysis

    investigation_iteration: int

    status: InvestigationStatus