from typing import Literal, TypedDict

from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    RiskAssessment,
    RiskContext,
    SecurityAlertInput,
)


InvestigationStatus = Literal[
    "received",
    "normalized",
    "analyzing",
    "analyzed",
    "needs_evidence",
    "evidence_gathered",
    "risk_scored",
    "complete",
    "failed",
]


class InvestigationState(TypedDict, total=False):
    alert: SecurityAlertInput

    normalized_event: str

    evidence_records: list[EvidenceRecord]

    analysis: AlertAnalysis

    risk_context: RiskContext

    risk_assessment: RiskAssessment

    investigation_iteration: int

    status: InvestigationStatus