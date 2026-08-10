from typing import Literal, TypedDict

from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    PolicyDecision,
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
    "policy_evaluated",
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

    policy_decision: PolicyDecision

    investigation_iteration: int

    status: InvestigationStatus