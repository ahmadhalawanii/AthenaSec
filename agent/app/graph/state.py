from typing import Literal, TypedDict

from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceRecord,
    MISPEnrichment,
    PolicyDecision,
    ResponsePlan,
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
    "response_planned",
    "complete",
    "failed",
]


class InvestigationState(TypedDict, total=False):
    alert: SecurityAlertInput

    normalized_event: str

    ml_prediction: AttackPrediction

    ml_error: str

    misp_enrichment: MISPEnrichment

    misp_error: str

    evidence_records: list[EvidenceRecord]

    analysis: AlertAnalysis

    risk_context: RiskContext

    risk_assessment: RiskAssessment

    policy_decision: PolicyDecision

    response_plan: ResponsePlan

    investigation_iteration: int

    status: InvestigationStatus