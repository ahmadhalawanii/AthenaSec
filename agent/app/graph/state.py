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
    EvidenceSufficiencyAssessment,
    AnalysisVerificationResult,
    InvestigationTraceStep,
    StructuredResponseProposal,
    ActionRiskAssessmentRecord,
    ProposedActionRecord,
    ApprovalRequestRecord,
    IncidentPolicyDecisionRecord,
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
    "evidence_sufficient",
    "investigation_budget_exhausted",
    "analysis_verified",
    "analysis_verification_failed",
    "response_proposed",
    "response_proposal_blocked",
    "action_risk_assessed",
    "action_policy_evaluated",
]


class InvestigationState(TypedDict, total=False):
    alert: SecurityAlertInput

    normalized_event: str

    ml_prediction: AttackPrediction

    ml_error: str

    misp_enrichment: MISPEnrichment

    misp_error: str

    evidence_records: list[EvidenceRecord]

    evidence_sufficiency: (
        EvidenceSufficiencyAssessment
    )

    investigation_budget_exhausted: bool

    analysis_verification: (
        AnalysisVerificationResult
    )

    investigation_trace: list[
        InvestigationTraceStep
    ]

    analysis: AlertAnalysis

    risk_context: RiskContext

    risk_assessment: RiskAssessment

    policy_decision: PolicyDecision

    response_plan: ResponsePlan

    response_proposal: (
        StructuredResponseProposal
    )

    investigation_iteration: int

    status: InvestigationStatus

    incident_id: str

    investigation_id: str

    proposed_actions: list[
        ProposedActionRecord
    ]

    action_risk_assessments: list[
        ActionRiskAssessmentRecord
    ]

    action_policy_decisions: list[
        IncidentPolicyDecisionRecord
    ]

    approval_requests: list[
        ApprovalRequestRecord
    ]