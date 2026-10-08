import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)
from datetime import datetime, timezone
class SecurityAlertInput(BaseModel):
    alert_id: str

    source: Literal[
        "manual",
        "mock",
        "wazuh",
        "dataset",
    ] = "manual"

    event_text: str = Field(
        min_length=1,
        description="Raw security event or alert text.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional structured alert metadata.",
    )


AttackClassification = Literal[
    "brute_force",
    "privilege_escalation",
    "privilege_misuse",
    "benign",
    "unknown",
]

class AttackPrediction(BaseModel):
    classification: AttackClassification
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    model_version: str


SeverityAssessment = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


RiskBand = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


AssetCriticality = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


EvidenceRequest = Literal[
    "authentication_history",
    "source_endpoint_context",
    "privilege_activity",
    "related_security_events",
]

EvidenceType = Literal[
    "alert",
    "authentication_history",
    "source_endpoint_context",
    "privilege_activity",
    "related_security_events",
]

EvidenceSource = Literal[
    "alert",
    "mock_wazuh",
    "wazuh",
    "opensearch",
    "cortex",
    "dataset",
]

EvidenceReference = str


def validate_evidence_reference(
    value: str,
) -> str:
    if not re.fullmatch(
        r"E\d{3,}",
        value,
    ):
        raise ValueError(
            "Evidence ID must use the format "
            "E001, E002, E003, etc."
        )

    return value


class EvidenceObservation(BaseModel):
    source: EvidenceSource

    evidence_type: EvidenceType | None = None

    content: str = Field(
        min_length=1,
    )


class EvidenceRecord(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    evidence_id: EvidenceReference

    source: EvidenceSource

    evidence_type: EvidenceType | None = None

    content: str = Field(
        min_length=1,
    )

    @field_validator("evidence_id")
    @classmethod
    def check_evidence_id(
        cls,
        value: str,
    ) -> str:
        return validate_evidence_reference(
            value
        )

class EvidenceSufficiencyAssessment(BaseModel):
    classification: AttackClassification

    sufficient: bool

    required_evidence: list[EvidenceRequest] = Field(
        default_factory=list,
    )

    satisfied_evidence: list[EvidenceRequest] = Field(
        default_factory=list,
    )

    missing_evidence: list[EvidenceRequest] = Field(
        default_factory=list,
    )

class AnalysisVerificationResult(BaseModel):
    verified: bool

    classification_consistent: bool

    evidence_sufficient: bool

    checked_evidence_refs: list[
        EvidenceReference
    ] = Field(
        default_factory=list,
    )

    blocking_issues: list[str] = Field(
        default_factory=list,
    )

    warnings: list[str] = Field(
        default_factory=list,
    )

InvestigationStepType = Literal[
    "analysis",
    "evidence_sufficiency",
    "evidence_gathering",
    "analysis_verification",
]


class InvestigationTraceStep(BaseModel):
    sequence: int = Field(
        ge=1,
    )

    step_type: InvestigationStepType

    status: str = Field(
        min_length=1,
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
    )

    recorded_at: datetime = Field(
        default_factory=lambda: (
            datetime.now(
                timezone.utc
            )
        )
    )


class InvestigationStepRecord(
    InvestigationTraceStep
):
    investigation_id: str = Field(
        min_length=1,
    )

    step_id: str = Field(
        min_length=1,
    )

class AlertAnalysis(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )

    classification: AttackClassification

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    severity_assessment: SeverityAssessment

    summary: str

    evidence_refs: list[EvidenceReference] = Field(
        min_length=1,
        description=(
            "One or more supplied evidence IDs that directly "
            "support the analysis. At least one is required."
        ),
    )

    uncertainties: list[str]

    recommended_investigation_steps: list[str]

    recommended_response_actions: list[str]

    requested_evidence: list[EvidenceRequest] = Field(
        default_factory=list,
        max_length=2,
    )

    needs_more_evidence: bool

    @field_validator("evidence_refs")
    @classmethod
    def check_evidence_refs(
        cls,
        values: list[str],
    ) -> list[str]:
        return [
            validate_evidence_reference(
                value
            )
            for value in values
        ]

class RiskContext(BaseModel):
    failed_attempts: int = Field(
        default=0,
        ge=0,
    )

    privileged_target: bool = False

    successful_authentication: bool | None = None

    privilege_change_observed: bool = False

    policy_violation_observed: bool = False

    asset_criticality: AssetCriticality = "medium"


class RiskFactor(BaseModel):
    name: str

    points: int = Field(
        ge=0,
    )

    reason: str


class RiskAssessment(BaseModel):
    score: int = Field(
        ge=0,
        le=100,
    )

    band: RiskBand

    factors: list[RiskFactor]

IncidentStatus = Literal[
    "open",
    "contained",
    "resolved",
    "closed",
]


class IncidentRecord(BaseModel):
    incident_id: str = Field(
        min_length=1,
    )

    title: str = Field(
        min_length=1,
    )

    status: IncidentStatus

    created_at: datetime

    updated_at: datetime

class AlertCorrelationFingerprint(BaseModel):
    alert_id: str = Field(
        min_length=1,
    )

    classification: AttackClassification

    observed_at: datetime

    source_ip: str | None = None

    target_user: str | None = None

    agent_id: str | None = None

    mitre_ids: list[str] = Field(
        default_factory=list,
    )


class IncidentCorrelationProfile(BaseModel):
    incident_id: str = Field(
        min_length=1,
    )

    classification: AttackClassification

    source_ips: list[str] = Field(
        default_factory=list,
    )

    target_users: list[str] = Field(
        default_factory=list,
    )

    agent_ids: list[str] = Field(
        default_factory=list,
    )

    mitre_ids: list[str] = Field(
        default_factory=list,
    )

    first_seen: datetime

    last_seen: datetime


class CorrelationMatchResult(BaseModel):
    matched: bool

    score: int = Field(
        ge=0,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )

class IncidentAlertRecord(BaseModel):
    incident_id: str = Field(
        min_length=1,
    )

    alert_id: str = Field(
        min_length=1,
    )

    source: Literal[
        "manual",
        "mock",
        "wazuh",
        "dataset",
    ]

    event_text: str = Field(
        min_length=1,
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
    )

    observed_at: datetime

AllowedAction = Literal[
    "block_ip",
    "lock_account",
    "notify_administrator",
    "create_case",
    "capture_telemetry",
    "record_response",
]

IncidentInvestigationStatus = Literal[
    "open",
    "investigating",
    "complete",
    "failed",
]

class IncidentCorrelationDecision(BaseModel):
    incident: IncidentRecord

    alert: IncidentAlertRecord

    profile: IncidentCorrelationProfile

    created_new_incident: bool

    duplicate_alert: bool = False

    correlation_score: int = Field(
        default=0,
        ge=0,
    )

    correlation_reasons: list[str] = Field(
        default_factory=list,
    )

class IncidentInvestigationRecord(BaseModel):
    investigation_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    primary_alert_id: str = Field(
        min_length=1,
    )

    status: IncidentInvestigationStatus

    started_at: datetime

    updated_at: datetime

    completed_at: datetime | None = None

    iteration_count: int = Field(
        default=0,
        ge=0,
    )

    budget_exhausted: bool = False

    evidence_sufficient: bool | None = None

    analysis_verified: bool | None = None


class InvestigationEvidenceRecord(BaseModel):
    investigation_id: str = Field(
        min_length=1,
    )

    evidence_id: EvidenceReference

    source: EvidenceSource

    evidence_type: EvidenceType | None = None

    content: str = Field(
        min_length=1,
    )

    captured_at: datetime

    @field_validator("evidence_id")
    @classmethod
    def check_evidence_id(
        cls,
        value: str,
    ) -> str:
        return validate_evidence_reference(
            value
        )

PolicyOutcome = Literal[
    "AUTO_ALLOWED",
    "APPROVAL_REQUIRED",
    "NOT_ALLOWED",
]


ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXPIRED",
    "CANCELLED",
]


ActionTargetType = Literal[
    "ip",
    "account",
    "endpoint",
    "network",
    "other",
]


ActionBlastRadius = Literal[
    "single",
    "limited",
    "broad",
    "unknown",
]

ResponseProposalActionType = Literal[
    "block_ip",
    "lock_account",
    "capture_telemetry",
]


class ResponseActionProposal(BaseModel):
    action_type: ResponseProposalActionType

    target_type: ActionTargetType

    target: str = Field(
        min_length=1,
    )

    duration_minutes: int | None = Field(
        default=None,
        ge=1,
        le=1440,
    )

    reason: str = Field(
        min_length=1,
    )

    evidence_refs: list[
        EvidenceReference
    ] = Field(
        min_length=1,
        max_length=5,
    )

    @field_validator(
        "evidence_refs"
    )
    @classmethod
    def check_evidence_refs(
        cls,
        values: list[str],
    ) -> list[str]:
        return [
            validate_evidence_reference(
                value
            )
            for value in values
        ]


class StructuredResponseProposal(BaseModel):
    summary: str = Field(
        min_length=1,
    )

    actions: list[
        ResponseActionProposal
    ] = Field(
        default_factory=list,
        max_length=3,
    )


ResponseActionStatus = Literal[
    "planned",
    "started",
    "completed",
    "failed",
    "blocked",
]

class ActionRiskContext(BaseModel):
    target_criticality: AssetCriticality = "low"

    protected_target: bool = False

    allowlisted_target: bool = False

    privileged_target: bool = False

    affected_target_count: int = Field(
        default=1,
        ge=1,
    )

class IncidentRiskAssessmentRecord(BaseModel):
    risk_assessment_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    investigation_id: str = Field(
        min_length=1,
    )

    score: int = Field(
        ge=0,
        le=100,
    )

    band: RiskBand

    factors: list[RiskFactor]

    assessed_at: datetime


class ProposedActionRecord(BaseModel):
    proposed_action_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    investigation_id: str = Field(
        min_length=1,
    )

    action_type: str = Field(
        min_length=1,
    )

    target_type: ActionTargetType

    target: str = Field(
        min_length=1,
    )

    parameters: dict[str, Any] = Field(
        default_factory=dict,
    )

    reversible: bool

    rollback_action_type: str | None = None

    rollback_parameters: dict[str, Any] = Field(
        default_factory=dict,
    )

    reason: str = Field(
        min_length=1,
    )

    proposed_at: datetime


class ActionRiskAssessmentRecord(BaseModel):
    action_risk_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    score: int = Field(
        ge=0,
        le=100,
    )

    band: RiskBand

    blast_radius: ActionBlastRadius

    reversible: bool

    protected_target: bool

    requires_approval: bool

    reasons: list[str]

    assessed_at: datetime


class IncidentPolicyDecisionRecord(BaseModel):
    decision_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    policy_id: str = Field(
        min_length=1,
    )

    outcome: PolicyOutcome

    reason: str = Field(
        min_length=1,
    )

    decided_at: datetime


class ApprovalRequestRecord(BaseModel):
    approval_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    policy_decision_id: str = Field(
        min_length=1,
    )

    action_fingerprint: str = Field(
        min_length=1,
    )

    status: ApprovalStatus

    requested_by: str = Field(
        min_length=1,
    )

    requested_at: datetime

    expires_at: datetime | None = None

    decided_at: datetime | None = None

    decided_by: str | None = None

    decision_reason: str | None = None


class ResponseActionRecord(BaseModel):
    response_action_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    approval_id: str | None = None

    executor: Literal[
        "cortex",
    ]

    status: ResponseActionStatus

    created_at: datetime


class ActionExecutionResultRecord(BaseModel):
    action_result_id: str = Field(
        min_length=1,
    )

    response_action_id: str = Field(
        min_length=1,
    )

    status: Literal[
        "completed",
        "failed",
    ]

    message: str = Field(
        min_length=1,
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
    )

    recorded_at: datetime

IncidentCaseStatus = Literal[
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
]


IncidentAuditEntityType = Literal[
    "incident",
    "alert",
    "investigation",
    "evidence",
    "incident_risk",
    "proposed_action",
    "action_risk",
    "policy_decision",
    "approval_request",
    "response_action",
    "action_result",
    "case",
    "verification",
    "rollback",
]


class IncidentCaseRecord(BaseModel):
    case_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    investigation_id: str | None = None

    policy_decision_id: str | None = None

    status: IncidentCaseStatus

    reason: str = Field(
        min_length=1,
    )

    created_at: datetime

    updated_at: datetime


class IncidentAuditRecord(BaseModel):
    audit_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    event_type: str = Field(
        min_length=1,
    )

    entity_type: IncidentAuditEntityType

    entity_id: str = Field(
        min_length=1,
    )

    message: str = Field(
        min_length=1,
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
    )

    timestamp: datetime = Field(
        default_factory=lambda: (
            datetime.now(
                timezone.utc
            )
        )
    )

class PolicyDecision(BaseModel):
    policy_id: str

    policy_name: str

    matched: bool

    response_allowed: bool

    actions: list[AllowedAction]

    reason: str


ResponsePlanStatus = Literal[
    "no_action",
    "create_case",
    "ready_for_execution",
]


class ResponsePlan(BaseModel):
    policy_id: str

    actions: list[AllowedAction]

    response_allowed: bool

    status: ResponsePlanStatus

    reason: str


ActionExecutionStatus = Literal[
    "completed",
    "failed",
]


ExecutionStatus = Literal[
    "completed",
    "failed",
]


ExecutionProvider = Literal[
    "cortex",
]


class ActionExecutionResult(BaseModel):
    action: AllowedAction

    status: ActionExecutionStatus

    message: str

    details: dict[str, object] = Field(
        default_factory=dict,
    )


class ResponseExecutionResult(BaseModel):
    policy_id: str

    executor: ExecutionProvider

    status: ExecutionStatus

    action_results: list[ActionExecutionResult]

CaseStatus = Literal[
    "open",
]


class CaseRecord(BaseModel):
    case_id: str

    alert_id: str

    policy_id: str

    classification: AttackClassification

    risk_score: int

    risk_band: RiskBand

    status: CaseStatus

    reason: str


AuditEventType = Literal[
    "investigation_created",
    "ml_classification_completed",
    "ml_classification_failed",
    "misp_enrichment_completed",
    "misp_enrichment_failed",
    "policy_evaluated",
    "case_created",
    "autonomous_response_blocked",
    "cortex_execution_started",
    "cortex_execution_completed",
    "cortex_execution_failed",
]
class AuditRecord(BaseModel):
    audit_id: str
    alert_id: str
    timestamp: datetime = Field(
        default_factory=lambda: (
            datetime.now(
                timezone.utc
            )
        )
    )
    event_type: AuditEventType
    message: str
    details: dict[str, object] = Field(
        default_factory=dict,
    )

class InvestigationResponse(BaseModel):
    alert_id: str

    incident_id: str | None = None

    investigation_id: str | None = None

    source: str

    alert_metadata: dict[str, object] = Field(
        default_factory=dict,
    )

    status: str

    normalized_event: str

    ml_prediction: (
        AttackPrediction | None
    ) = None

    ml_error: str | None = None

    misp_enrichment: MISPEnrichment | None = None
    misp_error: str | None = None

    analysis: AlertAnalysis

    evidence_records: list[EvidenceRecord]

    evidence_sufficiency: (
        EvidenceSufficiencyAssessment | None
    ) = None

    analysis_verification: (
        AnalysisVerificationResult | None
    ) = None

    response_proposal: (
        StructuredResponseProposal | None
    ) = None

    proposed_actions: list[
        ProposedActionRecord
    ] = Field(
        default_factory=list,
    )

    action_risk_assessments: list[
        ActionRiskAssessmentRecord
    ] = Field(
        default_factory=list,
    )

    investigation_budget_exhausted: bool = False

    investigation_trace: list[
        InvestigationTraceStep
    ] = Field(
        default_factory=list,
    )

    risk_assessment: RiskAssessment

    policy_decision: PolicyDecision

    response_plan: ResponsePlan

    execution_result: (
        ResponseExecutionResult | None
    ) = None

    investigation_iteration: int


MISPThreatLevel = Literal[
    "low",
    "medium",
    "high",
    "unknown",
]


class MISPMatch(BaseModel):
    indicator_type: str
    indicator_value: str
    event_id: str
    event_info: str
    threat_level: MISPThreatLevel


class MISPEnrichment(BaseModel):
    queried_indicators: list[str]
    matches: list[MISPMatch]