import ipaddress
import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
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


class ApprovalListResponse(BaseModel):
    total: int

    items: list[ApprovalRequestRecord]

    next_cursor: str | None = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal[
        "APPROVED",
        "REJECTED",
    ]

    reason: str = Field(
        min_length=1,
    )


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


ActionVerificationStatus = Literal[
    "SUCCESS",
    "PARTIAL",
    "FAILED",
    "UNVERIFIED",
]


class ActionVerificationRecord(BaseModel):
    verification_id: str = Field(
        min_length=1,
    )

    response_action_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    status: ActionVerificationStatus

    message: str = Field(
        min_length=1,
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
    )

    verified_at: datetime


ActionRollbackStatus = Literal[
    "completed",
    "failed",
]


class ActionRollbackRecord(BaseModel):
    rollback_id: str = Field(
        min_length=1,
    )

    response_action_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    verification_id: str = Field(
        min_length=1,
    )

    rollback_action_type: str = Field(
        min_length=1,
    )

    target: str = Field(
        min_length=1,
    )

    status: ActionRollbackStatus

    message: str = Field(
        min_length=1,
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
    )

    recorded_at: datetime


ContainmentExpiryStatus = Literal[
    "PENDING",
    "CLAIMED",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
]


class ContainmentExpiryRecord(BaseModel):
    expiry_id: str = Field(
        min_length=1,
    )

    incident_id: str = Field(
        min_length=1,
    )

    proposed_action_id: str = Field(
        min_length=1,
    )

    response_action_id: str = Field(
        min_length=1,
    )

    rollback_action_type: str = Field(
        min_length=1,
    )

    target: str = Field(
        min_length=1,
    )

    rollback_parameters: dict[
        str,
        Any,
    ] = Field(
        default_factory=dict,
    )

    due_at: datetime

    status: ContainmentExpiryStatus

    attempt_count: int = Field(
        default=0,
        ge=0,
    )

    lease_owner: str | None = None

    lease_expires_at: datetime | None = None

    last_error: str | None = None

    created_at: datetime

    updated_at: datetime

    completed_at: datetime | None = None


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
    "containment_expiry",
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
    "awaiting_approval",
    "ready_for_structured_execution",
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
    "legacy_response_blocked",
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

    action_policy_decisions: list[
        IncidentPolicyDecisionRecord
    ] = Field(
        default_factory=list,
    )

    approval_requests: list[
        ApprovalRequestRecord
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


class AlertListEntry(BaseModel):
    alert_id: str

    incident_id: str | None = None

    investigation_id: str | None = None

    source: str

    alert_metadata: dict[str, object] = Field(
        default_factory=dict,
    )

    status: str

    observed_at: datetime | None = None

    classification: AttackClassification

    ml_prediction: AttackPrediction | None = None

    risk_assessment: RiskAssessment

    # The analyst's handling (alert_workflow): open until someone closes it
    analyst_status: Literal["open", "closed"] = "open"

    assigned_analyst: str | None = None


class AlertDetail(AlertListEntry):
    normalized_event: str

    event_text: str | None = None

    ml_error: str | None = None

    misp_enrichment: MISPEnrichment | None = None

    misp_error: str | None = None


class InvestigationListEntry(
    IncidentInvestigationRecord
):
    classification: AttackClassification | None = None

    risk_score: int | None = None

    risk_band: RiskBand | None = None

    policy_outcome: str | None = None


class AlertListResponse(BaseModel):
    total: int

    items: list[AlertListEntry]

    next_cursor: str | None = None


class InvestigationListResponse(BaseModel):
    total: int

    items: list[InvestigationListEntry]

    next_cursor: str | None = None


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


RuntimeControlResponseMode = Literal[
    "SHADOW",
    "SUPERVISED",
    "AUTONOMOUS",
]


class RuntimeControlStateRecord(BaseModel):
    control_id: str = Field(
        default="ATHENASEC_RUNTIME",
        min_length=1,
    )

    response_mode: RuntimeControlResponseMode

    operator_execution_enabled: bool

    version: int = Field(
        ge=0,
    )

    updated_at: datetime

    updated_by: str = Field(
        min_length=1,
    )

    update_reason: str = Field(
        min_length=1,
    )


class RuntimeControlChangeRecord(BaseModel):
    change_id: str = Field(
        min_length=1,
    )

    control_id: str = Field(
        default="ATHENASEC_RUNTIME",
        min_length=1,
    )

    version: int = Field(
        ge=1,
    )

    previous_response_mode: (
        RuntimeControlResponseMode
    )

    new_response_mode: (
        RuntimeControlResponseMode
    )

    previous_operator_execution_enabled: bool

    new_operator_execution_enabled: bool

    changed_at: datetime

    changed_by: str = Field(
        min_length=1,
    )

    reason: str = Field(
        min_length=1,
    )


class RuntimeControlUpdateRequest(BaseModel):
    response_mode: (
        RuntimeControlResponseMode
        | None
    ) = None

    operator_execution_enabled: (
        bool | None
    ) = None

    changed_by: str = Field(
        min_length=1,
    )

    reason: str = Field(
        min_length=1,
    )


UserRole = Literal[
    "Analyst",
    "Administrator",
]


class UserRecord(BaseModel):
    user_id: str

    email: str

    name: str

    role: UserRole

    department: str = ""

    phone: str = ""

    active: bool

    mfa_enabled: bool = True

    can_read_approvals: bool

    can_decide_approvals: bool

    created_at: datetime | None = None

    last_login_at: datetime | None = None


class UserListResponse(BaseModel):
    total: int

    items: list[UserRecord]

    next_cursor: str | None = None


AuditResult = Literal[
    "Success",
    "Failed",
    "Denied",
]

AuditActorRole = Literal[
    "Analyst",
    "Administrator",
    "System",
]


class AuditEvent(BaseModel):
    """One row of GET /api/v1/audit: an operator event or an incident event."""

    seq: int | None = None

    event_id: str

    occurred_at: datetime

    actor_id: str

    actor_role: AuditActorRole

    category: str

    action: str

    target: str

    result: AuditResult

    source_ip: str | None = None

    source: Literal["operator", "incident"]

    incident_id: str | None = None

    event_type: str | None = None

    message: str | None = None

    detail: dict[str, Any] = Field(
        default_factory=dict,
    )

    prev_hash: str | None = None

    row_hash: str | None = None


class AuditListResponse(BaseModel):
    total: int

    items: list[AuditEvent]

    next_cursor: str | None = None

    alert_events: list[AuditRecord] = Field(
        default_factory=list,
    )


class ChainVerification(BaseModel):
    valid: bool

    checked: int

    first_broken_seq: int | None = None

    head_hash: str | None = None


class CaseEvidence(BaseModel):
    evidence_id: str

    source: str

    evidence_type: str | None = None

    content: str


class CaseAction(BaseModel):
    position: int

    label: str

    done: bool = False

    proposed_action_id: str | None = None

    approval_id: str | None = None


class CaseTimelineEntry(BaseModel):
    seq: int

    occurred_at: datetime

    title: str

    description: str

    failed: bool = False

    source: Literal["agent", "analyst"]

    author: str | None = None


class Case(BaseModel):
    """Website case: an incident_cases row plus analyst workflow plus derived investigation data."""

    case_id: str

    incident_id: str

    investigation_id: str | None = None

    alert_id: str | None = None

    policy_id: str | None = None

    classification: AttackClassification | None = None

    risk_score: int | None = None

    risk_band: RiskBand | None = None

    status: IncidentCaseStatus

    reason: str

    assigned_analyst: str | None = None

    summary: str | None = None

    endpoint: str | None = None

    source_ip: str | None = None

    evidence: list[CaseEvidence] = Field(
        default_factory=list,
    )

    recommended_actions: list[CaseAction] = Field(
        default_factory=list,
    )

    mitre_ids: list[str] = Field(
        default_factory=list,
    )

    timeline: list[CaseTimelineEntry] = Field(
        default_factory=list,
    )

    version: int = 1

    created_at: datetime

    updated_at: datetime

    closed_at: datetime | None = None


class CaseListResponse(BaseModel):
    total: int

    items: list[Case]

    next_cursor: str | None = None


class CaseWorkflowRecord(BaseModel):
    case_id: str = Field(
        min_length=1,
    )

    assigned_analyst: str | None = None

    summary: str | None = None

    closed_at: datetime | None = None

    updated_at: datetime

    version: int = Field(
        default=1,
        ge=1,
    )


class CaseActionRecord(BaseModel):
    case_id: str = Field(
        min_length=1,
    )

    position: int = Field(
        ge=0,
    )

    label: str = Field(
        min_length=1,
    )

    proposed_action_id: str | None = None

    approval_id: str | None = None

    done: bool = False


class CaseNoteRecord(BaseModel):
    case_id: str = Field(
        min_length=1,
    )

    seq: int = Field(
        ge=1,
    )

    occurred_at: datetime

    title: str = Field(
        min_length=1,
    )

    description: str

    failed: bool = False

    author: str | None = None


DashboardWindow = Literal[
    "24h",
    "7d",
    "30d",
]


class AlertsSummary(BaseModel):
    total: int = 0

    by_classification: dict[str, int] = Field(
        default_factory=dict,
    )

    by_risk_band: dict[str, int] = Field(
        default_factory=dict,
    )

    by_status: dict[str, int] = Field(
        default_factory=dict,
    )


class InvestigationsSummary(BaseModel):
    total: int = 0

    by_status: dict[str, int] = Field(
        default_factory=dict,
    )


class ApprovalsSummary(BaseModel):
    pending: int = 0

    decided: int = 0


class CasesSummary(BaseModel):
    active: int = 0

    by_status: dict[str, int] = Field(
        default_factory=dict,
    )

    opened_in_window: int = 0


class ResponseSummary(BaseModel):
    response_mode: str

    operator_execution_enabled: bool

    effective_execution_enabled: bool


class SeriesPoint(BaseModel):
    bucket_start: datetime

    alerts: int


class DashboardSummary(BaseModel):
    """Counts of events cover the window; pending approvals and active cases are current."""

    window: DashboardWindow

    role: UserRole

    generated_at: datetime

    window_start: datetime

    alerts: AlertsSummary

    investigations: InvestigationsSummary

    approvals: ApprovalsSummary

    cases: CasesSummary

    my_cases: int | None = None

    response: ResponseSummary | None = None

    recent_alerts: list[AlertListEntry] = Field(
        default_factory=list,
    )

    series: list[SeriesPoint] = Field(
        default_factory=list,
    )


PolicyEntryType = Literal[
    "ip",
    "cidr",
    "hostname",
    "account",
]

MAX_POLICY_ENTRIES = 1000

_HOSTNAME_LABEL = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)


class PolicyEntry(BaseModel):
    """One whitelist or blacklist entry. Values are validated and normalised."""

    model_config = ConfigDict(
        extra="forbid",
    )

    value: str = Field(
        min_length=1,
        max_length=253,
    )

    type: PolicyEntryType

    note: str = Field(
        default="",
        max_length=500,
    )

    @model_validator(mode="after")
    def check_and_normalise_value(self):
        value = self.value.strip()

        if self.type == "ip":
            value = str(ipaddress.ip_address(value))

        elif self.type == "cidr":
            network = ipaddress.ip_network(value, strict=True)

            if network.prefixlen == 0:
                raise ValueError(
                    "A CIDR entry must not cover the whole address space."
                )

            value = str(network)

        elif self.type == "hostname":
            value = value.lower().rstrip(".")

            if not value or not all(
                _HOSTNAME_LABEL.match(label)
                for label in value.split(".")
            ):
                raise ValueError("Invalid hostname.")

        elif not value or re.search(r"\s", value) or len(value) > 128:
            raise ValueError(
                "An account must be 1 to 128 characters without whitespace."
            )

        self.value = value

        return self


class PolicyUpdateRequest(BaseModel):
    """PUT /api/v1/policies. base_version is the version the editor last saw (0 if none)."""

    model_config = ConfigDict(
        extra="forbid",
    )

    base_version: int = Field(
        ge=0,
    )

    whitelist: list[PolicyEntry] = Field(
        max_length=MAX_POLICY_ENTRIES,
    )

    blacklist: list[PolicyEntry] = Field(
        max_length=MAX_POLICY_ENTRIES,
    )

    reason: str = Field(
        min_length=1,
        max_length=500,
    )

    @model_validator(mode="after")
    def check_entries_do_not_conflict(self):
        for name, entries in (
            ("whitelist", self.whitelist),
            ("blacklist", self.blacklist),
        ):
            keys = [(e.type, e.value) for e in entries]

            if len(keys) != len(set(keys)):
                raise ValueError(f"Duplicate entry in {name}.")

        overlap = {(e.type, e.value) for e in self.whitelist} & {
            (e.type, e.value) for e in self.blacklist
        }

        if overlap:
            raise ValueError(
                "An entry cannot be in both the whitelist and the blacklist."
            )

        return self


class PolicyProtectedTarget(BaseModel):
    """Read-only: the agent's own target protection (enforced), not part of the document."""

    value: str

    type: Literal[
        "ip",
        "account",
        "endpoint",
    ]


class PolicyVersionRecord(BaseModel):
    version: int = Field(
        ge=1,
    )

    whitelist: list[PolicyEntry] = Field(
        default_factory=list,
    )

    blacklist: list[PolicyEntry] = Field(
        default_factory=list,
    )

    created_at: datetime

    created_by: str = Field(
        min_length=1,
    )

    reason: str = Field(
        min_length=1,
    )


class PolicyDocument(BaseModel):
    """enforced is always false: the agent never reads the stored whitelist or blacklist."""

    version: int = 0

    whitelist: list[PolicyEntry] = Field(
        default_factory=list,
    )

    blacklist: list[PolicyEntry] = Field(
        default_factory=list,
    )

    protected_targets: list[PolicyProtectedTarget] = Field(
        default_factory=list,
    )

    enforced: Literal[False] = False

    enforcement_note: str

    created_at: datetime | None = None

    created_by: str | None = None

    reason: str | None = None


class PolicyVersionSummary(BaseModel):
    version: int

    created_at: datetime

    created_by: str

    reason: str

    whitelist_count: int

    blacklist_count: int

    enforced: Literal[False] = False


class PolicyVersionListResponse(BaseModel):
    total: int

    items: list[PolicyVersionSummary]

    next_cursor: str | None = None


HealthStatus = Literal[
    "up",
    "degraded",
    "down",
    "starting",
    "unconfigured",
]

HealthSeverity = Literal[
    "Info",
    "Warning",
    "Critical",
]


class HealthService(BaseModel):
    """uptime_seconds and uptime_percent are always null: the agent does not track uptime."""

    check_key: str

    name: str

    group: str

    category: str

    status: HealthStatus

    endpoint: str | None = None

    latency_ms: int | None = None

    checked_at: datetime | None = None

    detail: str | None = None

    uptime_seconds: int | None = None

    uptime_percent: float | None = None

    last_change_at: datetime | None = None


class HealthMetrics(BaseModel):
    process_uptime_seconds: int

    version: str

    response_mode: str

    persistence_backend: str

    evidence_provider: str


class SystemHealth(BaseModel):
    generated_at: datetime

    services: list[HealthService]

    summary: dict[str, int]

    metrics: HealthMetrics

    event_log: Literal["ok", "unavailable"]


class HealthEvent(BaseModel):
    event_id: int

    occurred_at: datetime

    severity: HealthSeverity

    source: str

    status: HealthStatus

    message: str


class HealthEventListResponse(BaseModel):
    total: int

    items: list[HealthEvent]

    next_cursor: str | None = None


class ApprovalActionDetail(BaseModel):
    """What an approval request is asking a person to approve."""

    approval: ApprovalRequestRecord

    proposed_action: ProposedActionRecord | None = None

    policy_decision: IncidentPolicyDecisionRecord | None = None

# ----- Action policy: the admin's whitelist and blacklist of agent actions ------
#
# Which actions the agent may use on its own, which need a person's approval, and
# which it may never use. Unlike the target policy above, the agent enforces this
# one (app/services/policy/action_policy_engine.py). Same shape as the website's
# Response Policy page (frontend/src/types/responsePoliciesTypes.ts).

ActionPolicyMode = Literal["automatic", "approval"]

ApproverRole = Literal["soc_analyst", "soc_lead"]


class ActionPolicyLimits(BaseModel):
    """Limits on an approval-required action."""

    model_config = ConfigDict(extra="forbid")

    default_minutes: int | None = Field(default=None, ge=1)
    max_minutes: int | None = Field(default=None, ge=1)
    approver: ApproverRole
    window_minutes: int = Field(ge=1, le=1440)
    # The agent recommends the action only at this incident risk or more
    min_risk: int = Field(ge=0, le=100)


class ActionWhitelistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=64)
    mode: ActionPolicyMode
    limits: ActionPolicyLimits | None = None


class ActionBlacklistEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=64)
    # From the security policy; cannot be removed
    required: bool = False


class ActionProtectedTarget(BaseModel):
    """An IP, CIDR range or host name the agent may never act against."""

    model_config = ConfigDict(extra="forbid")

    value: str = Field(min_length=1, max_length=255)
    label: str = Field(default="", max_length=200)
    required: bool = False


class ActionPolicyContent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    whitelist: list[ActionWhitelistEntry] = Field(default_factory=list, max_length=200)
    blacklist: list[ActionBlacklistEntry] = Field(default_factory=list, max_length=200)
    never_block: list[ActionProtectedTarget] = Field(default_factory=list, max_length=1000)
    never_isolate: list[ActionProtectedTarget] = Field(default_factory=list, max_length=1000)


class ActionPolicyDocument(ActionPolicyContent):
    """The action policy as stored. Version 0 is the built-in default."""

    version: int = Field(ge=0)
    is_default: bool = False
    created_at: datetime | None = None
    created_by: str | None = None
    reason: str | None = None


class ActionPolicyUpdateRequest(ActionPolicyContent):
    base_version: int = Field(ge=0)
    reason: str = Field(min_length=1, max_length=500)


class ActionPolicyVersionListResponse(BaseModel):
    total: int
    items: list[ActionPolicyDocument]
    next_cursor: str | None = None


# ----- Analyst workflow for alerts and cases (website actions) -----

AnalystStatus = Literal["open", "closed"]


class AlertWorkflowRecord(BaseModel):
    alert_id: str = Field(min_length=1)
    status: AnalystStatus = "open"
    assigned_analyst: str | None = None
    updated_at: datetime
    updated_by: str = Field(min_length=1)


class StatusChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AnalystStatus


class CaseActionUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    done: bool


# ----- User administration (website User Management) -----


class UserWriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    role: UserRole
    department: str = Field(default="", max_length=200)
    phone: str = Field(default="", max_length=50)


class UserStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool


class UserCredentialsResponse(BaseModel):
    """Shown to the administrator once: the account and how its owner signs in."""

    user: UserRecord
    temporary_password: str
    # otpauth:// link for the authenticator app (new accounts only)
    totp_uri: str | None = None


# ----- Website configuration, personal settings and profile -----


class ConfigurationValues(BaseModel):
    """System configuration (admin). correlation_window_minutes is used by alert
    correlation; the other values are recorded for the SOC and shown on the website."""

    model_config = ConfigDict(extra="forbid")

    organization: str = Field(default="AthenaSec SOC", min_length=1, max_length=200)
    workspace: Literal["Production", "Staging", "Development", "Testing"] = "Production"
    correlation_window_minutes: int = Field(default=15, ge=1, le=1440)
    critical_risk_threshold: int = Field(default=90, ge=0, le=100)
    logging_destination: Literal["OpenSearch", "Local File", "Syslog"] = "OpenSearch"
    logging_mode: Literal["Realtime", "Batch", "Manual"] = "Realtime"
    hot_storage_days: int = Field(default=30, ge=1, le=3650)
    audit_retention_days: int = Field(default=365, ge=1, le=3650)
    critical_alert_notification: Literal[
        "Email + In-App", "Email Only", "In-App Only", "Disabled"
    ] = "Email + In-App"


class ConfigurationDocument(ConfigurationValues):
    model_config = ConfigDict(extra="forbid")

    # 0 until an administrator saves (the defaults above apply)
    version: int = 0
    updated_at: datetime | None = None
    updated_by: str | None = None


class ConfigurationUpdateRequest(ConfigurationValues):
    base_version: int = Field(ge=0)


class UserSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    theme: Literal["Dark Enterprise", "High Contrast"] = "Dark Enterprise"
    language: Literal["English", "Arabic"] = "English"
    notifications_enabled: bool = True
    critical_alert_notifications: bool = True
    case_notifications: bool = True
    system_health_notifications: bool = True
    email_notifications: bool = True
    session_timeout: Literal["30 minutes", "60 minutes", "4 hours"] = "30 minutes"
    # Two-factor sign-in is required for every account; kept for the page's switch
    mfa_enabled: bool = True
    require_mfa_for_sensitive_actions: bool = True
    auto_logout_warning: bool = True


class ProfileDocument(BaseModel):
    user_id: str
    role: UserRole
    display_name: str
    email: str
    department: str = ""
    phone: str = ""
    timezone: str = "Asia/Dubai"


class ProfileUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=254)
    department: str = Field(default="", max_length=200)
    phone: str = Field(default="", max_length=50)
    timezone: str = Field(default="Asia/Dubai", min_length=1, max_length=64)


class PasswordChangeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=14, max_length=1024)


class AccountActivityEntry(BaseModel):
    event_type: str
    recorded_at: datetime


class AccountActivityResponse(BaseModel):
    items: list[AccountActivityEntry]


# ----- Executed responses (Incident Response page) -----


class ResponseStep(BaseModel):
    status: str
    message: str = ""
    at: datetime


class ResponseRun(BaseModel):
    """One executed (or attempted) containment action and what followed it."""

    response_action_id: str
    incident_id: str
    alert_id: str | None = None
    proposed_action_id: str
    approval_id: str | None = None
    policy_decision_id: str | None = None
    action_type: str | None = None
    target: str | None = None
    duration_minutes: int | None = None
    reason: str | None = None
    status: str
    executor: str
    created_at: datetime
    approved_by: str | None = None
    # soc_lead for an Administrator, soc_analyst for an Analyst (None if unknown)
    approver_role: Literal["soc_analyst", "soc_lead"] | None = None
    approver_name: str | None = None
    approved_at: datetime | None = None
    result: ResponseStep | None = None
    verification: ResponseStep | None = None
    rollback: ResponseStep | None = None
    # When a time-limited block or isolation lapses on its own
    expires_at: datetime | None = None


class ResponseRunListResponse(BaseModel):
    total: int
    items: list[ResponseRun]
    next_cursor: str | None = None


class MfaResetResponse(BaseModel):
    """Shown to the administrator once: the link that enrols the user's new authenticator."""

    user: UserRecord
    totp_uri: str
