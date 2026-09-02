import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)
from datetime import datetime, timezone
from typing import Literal
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


EvidenceSource = Literal[
    "alert",
    "mock_wazuh",
    "wazuh",
    "opensearch",
    "cortex",
    "thehive",
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


AllowedAction = Literal[
    "block_ip",
    "lock_account",
    "notify_administrator",
    "create_case",
    "capture_telemetry",
    "record_response",
]


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