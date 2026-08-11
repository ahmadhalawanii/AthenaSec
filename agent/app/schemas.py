import re
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
)


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


# Keep this as a plain string for Ollama's JSON Schema.
# We validate the E001 format locally in Python instead.
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


ApprovalType = Literal[
    "none",
    "analyst",
    "automatic",
]


ExecutionMode = Literal[
    "dry_run",
]


class PolicyDecision(BaseModel):
    policy_id: str

    policy_name: str

    matched: bool

    approval_type: ApprovalType

    execution_mode: ExecutionMode = "dry_run"

    actions: list[AllowedAction]

    reason: str


ResponsePlanStatus = Literal[
    "no_action",
    "pending_approval",
    "approved",
    "rejected",
    "ready_for_dry_run",
]


class ResponsePlan(BaseModel):
    policy_id: str

    actions: list[AllowedAction]

    approval_type: ApprovalType

    execution_mode: ExecutionMode

    status: ResponsePlanStatus

    reason: str


AnalystDecisionType = Literal[
    "approve",
    "reject",
]


class AnalystDecision(BaseModel):
    decision: AnalystDecisionType

    analyst_id: str = Field(
        min_length=1,
    )

    reason: str = Field(
        min_length=1,
    )


ActionExecutionStatus = Literal[
    "simulated",
]


ExecutionStatus = Literal[
    "completed",
]


class ActionExecutionResult(BaseModel):
    action: AllowedAction

    status: ActionExecutionStatus

    message: str


class DryRunExecutionResult(BaseModel):
    policy_id: str

    execution_mode: ExecutionMode

    status: ExecutionStatus

    action_results: list[ActionExecutionResult]


class InvestigationResponse(BaseModel):
    alert_id: str

    source: Literal[
        "manual",
        "mock",
        "wazuh",
        "dataset",
    ]

    status: str

    normalized_event: str

    analysis: AlertAnalysis

    evidence_records: list[EvidenceRecord]

    risk_assessment: RiskAssessment

    policy_decision: PolicyDecision

    response_plan: ResponsePlan

    execution_result: (
        DryRunExecutionResult | None
    ) = None

    investigation_iteration: int