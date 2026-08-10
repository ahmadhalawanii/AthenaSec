from typing import Any, Literal

from pydantic import BaseModel, Field


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
        description="Optional structured data associated with the alert.",
    )

class AlertAnalysis(BaseModel):
    classification: AttackClassification

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence in the classification from 0 to 1.",
    )

    severity_assessment: SeverityAssessment

    summary: str

    evidence: list[str] = Field(
        description=(
            "Only facts directly supported by the supplied security data."
        )
    )

    uncertainties: list[str] = Field(
        description=(
            "Things that cannot be determined from the supplied evidence."
        )
    )

    recommended_investigation_steps: list[str]

    recommended_response_actions: list[str]

    needs_more_evidence: bool