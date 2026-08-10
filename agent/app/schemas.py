from typing import Literal

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