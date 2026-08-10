import pytest
from pydantic import ValidationError

from app.schemas import AlertAnalysis


def test_valid_alert_analysis():
    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="Repeated SSH authentication failures targeted the root account.",
        evidence=[
            "148 failed SSH login attempts",
            "Root account was targeted",
            "Attempts occurred within five minutes",
        ],
        uncertainties=[
            "No evidence confirms whether authentication eventually succeeded"
        ],
        recommended_investigation_steps=[
            "Review SSH authentication logs",
            "Check for successful login events",
        ],
        recommended_response_actions=[
            "Consider temporarily blocking the source if policy permits"
        ],
        needs_more_evidence=True,
    )

    assert analysis.classification == "brute_force"
    assert analysis.confidence == 0.95
    assert analysis.needs_more_evidence is True


def test_confidence_cannot_exceed_one():
    with pytest.raises(ValidationError):
        AlertAnalysis(
            classification="brute_force",
            confidence=1.5,
            severity_assessment="high",
            summary="Test",
            evidence=["Test evidence"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            needs_more_evidence=False,
        )