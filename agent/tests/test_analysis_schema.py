import pytest
from pydantic import ValidationError

from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
)


def test_valid_alert_analysis():
    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="Repeated SSH failures detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[
            "Successful authentication status is unknown",
        ],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
        ],
        needs_more_evidence=True,
    )

    assert analysis.classification == "brute_force"
    assert analysis.evidence_refs == ["E001"]


def test_confidence_cannot_exceed_one():
    with pytest.raises(ValidationError):
        AlertAnalysis(
            classification="brute_force",
            confidence=1.5,
            severity_assessment="high",
            summary="Test",
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )


def test_analysis_accepts_requested_evidence():
    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force suspected.",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
            "source_endpoint_context",
        ],
        needs_more_evidence=True,
    )

    assert analysis.requested_evidence == [
        "authentication_history",
        "source_endpoint_context",
    ]


def test_analysis_rejects_unknown_evidence_type():
    with pytest.raises(ValidationError):
        AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Test",
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[
                "run_random_command",
            ],
            needs_more_evidence=True,
        )


def test_evidence_reference_requires_valid_id():
    with pytest.raises(ValidationError):
        AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Test",
            evidence_refs=[
                "something-made-up",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )


def test_evidence_record_is_immutable():
    evidence = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content="148 failed SSH login attempts.",
    )

    with pytest.raises(ValidationError):
        evidence.content = "Changed evidence"

def test_analysis_rejects_empty_evidence_refs():
    with pytest.raises(ValidationError):
        AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="SSH brute force detected.",
            evidence_refs=[],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )