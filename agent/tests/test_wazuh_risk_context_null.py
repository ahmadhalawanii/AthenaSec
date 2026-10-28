import pytest
from pydantic import ValidationError

from app.graph.nodes.risk import build_risk_context
from app.schemas import AlertAnalysis, SecurityAlertInput
from app.services.risk_engine import calculate_risk


def make_alert(metadata):
    return SecurityAlertInput(
        alert_id="TEST-RISK-NULL",
        source="wazuh",
        event_text="Synthetic Wazuh security event",
        metadata=metadata,
    )


@pytest.mark.parametrize(
    "raw, expected",
    [(None, 0), (0, 0), (18, 18)],
)
def test_failed_attempts_are_handled_without_changing_alert(raw, expected):
    alert = make_alert({"failed_attempts": raw})

    context = build_risk_context({"alert": alert})

    assert context.failed_attempts == expected
    assert alert.metadata["failed_attempts"] == raw


def test_missing_failed_attempts_defaults_to_no_volume_points():
    alert = make_alert({})
    context = build_risk_context({"alert": alert})

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.9,
        severity_assessment="medium",
        summary="Synthetic test",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    risk = calculate_risk(analysis, context)

    assert context.failed_attempts == 0
    assert "failed_attempt_volume" not in {
        factor.name for factor in risk.factors
    }


@pytest.mark.parametrize("invalid", [-1, "invalid"])
def test_invalid_failed_attempt_counts_are_rejected(invalid):
    with pytest.raises(ValidationError):
        build_risk_context({
            "alert": make_alert({"failed_attempts": invalid})
        })
