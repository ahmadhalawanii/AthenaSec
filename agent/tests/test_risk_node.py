from app.graph.nodes.risk import (
    calculate_investigation_risk,
)
from app.schemas import (
    AlertAnalysis,
    SecurityAlertInput,
)


def test_risk_node_calculates_risk_from_alert_metadata():
    alert = SecurityAlertInput(
        alert_id="ALT-RISK-001",
        source="mock",
        event_text="SSH brute force detected.",
        metadata={
            "failed_attempts": 148,
            "privileged_target": True,
            "successful_authentication": None,
            "asset_criticality": "medium",
        },
    )

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    result = calculate_investigation_risk(
        {
            "alert": alert,
            "analysis": analysis,
            "status": "analyzed",
        }
    )

    assert result["risk_context"].failed_attempts == 148

    assert (
        result["risk_context"].privileged_target
        is True
    )

    assert result["risk_assessment"].score == 75
    assert result["risk_assessment"].band == "high"

    assert result["status"] == "risk_scored"