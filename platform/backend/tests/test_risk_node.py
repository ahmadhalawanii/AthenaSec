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

def test_risk_context_treats_missing_wazuh_values_as_defaults():
    # A Wazuh sudo alert has no failure count, so the parser stores None.
    from app.graph.nodes.risk import build_risk_context

    alert = SecurityAlertInput(
        alert_id="ALT-RISK-NONE",
        source="wazuh",
        event_text="Successful sudo to ROOT executed.",
        metadata={
            "failed_attempts": None,
            "privileged_target": None,
            "privilege_change_observed": None,
            "policy_violation_observed": None,
            "asset_criticality": None,
        },
    )

    context = build_risk_context({"alert": alert})

    assert context.failed_attempts == 0
    assert context.privileged_target is False
    assert context.asset_criticality == "medium"
