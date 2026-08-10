from app.graph.nodes.analyze import make_analyze_alert_node
from app.schemas import AlertAnalysis, SecurityAlertInput


def fake_analyzer(event: str) -> AlertAnalysis:
    assert "148 failed SSH login attempts" in event

    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="Repeated SSH authentication failures were detected.",
        evidence=[
            "148 failed SSH login attempts",
            "The root account was targeted",
        ],
        uncertainties=[
            "No successful authentication information was provided",
        ],
        recommended_investigation_steps=[
            "Review SSH authentication logs",
        ],
        recommended_response_actions=[
            "Consider restricting the source if policy permits",
        ],
        needs_more_evidence=True,
    )


def test_analyze_node_stores_structured_analysis():
    node = make_analyze_alert_node(fake_analyzer)

    alert = SecurityAlertInput(
        alert_id="ALT-TEST-001",
        source="mock",
        event_text="148 failed SSH login attempts.",
    )

    result = node(
        {
            "alert": alert,
            "normalized_event": (
                "148 failed SSH login attempts "
                "against the root account."
            ),
            "status": "normalized",
            "investigation_iteration": 0,
            "gathered_evidence": [],
        }
    )

    assert result["analysis"].classification == "brute_force"
    assert result["analysis"].confidence == 0.95
    assert result["status"] == "analyzed"