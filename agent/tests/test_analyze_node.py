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

def test_analyze_node_includes_gathered_evidence():
    received_context = ""

    def analyzer(event: str) -> AlertAnalysis:
        nonlocal received_context
        received_context = event

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.98,
            severity_assessment="high",
            summary="SSH brute force detected.",
            evidence=[
                "148 failed SSH login attempts",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(analyzer)

    alert = SecurityAlertInput(
        alert_id="ALT-TEST-002",
        source="mock",
        event_text="SSH failures detected.",
    )

    node(
        {
            "alert": alert,
            "normalized_event": "SSH failures detected.",
            "gathered_evidence": [
                "No successful authentication was found",
                "Source belongs to workstation-07",
            ],
            "investigation_iteration": 1,
            "status": "needs_evidence",
        }
    )

    assert "ORIGINAL EVENT:" in received_context

    assert (
        "No successful authentication was found"
        in received_context
    )

    assert (
        "Source belongs to workstation-07"
        in received_context
    )