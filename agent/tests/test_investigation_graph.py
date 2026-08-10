from app.graph.graph import build_investigation_graph
from app.schemas import AlertAnalysis, SecurityAlertInput


def fake_analyzer(event: str) -> AlertAnalysis:
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.97,
        severity_assessment="high",
        summary="SSH brute-force activity detected.",
        evidence=[
            "148 failed SSH login attempts",
        ],
        uncertainties=[
            "Successful authentication status is unknown",
        ],
        recommended_investigation_steps=[
            "Review authentication logs",
        ],
        recommended_response_actions=[
            "Consider restricting the source",
        ],
        needs_more_evidence=True,
    )


def test_graph_normalizes_security_alert():
    graph = build_investigation_graph(
        analyzer=fake_analyzer
    )

    alert = SecurityAlertInput(
        alert_id="ALT-TEST-001",
        source="mock",
        event_text="""
            148 failed SSH login attempts
            occurred against root.
        """,
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["alert"].alert_id == "ALT-TEST-001"

    assert result["normalized_event"] == (
        "148 failed SSH login attempts "
        "occurred against root."
    )

    assert result["status"] == "complete"
    assert result["investigation_iteration"] == 0


def test_graph_runs_complete_ai_analysis():
    graph = build_investigation_graph(
        analyzer=fake_analyzer
    )

    alert = SecurityAlertInput(
        alert_id="ALT-AI-001",
        source="mock",
        event_text="""
            148 failed SSH login attempts
            occurred against root.
        """,
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["status"] == "complete"

    assert (
        result["analysis"].classification
        == "brute_force"
    )

    assert result["analysis"].confidence == 0.97