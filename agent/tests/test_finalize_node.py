from app.graph.nodes.finalize import finalize_investigation
from app.schemas import AlertAnalysis


def test_finalize_marks_investigation_complete():
    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="Brute-force activity detected.",
        evidence=["148 failed SSH login attempts"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        needs_more_evidence=False,
    )

    result = finalize_investigation(
        {
            "analysis": analysis,
            "status": "analyzed",
        }
    )

    assert result["status"] == "complete"