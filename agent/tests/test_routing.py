from app.graph.routing import route_after_analysis
from app.schemas import AlertAnalysis


def make_analysis(
    needs_more_evidence: bool,
    requested_evidence=None,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.90,
        severity_assessment="high",
        summary="Test analysis",
        evidence=["Evidence"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=(
            requested_evidence or []
        ),
        needs_more_evidence=needs_more_evidence,
    )


def test_routes_to_evidence_when_requested():
    result = route_after_analysis(
        {
            "analysis": make_analysis(
                True,
                [
                    "authentication_history",
                ],
            ),
            "investigation_iteration": 0,
        }
    )

    assert result == "gather_evidence"


def test_routes_to_finalize_when_evidence_not_needed():
    result = route_after_analysis(
        {
            "analysis": make_analysis(
                False
            ),
            "investigation_iteration": 0,
        }
    )

    assert result == "finalize_investigation"


def test_routes_to_finalize_when_no_tool_requested():
    result = route_after_analysis(
        {
            "analysis": make_analysis(
                True,
                [],
            ),
            "investigation_iteration": 0,
        }
    )

    assert result == "finalize_investigation"


def test_routes_to_finalize_after_max_iterations():
    result = route_after_analysis(
        {
            "analysis": make_analysis(
                True,
                [
                    "authentication_history",
                ],
            ),
            "investigation_iteration": 1,
        }
    )

    assert result == "finalize_investigation"