from app.graph.routing import (
    route_after_analysis,
)
from app.schemas import (
    AlertAnalysis,
    SecurityAlertInput,
)


def make_analysis(
    *,
    classification: str = "brute_force",
    needs_more_evidence: bool = False,
    requested_evidence: list[str] | None = None,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification=classification,
        confidence=0.95,
        severity_assessment="high",
        summary="Test analysis",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=(
            requested_evidence
            if requested_evidence is not None
            else []
        ),
        needs_more_evidence=needs_more_evidence,
    )


def make_alert(
    *,
    source: str = "manual",
) -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="test-alert-001",
        source=source,
        event_text="Test security event",
        metadata={},
    )


def test_routes_to_evidence_when_requested():
    state = {
        "alert": make_alert(),
        "analysis": make_analysis(
            needs_more_evidence=True,
            requested_evidence=[
                "authentication_history",
            ],
        ),
        "investigation_iteration": 0,
    }

    assert (
        route_after_analysis(state)
        == "gather_evidence"
    )


def test_routes_to_risk_when_evidence_not_needed():
    state = {
        "alert": make_alert(),
        "analysis": make_analysis(
            needs_more_evidence=False,
        ),
        "investigation_iteration": 0,
    }

    assert (
        route_after_analysis(state)
        == "calculate_risk"
    )


def test_routes_to_risk_when_no_tool_requested():
    state = {
        "alert": make_alert(),
        "analysis": make_analysis(
            needs_more_evidence=True,
            requested_evidence=[],
        ),
        "investigation_iteration": 0,
    }

    assert (
        route_after_analysis(state)
        == "calculate_risk"
    )


def test_routes_to_risk_after_max_iterations():
    state = {
        "alert": make_alert(),
        "analysis": make_analysis(
            needs_more_evidence=True,
            requested_evidence=[
                "authentication_history",
            ],
        ),
        "investigation_iteration": 1,
    }

    assert (
        route_after_analysis(state)
        == "calculate_risk"
    )


def test_wazuh_brute_force_gathers_evidence_even_if_llm_declines():
    state = {
        "alert": make_alert(
            source="wazuh",
        ),
        "analysis": make_analysis(
            classification="brute_force",
            needs_more_evidence=False,
            requested_evidence=[],
        ),
        "investigation_iteration": 0,
    }

    assert (
        route_after_analysis(state)
        == "gather_evidence"
    )


def test_manual_brute_force_does_not_force_wazuh_evidence():
    state = {
        "alert": make_alert(
            source="manual",
        ),
        "analysis": make_analysis(
            classification="brute_force",
            needs_more_evidence=False,
            requested_evidence=[],
        ),
        "investigation_iteration": 0,
    }

    assert (
        route_after_analysis(state)
        == "calculate_risk"
    )