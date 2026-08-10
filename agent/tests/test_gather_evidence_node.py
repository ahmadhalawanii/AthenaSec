from app.graph.nodes.gather_evidence import (
    make_gather_evidence_node,
)
from app.schemas import (
    AlertAnalysis,
    EvidenceRequest,
    SecurityAlertInput,
)


def fake_evidence_provider(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[str]:
    assert requests == [
        "authentication_history",
        "source_endpoint_context",
    ]

    return [
        "No successful SSH authentication was found",
        "Source belongs to workstation-07",
    ]


def test_gather_evidence_uses_requested_types():
    node = make_gather_evidence_node(
        fake_evidence_provider
    )

    alert = SecurityAlertInput(
        alert_id="ALT-001",
        source="mock",
        event_text="SSH failures detected.",
    )

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.90,
        severity_assessment="high",
        summary="SSH brute force suspected.",
        evidence=[
            "148 failed SSH attempts",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
            "source_endpoint_context",
        ],
        needs_more_evidence=True,
    )

    result = node(
        {
            "alert": alert,
            "analysis": analysis,
            "gathered_evidence": [],
            "investigation_iteration": 0,
            "status": "needs_evidence",
        }
    )

    assert result["gathered_evidence"] == [
        "No successful SSH authentication was found",
        "Source belongs to workstation-07",
    ]

    assert result["investigation_iteration"] == 1

    assert result["status"] == "evidence_gathered"