from app.graph.graph import build_investigation_graph
from app.schemas import (
    AlertAnalysis,
    EvidenceRequest,
    SecurityAlertInput,
)


def make_fake_analyzer():
    calls = 0

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        nonlocal calls
        calls += 1

        if calls == 1:
            return AlertAnalysis(
                classification="brute_force",
                confidence=0.85,
                severity_assessment="high",
                summary=(
                    "SSH brute-force activity "
                    "requires additional evidence."
                ),
                evidence=[
                    "148 failed SSH login attempts",
                ],
                uncertainties=[
                    "Successful authentication "
                    "status is unknown",
                ],
                recommended_investigation_steps=[],
                recommended_response_actions=[],
                requested_evidence=[
                    "authentication_history",
                    "source_endpoint_context",
                ],
                needs_more_evidence=True,
            )

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.97,
            severity_assessment="high",
            summary=(
                "SSH brute-force activity confirmed "
                "with additional context."
            ),
            evidence=[
                "148 failed SSH login attempts",
                "No successful authentication was found",
                "Source belongs to workstation-07",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    return fake_analyzer


def fake_evidence_provider(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[str]:
    assert requests == [
        "authentication_history",
        "source_endpoint_context",
    ]

    return [
        "No successful authentication was found",
        "Source belongs to workstation-07",
    ]


def test_graph_normalizes_security_alert():
    graph = build_investigation_graph(
        analyzer=make_fake_analyzer(),
        evidence_provider=fake_evidence_provider,
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

    assert result["normalized_event"] == (
        "148 failed SSH login attempts "
        "occurred against root."
    )

    assert result["status"] == "complete"


def test_graph_gathers_only_requested_evidence():
    graph = build_investigation_graph(
        analyzer=make_fake_analyzer(),
        evidence_provider=fake_evidence_provider,
    )

    alert = SecurityAlertInput(
        alert_id="ALT-AI-001",
        source="mock",
        event_text=(
            "148 failed SSH login attempts "
            "occurred against root."
        ),
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["status"] == "complete"

    assert result["investigation_iteration"] == 1

    assert result["gathered_evidence"] == [
        "No successful authentication was found",
        "Source belongs to workstation-07",
    ]

    assert (
        result["analysis"].classification
        == "brute_force"
    )

    assert result["analysis"].confidence == 0.97

    assert (
        result["analysis"].needs_more_evidence
        is False
    )

    assert (
        result["analysis"].requested_evidence
        == []
    )