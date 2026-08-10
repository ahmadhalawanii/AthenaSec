from app.graph.graph import build_investigation_graph
from app.schemas import (
    AlertAnalysis,
    EvidenceObservation,
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
                summary="More evidence required.",
                evidence_refs=[
                    "E001",
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

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Brute force supported.",
            evidence_refs=[
                "E001",
                "E002",
                "E003",
                "E004",
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
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content="151 failed SSH attempts.",
        ),
        EvidenceObservation(
            source="mock_wazuh",
            content="No successful login found.",
        ),
        EvidenceObservation(
            source="mock_wazuh",
            content="Source is workstation-07.",
        ),
    ]


def test_graph_creates_pending_response_plan():
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
        metadata={
            "failed_attempts": 148,
            "privileged_target": True,
            "successful_authentication": None,
            "asset_criticality": "medium",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["status"] == "complete"

    assert result["risk_assessment"].score == 75

    assert (
        result["policy_decision"].policy_id
        == "POL-BF-HIGH"
    )

    plan = result["response_plan"]

    assert (
        plan.status
        == "pending_approval"
    )

    assert (
        plan.execution_mode
        == "dry_run"
    )

    assert plan.actions == [
        "block_ip",
        "notify_administrator",
        "create_case",
    ]