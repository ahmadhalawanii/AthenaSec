from app.graph.nodes.gather_evidence import (
    make_gather_evidence_node,
)
from app.schemas import (
    AlertAnalysis,
    EvidenceObservation,
    EvidenceRecord,
    EvidenceRequest,
    SecurityAlertInput,
)


def fake_evidence_provider(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[EvidenceObservation]:
    return [
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "No successful SSH authentication "
                "was found"
            ),
        ),
        EvidenceObservation(
            source="mock_wazuh",
            content=(
                "Source belongs to workstation-07"
            ),
        ),
    ]


def test_gather_evidence_assigns_immutable_ids():
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
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
        ],
        needs_more_evidence=True,
    )

    initial_record = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content="SSH failures detected.",
    )

    result = node(
        {
            "alert": alert,
            "analysis": analysis,
            "evidence_records": [
                initial_record,
            ],
            "investigation_iteration": 0,
        }
    )

    records = result["evidence_records"]

    assert len(records) == 3

    assert records[0].evidence_id == "E001"
    assert records[1].evidence_id == "E002"
    assert records[2].evidence_id == "E003"

    assert (
        records[1].content
        == "No successful SSH authentication was found"
    )

    assert result["investigation_iteration"] == 1