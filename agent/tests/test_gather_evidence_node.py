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


captured_requests: list[EvidenceRequest] = []


def fake_evidence_provider(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[EvidenceObservation]:
    captured_requests.clear()
    captured_requests.extend(requests)

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


def make_initial_record() -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content="SSH failures detected.",
    )


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

    result = node(
        {
            "alert": alert,
            "analysis": analysis,
            "evidence_records": [
                make_initial_record(),
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


def test_wazuh_brute_force_uses_default_evidence_requests():
    node = make_gather_evidence_node(
        fake_evidence_provider
    )

    alert = SecurityAlertInput(
        alert_id="ALT-WAZUH-001",
        source="wazuh",
        event_text="SSH brute force detected.",
    )

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force detected.",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    node(
        {
            "alert": alert,
            "analysis": analysis,
            "evidence_records": [
                make_initial_record(),
            ],
            "investigation_iteration": 0,
        }
    )

    assert captured_requests == [
        "authentication_history",
        "source_endpoint_context",
        "related_security_events",
    ]


def test_wazuh_privilege_misuse_uses_default_evidence_requests():
    node = make_gather_evidence_node(
        fake_evidence_provider
    )

    alert = SecurityAlertInput(
        alert_id="ALT-WAZUH-002",
        source="wazuh",
        event_text="Privilege misuse detected.",
    )

    analysis = AlertAnalysis(
        classification="privilege_misuse",
        confidence=0.95,
        severity_assessment="high",
        summary="Privilege misuse detected.",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    node(
        {
            "alert": alert,
            "analysis": analysis,
            "evidence_records": [
                make_initial_record(),
            ],
            "investigation_iteration": 0,
        }
    )

    assert captured_requests == [
        "privilege_activity",
        "authentication_history",
        "related_security_events",
    ]


def test_explicit_llm_requests_are_preserved():
    node = make_gather_evidence_node(
        fake_evidence_provider
    )

    alert = SecurityAlertInput(
        alert_id="ALT-WAZUH-003",
        source="wazuh",
        event_text="SSH brute force detected.",
    )

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force detected.",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
        ],
        needs_more_evidence=True,
    )

    node(
        {
            "alert": alert,
            "analysis": analysis,
            "evidence_records": [
                make_initial_record(),
            ],
            "investigation_iteration": 0,
        }
    )

    assert captured_requests == [
        "authentication_history",
    ]