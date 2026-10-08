from app.graph.nodes.gather_evidence import (
    make_gather_evidence_node,
)
from app.graph.nodes.normalize import (
    normalize_alert,
)
from app.schemas import (
    AlertAnalysis,
    EvidenceObservation,
    EvidenceRecord,
    SecurityAlertInput,
)


def make_alert() -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="ALT-WAZUH-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
    )


def make_analysis() -> AlertAnalysis:
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[
            "authentication_history",
        ],
        needs_more_evidence=True,
    )


def test_normalized_alert_is_tagged_as_alert_evidence():
    result = normalize_alert(
        {
            "alert": make_alert(),
            "status": "received",
        }
    )

    record = (
        result[
            "evidence_records"
        ][0]
    )

    assert (
        record.evidence_type
        == "alert"
    )


def test_gather_evidence_preserves_evidence_type():
    def provider(
        alert,
        requests,
    ):
        return [
            EvidenceObservation(
                source="wazuh",
                evidence_type=(
                    "authentication_history"
                ),
                content=(
                    "No successful authentication "
                    "was observed."
                ),
            )
        ]

    node = make_gather_evidence_node(
        provider
    )

    result = node(
        {
            "alert": make_alert(),
            "analysis": make_analysis(),
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    evidence_type="alert",
                    content=(
                        "Repeated SSH failures."
                    ),
                ),
            ],
            "investigation_iteration": 0,
        }
    )

    records = result[
        "evidence_records"
    ]

    assert (
        records[1].evidence_type
        == "authentication_history"
    )


def test_evidence_type_is_optional_for_legacy_records():
    record = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content="Legacy evidence.",
    )

    assert (
        record.evidence_type
        is None
    )