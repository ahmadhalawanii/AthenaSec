import pytest
from pydantic import ValidationError

from app.graph.nodes.analyze import (
    make_analyze_alert_node,
)
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
)


def test_analyze_node_uses_evidence_records():
    received_context = ""

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        nonlocal received_context

        received_context = event

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="SSH brute force suspected.",
            evidence_refs=[
                "E001",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    result = node(
        {
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    content=(
                        "148 failed SSH login attempts"
                    ),
                ),
            ],
        }
    )

    assert "[E001]" in received_context

    assert (
        "148 failed SSH login attempts"
        in received_context
    )

    assert result["analysis"].evidence_refs == [
        "E001",
    ]


def test_analyze_node_rejects_nonexistent_reference():
    def bad_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Test",
            evidence_refs=[
                "E999",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        bad_analyzer
    )

    with pytest.raises(
        ValueError,
        match="E999",
    ):
        node(
            {
                "evidence_records": [
                    EvidenceRecord(
                        evidence_id="E001",
                        source="alert",
                        content="Real evidence",
                    ),
                ],
            }
        )


def test_analyze_node_rejects_empty_evidence_refs():
    def bad_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="SSH brute force detected.",
            evidence_refs=[],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        bad_analyzer
    )

    with pytest.raises(
        ValidationError,
    ):
        node(
            {
                "evidence_records": [
                    EvidenceRecord(
                        evidence_id="E001",
                        source="alert",
                        content=(
                            "148 failed SSH login attempts"
                        ),
                    ),
                ],
            }
        )