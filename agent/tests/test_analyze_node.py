import pytest
from pydantic import ValidationError

from app.graph.nodes.analyze import (
    build_analysis_context,
    make_analyze_alert_node,
)
from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceRecord,
    SecurityAlertInput,
)


def make_alert() -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="ALT-001",
        source="wazuh",
        event_text=(
            "Failed SSH logins from "
            "192.0.2.50 targeting root"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
        },
    )


def make_evidence() -> list[EvidenceRecord]:
    return [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            content=(
                "Failed SSH logins from "
                "192.0.2.50 targeting root"
            ),
        ),
        EvidenceRecord(
            evidence_id="E002",
            source="wazuh",
            content=(
                "source_ip=192.0.2.50; "
                "target_user=root; "
                "authentication failed"
            ),
        ),
    ]


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
                "E002",
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
            "alert": make_alert(),
            "evidence_records": make_evidence(),
        }
    )

    assert "[E001]" in received_context
    assert "[E002]" in received_context

    assert (
        "192.0.2.50"
        in received_context
    )

    assert result[
        "analysis"
    ].classification == "brute_force"


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
                "alert": make_alert(),
                "evidence_records": make_evidence(),
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
                "alert": make_alert(),
                "evidence_records": make_evidence(),
            }
        )


def test_analyze_node_rejects_ungrounded_ip_in_recommendation():
    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "Brute force activity from "
                "192.0.2.50"
            ),
            evidence_refs=[
                "E001",
                "E002",
            ],
            uncertainties=[],
            recommended_investigation_steps=[
                (
                    "Review authentication activity "
                    "from 192.0.2.50"
                ),
            ],
            recommended_response_actions=[
                (
                    "Block 192.0.0.50 "
                    "at the firewall"
                ),
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    with pytest.raises(
        ValueError,
        match="ungrounded IP",
    ):
        node(
            {
                "alert": make_alert(),
                "evidence_records": make_evidence(),
            }
        )


def test_analyze_node_allows_grounded_ip_in_recommendation():
    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "Brute force activity from "
                "192.0.2.50"
            ),
            evidence_refs=[
                "E001",
                "E002",
            ],
            uncertainties=[],
            recommended_investigation_steps=[
                (
                    "Review authentication activity "
                    "from 192.0.2.50"
                ),
            ],
            recommended_response_actions=[
                (
                    "Block 192.0.2.50 "
                    "if policy permits"
                ),
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    result = node(
        {
            "alert": make_alert(),
            "evidence_records": make_evidence(),
        }
    )

    assert (
        result[
            "analysis"
        ].recommended_response_actions[
            0
        ]
        == (
            "Block 192.0.2.50 "
            "if policy permits"
        )
    )


def test_build_analysis_context_contains_evidence_ids():
    context = build_analysis_context(
        {
            "alert": make_alert(),
            "evidence_records": make_evidence(),
        }
    )

    assert "[E001]" in context
    assert "[E002]" in context

def test_analyze_node_rejects_ungrounded_user_in_recommendation():
    evidence = [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            content=(
                "source_ip=192.0.2.50; "
                "target_user=root; "
                "agent_name=workstation-07"
            ),
        ),
    ]

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Brute force targeting root.",
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[
                "Lock user administrator"
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    with pytest.raises(
        ValueError,
        match="ungrounded user",
    ):
        node(
            {
                "alert": make_alert(),
                "evidence_records": evidence,
            }
        )


def test_analyze_node_allows_grounded_user_in_recommendation():
    evidence = [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            content=(
                "source_ip=192.0.2.50; "
                "target_user=root; "
                "agent_name=workstation-07"
            ),
        ),
    ]

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="Brute force targeting root.",
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[
                "Lock user root if policy permits"
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    result = node(
        {
            "alert": make_alert(),
            "evidence_records": evidence,
        }
    )

    assert (
        result[
            "analysis"
        ].recommended_response_actions[0]
        == "Lock user root if policy permits"
    )


def test_analyze_node_rejects_ungrounded_host_in_recommendation():
    evidence = [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            content=(
                "source_ip=192.0.2.50; "
                "target_user=root; "
                "agent_name=workstation-07"
            ),
        ),
    ]

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "Attack observed on workstation-07."
            ),
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[
                "Isolate host workstation-99"
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    with pytest.raises(
        ValueError,
        match="ungrounded host",
    ):
        node(
            {
                "alert": make_alert(),
                "evidence_records": evidence,
            }
        )


def test_analyze_node_allows_grounded_host_in_recommendation():
    evidence = [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            content=(
                "source_ip=192.0.2.50; "
                "target_user=root; "
                "agent_name=workstation-07"
            ),
        ),
    ]

    def fake_analyzer(
        event: str,
    ) -> AlertAnalysis:
        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "Attack observed on workstation-07."
            ),
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[
                (
                    "Isolate host workstation-07 "
                    "if policy permits"
                )
            ],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    node = make_analyze_alert_node(
        fake_analyzer
    )

    result = node(
        {
            "alert": make_alert(),
            "evidence_records": evidence,
        }
    )

    assert (
        result[
            "analysis"
        ].recommended_response_actions[0]
        == (
            "Isolate host workstation-07 "
            "if policy permits"
        )
    )

def test_build_analysis_context_contains_ml_prediction():
    prediction = AttackPrediction(
        classification="brute_force",
        confidence=0.97,
        model_version="fake-ml-v1",
    )

    context = build_analysis_context(
        {
            "alert": make_alert(),
            "ml_prediction": prediction,
            "evidence_records": make_evidence(),
        }
    )

    assert (
        "ML prediction"
        in context
    )

    assert (
        "classification=brute_force"
        in context
    )

    assert (
        "confidence=0.97"
        in context
    )

    assert (
        "model_version=fake-ml-v1"
        in context
    )

    assert "[E001]" in context
    assert "[E002]" in context