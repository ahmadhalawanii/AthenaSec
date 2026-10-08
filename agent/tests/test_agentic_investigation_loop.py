from app.graph.graph import (
    build_investigation_graph,
)
from app.graph.nodes.evidence_sufficiency import (
    assess_evidence_sufficiency,
)
from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceObservation,
    EvidenceRecord,
    SecurityAlertInput,
)


def make_alert() -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="ALT-AGENTIC-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication "
            "failures were detected."
        ),
        metadata={
            "failed_attempts": 12,
            "source_ip": "203.0.113.10",
            "target_user": "root",
        },
    )


def make_analysis(
    classification: str = "brute_force",
) -> AlertAnalysis:
    return AlertAnalysis(
        classification=classification,
        confidence=0.95,
        severity_assessment="high",
        summary=(
            "Suspicious authentication "
            "activity was detected."
        ),
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def test_wazuh_loop_requests_only_missing_evidence_until_sufficient():
    analyzer_calls = []

    def analyzer(
        context: str,
    ) -> AlertAnalysis:
        analyzer_calls.append(
            context
        )

        return make_analysis()

    requested_rounds = []

    def provider(
        alert,
        requests,
    ):
        requested_rounds.append(
            list(requests)
        )

        if len(requested_rounds) == 1:
            return [
                EvidenceObservation(
                    source="wazuh",
                    evidence_type=(
                        "authentication_history"
                    ),
                    content=(
                        "Authentication history "
                        "was reviewed."
                    ),
                ),
            ]

        return [
            EvidenceObservation(
                source="wazuh",
                evidence_type=(
                    "source_endpoint_context"
                ),
                content=(
                    "Source endpoint context "
                    "was reviewed."
                ),
            ),
        ]

    graph = build_investigation_graph(
        analyzer=analyzer,
        evidence_provider=provider,
    )

    result = graph.invoke(
        {
            "alert": make_alert(),
            "status": "received",
        }
    )

    assert requested_rounds == [
        [
            "authentication_history",
            "source_endpoint_context",
        ],
        [
            "source_endpoint_context",
        ],
    ]

    assert len(analyzer_calls) == 3

    assert (
        result[
            "investigation_iteration"
        ]
        == 2
    )

    assert (
        result[
            "evidence_sufficiency"
        ].sufficient
        is True
    )

    assert (
        result[
            "evidence_sufficiency"
        ].missing_evidence
        == []
    )

    assert (
        result[
            "investigation_budget_exhausted"
        ]
        is False
    )

    assert result["status"] == "complete"


def test_wazuh_loop_stops_when_budget_is_exhausted():
    analyzer_calls = []
    provider_calls = []

    def analyzer(
        context: str,
    ) -> AlertAnalysis:
        analyzer_calls.append(
            context
        )

        return make_analysis()

    def empty_provider(
        alert,
        requests,
    ):
        provider_calls.append(
            list(requests)
        )

        return []

    graph = build_investigation_graph(
        analyzer=analyzer,
        evidence_provider=(
            empty_provider
        ),
    )

    result = graph.invoke(
        {
            "alert": make_alert(),
            "status": "received",
        }
    )

    assert len(provider_calls) == 3

    assert len(analyzer_calls) == 4

    assert (
        result[
            "investigation_iteration"
        ]
        == 3
    )

    assert (
        result[
            "evidence_sufficiency"
        ].sufficient
        is False
    )

    assert (
        result[
            "evidence_sufficiency"
        ].missing_evidence
        == [
            "authentication_history",
            "source_endpoint_context",
        ]
    )

    assert (
        result[
            "investigation_budget_exhausted"
        ]
        is True
    )

    assert result["status"] == "complete"


def test_ml_classification_controls_evidence_requirements():
    prediction = AttackPrediction(
        classification="privilege_misuse",
        confidence=0.97,
        model_version="test-model",
    )

    analysis = make_analysis(
        classification="brute_force",
    )

    result = assess_evidence_sufficiency(
        {
            "alert": make_alert(),
            "ml_prediction": prediction,
            "analysis": analysis,
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    evidence_type="alert",
                    content="Original alert.",
                ),
                EvidenceRecord(
                    evidence_id="E002",
                    source="wazuh",
                    evidence_type=(
                        "privilege_activity"
                    ),
                    content=(
                        "Privilege activity reviewed."
                    ),
                ),
                EvidenceRecord(
                    evidence_id="E003",
                    source="wazuh",
                    evidence_type=(
                        "authentication_history"
                    ),
                    content=(
                        "Authentication history "
                        "reviewed."
                    ),
                ),
            ],
            "investigation_iteration": 1,
        }
    )

    assessment = result[
        "evidence_sufficiency"
    ]

    assert (
        assessment.classification
        == "privilege_misuse"
    )

    assert assessment.sufficient is True

    assert (
        assessment.required_evidence
        == [
            "privilege_activity",
            "authentication_history",
        ]
    )