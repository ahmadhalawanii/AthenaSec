from app.graph.graph import build_investigation_graph
from app.schemas import (
    AlertAnalysis,
    EvidenceObservation,
    EvidenceRequest,
    SecurityAlertInput,
)

from app.schemas import (
    MISPEnrichment,
    MISPMatch,
    AttackPrediction,
)

def fake_analyzer(
    event: str,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="critical",
        summary=(
            "Critical SSH brute-force activity "
            "was detected against root."
        ),
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[
            (
                "Block 192.0.2.50 "
                "if policy permits"
            ),
        ],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def fake_evidence_provider(
    alert: SecurityAlertInput,
    requests: list[EvidenceRequest],
) -> list[EvidenceObservation]:
    return []

class FailingMLClassifier:
    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        raise RuntimeError(
            "ML model unavailable"
        )

class FakeMLClassifier:
    def __init__(self):
        self.calls = []

    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        self.calls.append(
            alert
        )

        return AttackPrediction(
            classification="brute_force",
            confidence=0.97,
            model_version="fake-ml-v1",
        )

class FakeMISPClient:
    def __init__(self):
        self.calls = []

    def enrich(
        self,
        indicators,
    ) -> MISPEnrichment:
        self.calls.append(
            indicators
        )

        return MISPEnrichment(
            queried_indicators=[
                value
                for _, value in indicators
            ],
            matches=[
                MISPMatch(
                    indicator_type="ip-src",
                    indicator_value="192.0.2.50",
                    event_id="42",
                    event_info=(
                        "Known brute-force "
                        "infrastructure"
                    ),
                    threat_level="high",
                )
            ],
        )

class FailingMISPClient:
    def enrich(
        self,
        indicators,
    ):
        raise RuntimeError(
            "MISP unavailable"
        )

def test_graph_creates_autonomous_execution_plan():
    graph = build_investigation_graph(
        analyzer=fake_analyzer,
        evidence_provider=(
            fake_evidence_provider
        ),
    )

    alert = SecurityAlertInput(
        alert_id="TEST-BF-001",
        source="manual",
        event_text=(
            "148 failed SSH login attempts "
            "to root from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "failed_attempts": 148,
            "privileged_target": True,
            "successful_authentication": True,
            "asset_criticality": "critical",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["status"] == "complete"

    assert (
        result[
            "analysis"
        ].classification
        == "brute_force"
    )

    assert (
        result[
            "risk_assessment"
        ].score
        >= 90
    )

    assert (
        result[
            "policy_decision"
        ].policy_id
        == "POL-BF-CRITICAL"
    )

    assert (
        result[
            "policy_decision"
        ].response_allowed
        is True
    )

    assert (
        result[
            "response_plan"
        ].status
        == "ready_for_execution"
    )

    assert (
        result[
            "response_plan"
        ].response_allowed
        is True
    )

    assert (
        result[
            "response_plan"
        ].actions
        == [
            "block_ip",
        ]
    )

def test_graph_runs_misp_enrichment_before_analysis():
    classifier = FakeMLClassifier()
    misp_client = FakeMISPClient()

    graph = build_investigation_graph(
        analyzer=fake_analyzer,
        evidence_provider=(
            fake_evidence_provider
        ),
        ml_classifier=classifier,
        misp_client=misp_client,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-MISP-001",
        source="wazuh",
        event_text=(
            "Repeated SSH login failures "
            "from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert misp_client.calls == [
        [
            (
                "ip-src",
                "192.0.2.50",
            )
        ]
    ]

    assert (
        result["misp_enrichment"]
        .queried_indicators
        == [
            "192.0.2.50",
        ]
    )

    assert len(
        result["misp_enrichment"].matches
    ) == 1

    assert (
        result["misp_enrichment"]
        .matches[0]
        .threat_level
        == "high"
    )

def test_graph_runs_ml_classification_before_analysis():
    classifier = FakeMLClassifier()

    graph = build_investigation_graph(
        analyzer=fake_analyzer,
        evidence_provider=(
            fake_evidence_provider
        ),
        ml_classifier=classifier,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-ML-001",
        source="manual",
        event_text=(
            "Repeated SSH login failures "
            "from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert len(
        classifier.calls
    ) == 1

    assert (
        classifier.calls[0].alert_id
        == "TEST-ML-001"
    )

    assert (
        result[
            "ml_prediction"
        ].classification
        == "brute_force"
    )

    assert (
        result[
            "ml_prediction"
        ].confidence
        == 0.97
    )

    assert (
        result[
            "ml_prediction"
        ].model_version
        == "fake-ml-v1"
    )

def test_graph_passes_misp_enrichment_to_analyzer():
    classifier = FakeMLClassifier()
    misp_client = FakeMISPClient()

    received_context = ""

    def analyzer_with_misp_context(
        event: str,
    ) -> AlertAnalysis:
        nonlocal received_context

        received_context = event

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="critical",
            summary=(
                "Critical SSH brute-force activity "
                "was detected."
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

    graph = build_investigation_graph(
        analyzer=analyzer_with_misp_context,
        evidence_provider=(
            fake_evidence_provider
        ),
        ml_classifier=classifier,
        misp_client=misp_client,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-MISP-CONTEXT-001",
        source="wazuh",
        event_text=(
            "Repeated SSH login failures "
            "from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
        },
    )

    graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert (
        "MISP enrichment"
        in received_context
    )

    assert (
        "192.0.2.50"
        in received_context
    )

    assert (
        "Known brute-force infrastructure"
        in received_context
    )

    assert (
        "threat_level=high"
        in received_context
    )

    assert (
        "event_id=42"
        in received_context
    )

def test_graph_passes_ml_prediction_to_analyzer():
    classifier = FakeMLClassifier()

    received_context = ""

    def analyzer_with_context_check(
        event: str,
    ) -> AlertAnalysis:
        nonlocal received_context

        received_context = event

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="critical",
            summary=(
                "Critical SSH brute-force activity "
                "was detected."
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

    def evidence_provider(
        alert: SecurityAlertInput,
        requests: list[EvidenceRequest],
    ) -> list[EvidenceObservation]:
        return [
            EvidenceObservation(
                source="wazuh",
                content=(
                    "source_ip=192.0.2.50; "
                    "target_user=root; "
                    "authentication failed"
                ),
            ),
        ]

    graph = build_investigation_graph(
        analyzer=analyzer_with_context_check,
        evidence_provider=(
            evidence_provider
        ),
        ml_classifier=classifier,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-ML-CONTEXT-001",
        source="manual",
        event_text=(
            "Repeated SSH login failures "
            "from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
        },
    )

    graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert (
        "ML prediction"
        in received_context
    )

    assert (
        "classification=brute_force"
        in received_context
    )

    assert (
        "confidence=0.97"
        in received_context
    )

    assert (
        "model_version=fake-ml-v1"
        in received_context
    )

def test_graph_fails_closed_when_ml_classifier_fails():
    classifier = FailingMLClassifier()

    graph = build_investigation_graph(
        analyzer=fake_analyzer,
        evidence_provider=(
            fake_evidence_provider
        ),
        ml_classifier=classifier,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-ML-FAIL-001",
        source="manual",
        event_text=(
            "148 failed SSH login attempts "
            "to root from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
            "failed_attempts": 148,
            "privileged_target": True,
            "successful_authentication": True,
            "asset_criticality": "critical",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert (
        result["ml_prediction"].classification
        == "unknown"
    )

    assert (
        result["ml_prediction"].confidence
        == 0.0
    )

    assert (
        result["ml_prediction"].model_version
        == "unavailable"
    )

    assert (
        "ML model unavailable"
        in result["ml_error"]
    )

    assert (
        result["policy_decision"].response_allowed
        is False
    )

    assert (
        result["response_plan"].status
        == "create_case"
    )

    assert (
        result["response_plan"].response_allowed
        is False
    )

def test_graph_continues_when_misp_enrichment_fails():
    classifier = FakeMLClassifier()
    misp_client = FailingMISPClient()

    received_context = ""

    def analyzer_with_failed_misp_context(
        event: str,
    ) -> AlertAnalysis:
        nonlocal received_context

        received_context = event

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "SSH brute-force activity "
                "was detected."
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

    graph = build_investigation_graph(
        analyzer=analyzer_with_failed_misp_context,
        evidence_provider=(
            fake_evidence_provider
        ),
        ml_classifier=classifier,
        misp_client=misp_client,
    )

    alert = SecurityAlertInput(
        alert_id="TEST-MISP-FAIL-001",
        source="wazuh",
        event_text=(
            "Repeated SSH login failures "
            "from 192.0.2.50"
        ),
        metadata={
            "source_ip": "192.0.2.50",
            "target_user": "root",
        },
    )

    result = graph.invoke(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert (
        result["misp_error"]
        == "MISP unavailable"
    )

    assert (
        result["misp_enrichment"].matches
        == []
    )

    assert (
        "No MISP matches found."
        in received_context
    )

    assert (
        result["status"]
        == "complete"
    )