from datetime import (
    datetime,
    timedelta,
    timezone,
)

from fastapi.testclient import TestClient

from app.graph.nodes.classify_ml import (
    make_ml_classification_node,
)
from app.main import create_app
from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceRecord,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)
from app.services.audit_store import (
    InMemoryAuditStore,
)
from app.services.benign_investigation import (
    build_benign_investigation,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)


BASE_TIME = datetime(
    2026,
    10,
    8,
    8,
    0,
    tzinfo=timezone.utc,
)


def make_raw_alert(
    *,
    alert_id: str = "1716206454.722325",
    minute: int = 0,
):
    observed_at = (
        BASE_TIME
        + timedelta(minutes=minute)
    )

    return {
        "timestamp": (
            observed_at.isoformat()
        ),
        "rule": {
            "level": 10,
            "description": (
                "sshd: Multiple authentication failures."
            ),
            "id": "5712",
            "frequency": 8,
            "groups": [
                "authentication_failures",
                "sshd",
            ],
            "mitre": {
                "id": [
                    "T1110.001",
                ],
                "tactic": [
                    "Credential Access",
                ],
                "technique": [
                    "Password Guessing",
                ],
            },
        },
        "agent": {
            "id": "007",
            "name": "workstation-07",
            "ip": "192.168.1.20",
        },
        "id": alert_id,
        "full_log": (
            "Failed password for root from "
            "203.0.113.10 port 55122 ssh2"
        ),
        "data": {
            "srcip": "203.0.113.10",
            "dstuser": "root",
            "srcport": "55122",
            "dstport": "22",
        },
        "decoder": {
            "name": "sshd",
            "parent": "sshd",
        },
        "location": "/var/log/auth.log",
    }


class FakeClassifier:
    def __init__(
        self,
        classification: str,
    ):
        self.classification = (
            classification
        )

        self.calls = []

    def classify(
        self,
        alert: SecurityAlertInput,
    ) -> AttackPrediction:
        self.calls.append(
            alert.alert_id
        )

        return AttackPrediction(
            classification=(
                self.classification
            ),
            confidence=0.97,
            model_version="fake-runtime-v1",
        )


class RecordingGraph:
    def __init__(self):
        self.calls = 0
        self.last_state = None

    def invoke(
        self,
        state: dict,
    ) -> dict:
        self.calls += 1
        self.last_state = state

        alert = state["alert"]

        prediction = state.get(
            "ml_prediction"
        )

        classification = (
            prediction.classification
            if prediction is not None
            else "unknown"
        )

        return {
            "alert": alert,
            "normalized_event": (
                alert.event_text
            ),
            "ml_prediction": prediction,
            "ml_error": state.get(
                "ml_error"
            ),
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    content=(
                        alert.event_text
                    ),
                ),
            ],
            "analysis": AlertAnalysis(
                classification=classification,
                confidence=(
                    prediction.confidence
                    if prediction
                    is not None
                    else 0.0
                ),
                severity_assessment="high",
                summary=(
                    "Security activity detected."
                ),
                evidence_refs=[
                    "E001",
                ],
                uncertainties=[],
                recommended_investigation_steps=[],
                recommended_response_actions=[],
                requested_evidence=[],
                needs_more_evidence=False,
            ),
            "risk_assessment": RiskAssessment(
                score=75,
                band="high",
                factors=[],
            ),
            "policy_decision": PolicyDecision(
                policy_id="POL-TEST",
                policy_name=(
                    "Runtime Test Policy"
                ),
                matched=True,
                response_allowed=False,
                actions=[],
                reason=(
                    "Test policy requires a case."
                ),
            ),
            "response_plan": ResponsePlan(
                policy_id="POL-TEST",
                actions=[],
                response_allowed=False,
                status="create_case",
                reason=(
                    "Test policy requires a case."
                ),
            ),
            "investigation_iteration": 0,
            "status": "complete",
        }


def make_runtime(
    *,
    classification: str = "brute_force",
):
    graph = RecordingGraph()

    classifier = FakeClassifier(
        classification
    )

    store = InMemoryInvestigationStore()

    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=graph,
        investigation_store=store,
        audit_store=audit_store,
        ml_classifier=classifier,
        wazuh_ingest_key=(
            "test-wazuh-key"
        ),
    )

    client = TestClient(
        app
    )

    return (
        client,
        graph,
        classifier,
        store,
        audit_store,
    )


def submit(
    client,
    payload,
):
    return client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "test-wazuh-key"
            )
        },
        json=payload,
    )


def test_wazuh_runtime_classifies_before_graph_and_creates_incident():
    (
        client,
        graph,
        classifier,
        store,
        _,
    ) = make_runtime()

    response = submit(
        client,
        make_raw_alert(),
    )

    assert response.status_code == 200

    body = response.json()

    assert len(classifier.calls) == 1

    assert graph.calls == 1

    assert (
        graph.last_state[
            "ml_prediction"
        ].classification
        == "brute_force"
    )

    assert body["incident_id"] is not None

    incident = store.get_incident(
        body["incident_id"]
    )

    assert incident is not None

    assert (
        body["ml_prediction"][
            "classification"
        ]
        == "brute_force"
    )


def test_wazuh_runtime_correlates_related_alerts():
    (
        client,
        _,
        _,
        store,
        _,
    ) = make_runtime()

    first = submit(
        client,
        make_raw_alert(
            alert_id="ALERT-001",
            minute=0,
        ),
    )

    second = submit(
        client,
        make_raw_alert(
            alert_id="ALERT-002",
            minute=5,
        ),
    )

    assert first.status_code == 200

    assert second.status_code == 200

    first_incident_id = (
        first.json()["incident_id"]
    )

    second_incident_id = (
        second.json()["incident_id"]
    )

    assert (
        second_incident_id
        == first_incident_id
    )

    alerts = store.list_incident_alerts(
        first_incident_id
    )

    assert len(alerts) == 2


def test_wazuh_runtime_records_incident_audit_event():
    (
        client,
        _,
        _,
        _,
        audit_store,
    ) = make_runtime()

    response = submit(
        client,
        make_raw_alert(),
    )

    assert response.status_code == 200

    incident_id = (
        response.json()[
            "incident_id"
        ]
    )

    records = (
        audit_store.list_by_incident_id(
            incident_id
        )
    )

    assert len(records) == 1

    assert (
        records[0].event_type
        == "incident_created"
    )

    assert (
        records[0].incident_id
        == incident_id
    )


def test_benign_wazuh_alert_skips_agentic_graph():
    (
        client,
        graph,
        classifier,
        store,
        _,
    ) = make_runtime(
        classification="benign",
    )

    response = submit(
        client,
        make_raw_alert(),
    )

    assert response.status_code == 200

    body = response.json()

    assert len(classifier.calls) == 1

    assert graph.calls == 0

    assert body["incident_id"] is None

    assert (
        body["ml_prediction"][
            "classification"
        ]
        == "benign"
    )

    assert (
        body["risk_assessment"]["score"]
        == 0
    )

    assert (
        body["response_plan"]["status"]
        == "no_action"
    )

    assert (
        store.get_incident_alert(
            "wazuh:1716206454.722325"
        )
        is None
    )


def test_duplicate_wazuh_alert_does_not_repeat_graph():
    (
        client,
        graph,
        _,
        _,
        audit_store,
    ) = make_runtime()

    payload = make_raw_alert()

    first = submit(
        client,
        payload,
    )

    second = submit(
        client,
        payload,
    )

    assert first.status_code == 200

    assert second.status_code == 200

    assert graph.calls == 1

    assert (
        first.json()["incident_id"]
        == second.json()["incident_id"]
    )

    incident_id = (
        first.json()["incident_id"]
    )

    records = (
        audit_store.list_by_incident_id(
            incident_id
        )
    )

    assert [
        record.event_type
        for record in records
    ] == [
        "incident_created",
        "duplicate_alert_received",
    ]


def test_ml_node_reuses_preclassified_prediction():
    alert = SecurityAlertInput(
        alert_id="ALT-PRECLASSIFIED",
        source="wazuh",
        event_text=(
            "Repeated SSH failures."
        ),
    )

    prediction = AttackPrediction(
        classification="brute_force",
        confidence=0.98,
        model_version="preclassified-v1",
    )

    calls = []

    def classifier(
        classifier_alert,
    ):
        calls.append(
            classifier_alert.alert_id
        )

        raise AssertionError(
            "Classifier must not run twice."
        )

    node = make_ml_classification_node(
        classifier
    )

    result = node(
        {
            "alert": alert,
            "ml_prediction": prediction,
            "status": "normalized",
        }
    )

    assert calls == []

    assert (
        result["ml_prediction"]
        == prediction
    )