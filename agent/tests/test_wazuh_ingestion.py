from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)


class FakeWazuhGraph:
    def __init__(self):
        self.last_alert = None

    def invoke(
        self,
        state: dict,
    ) -> dict:
        alert: SecurityAlertInput = state["alert"]

        self.last_alert = alert

        return {
            "alert": alert,
            "normalized_event": alert.event_text,
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    content=alert.event_text,
                ),
            ],
            "analysis": AlertAnalysis(
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
                requested_evidence=[],
                needs_more_evidence=False,
            ),
            "risk_assessment": RiskAssessment(
                score=75,
                band="high",
                factors=[],
            ),
            "policy_decision": PolicyDecision(
                policy_id="POL-BF-HIGH",
                policy_name=(
                    "High-Risk Brute Force"
                ),
                matched=True,
                response_allowed=False,
                actions=[],
                reason=(
                    "Automatic containment "
                    "is not permitted."
                ),
            ),
            "response_plan": ResponsePlan(
                policy_id="POL-BF-HIGH",
                actions=[],
                response_allowed=False,
                status="create_case",
                reason=(
                    "Automatic containment "
                    "is not permitted."
                ),
            ),
            "investigation_iteration": 0,
            "status": "complete",
        }


RAW_WAZUH_ALERT = {
    "timestamp": "2026-08-14T18:30:00.000+0000",
    "rule": {
        "level": 10,
        "description": (
            "sshd: Multiple authentication failures."
        ),
        "id": "5712",
        "groups": [
            "authentication_failures",
            "sshd",
        ],
    },
    "agent": {
        "id": "007",
        "name": "workstation-07",
        "ip": "192.168.1.20",
    },
    "id": "1716206454.722325",
    "full_log": (
        "Failed password for root from "
        "192.168.1.45 port 55122 ssh2"
    ),
    "data": {
        "srcip": "192.168.1.45",
        "dstuser": "root",
        "srcport": "55122",
    },
    "location": "/var/log/auth.log",
}


def make_client(
    key: str = "test-wazuh-key",
):
    graph = FakeWazuhGraph()

    app = create_app(
        investigation_graph=graph,
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        wazuh_ingest_key=key,
    )

    return (
        TestClient(app),
        graph,
    )


def test_wazuh_ingestion_requires_key():
    client, _ = make_client()

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        json=RAW_WAZUH_ALERT,
    )

    assert response.status_code == 401


def test_wazuh_ingestion_rejects_wrong_key():
    client, _ = make_client()

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "wrong-key"
            )
        },
        json=RAW_WAZUH_ALERT,
    )

    assert response.status_code == 401


def test_wazuh_ingestion_creates_investigation():
    client, graph = make_client()

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "test-wazuh-key"
            )
        },
        json=RAW_WAZUH_ALERT,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["alert_id"] == (
        "wazuh:1716206454.722325"
    )

    assert data["source"] == "wazuh"

    assert (
        data["analysis"]["classification"]
        == "brute_force"
    )

    assert (
        data["response_plan"]["status"]
        == "create_case"
    )

    assert (
        data["response_plan"]["response_allowed"]
        is False
    )

    assert graph.last_alert is not None

    assert (
        graph.last_alert.metadata["source_ip"]
        == "192.168.1.45"
    )

    assert (
        graph.last_alert.metadata["agent_id"]
        == "007"
    )


def test_wazuh_ingestion_rejects_invalid_alert():
    client, _ = make_client()

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "test-wazuh-key"
            )
        },
        json={
            "rule": {
                "description": "Missing identifier"
            }
        },
    )

    assert response.status_code == 400


def test_wazuh_ingestion_disabled_without_key():
    client, _ = make_client(
        key=""
    )

    response = client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "anything"
            )
        },
        json=RAW_WAZUH_ALERT,
    )

    assert response.status_code == 503