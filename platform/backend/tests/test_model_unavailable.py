"""When Ollama is down the backend answers 503 with a plain reason, not a crash.

The Wazuh route also records an investigation_failed event on the incident, so the
alert that could not be investigated is visible in its audit trail.
"""

import httpx
import ollama
import pytest
from fastapi.testclient import TestClient

import app.llm as llm
from app.main import create_app
from app.schemas import AttackPrediction
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from tests.conftest import ANALYZE_HEADERS
from tests.test_wazuh_ingestion import RAW_WAZUH_ALERT

pytestmark = pytest.mark.usefixtures("operator_identity_for_tests")


class RaisingModel:
    def __init__(self, error):
        self.error = error

    def invoke(self, messages):
        raise self.error


@pytest.mark.parametrize("error", [
    httpx.ConnectError("refused"),
    httpx.ReadTimeout("slow"),
    ConnectionRefusedError("refused"),
])
def test_connection_problems_become_model_unavailable(error):
    with pytest.raises(llm.ModelUnavailable, match="Is Ollama running"):
        llm._invoke(RaisingModel(error), [])


def test_missing_model_says_how_to_pull_it():
    with pytest.raises(llm.ModelUnavailable, match="ollama pull"):
        llm._invoke(RaisingModel(ollama.ResponseError("not found", 404)), [])


def test_other_model_errors_are_not_hidden():
    with pytest.raises(ollama.ResponseError):
        llm._invoke(RaisingModel(ollama.ResponseError("bad request", 400)), [])
    with pytest.raises(ValueError):
        llm._invoke(RaisingModel(ValueError("bad output")), [])


class DownGraph:
    def invoke(self, state):
        raise llm.ModelUnavailable("The AI model could not be reached at http://x. Is Ollama running?")


class Classifier:
    # The ML step runs before the model and puts the alert in an incident
    def classify(self, alert):
        return AttackPrediction(classification="brute_force", confidence=0.9, model_version="t")


def make_client():
    audit = InMemoryAuditStore()
    app = create_app(
        investigation_graph=DownGraph(),
        ml_classifier=Classifier(),
        investigation_store=InMemoryInvestigationStore(),
        audit_store=audit,
        wazuh_ingest_key="k",
    )
    return TestClient(app, raise_server_exceptions=False), audit


def test_wazuh_alert_gets_503_and_an_audit_event():
    client, audit = make_client()

    response = client.post("/api/v1/integrations/wazuh/alerts", json=RAW_WAZUH_ALERT,
                           headers={"X-AthenaSec-Integration-Key": "k"})

    assert response.status_code == 503
    assert "Is Ollama running?" in response.json()["detail"]
    assert "was not investigated" in response.json()["detail"]
    events = [e for e in audit.list_incident_events() if e.event_type == "investigation_failed"]
    assert len(events) == 1
    assert events[0].entity_type == "alert"
    assert "Is Ollama running?" in events[0].details["reason"]


def test_manual_alert_gets_503():
    client, _ = make_client()

    response = client.post("/api/v1/analyze", headers=ANALYZE_HEADERS, json={
        "alert_id": "ALT-1", "source": "manual", "event_text": "x", "metadata": {}})

    assert response.status_code == 503
    assert "ALT-1 was not investigated" in response.json()["detail"]
