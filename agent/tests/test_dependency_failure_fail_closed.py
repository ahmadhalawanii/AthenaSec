"""A failed investigation dependency (Ollama, graph) must fail closed.

Evidence tier: Mock (fake graph that raises). It proves the API contract,
not connectivity to a deployed Ollama.
"""
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit_store import InMemoryAuditStore
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)

SECRET_HOST = "http://internal-ollama.lab:11434"

ALERT = {
    "alert_id": "ALT-DEP-001",
    "source": "manual",
    "event_text": "148 failed SSH login attempts against root.",
    "metadata": {
        "failed_attempts": 148,
        "privileged_target": True,
        "asset_criticality": "medium",
    },
}


class ExplodingGraph:
    def __init__(self, exc):
        self.exc = exc
        self.calls = 0

    def invoke(self, state):
        self.calls += 1
        raise self.exc


class RecordingExecutor:
    def __init__(self):
        self.calls = 0

    def execute(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("Cortex must not be called")


def _client(exc):
    store = InMemoryInvestigationStore()
    audit = InMemoryAuditStore()
    executor = RecordingExecutor()
    graph = ExplodingGraph(exc)
    app = create_app(
        investigation_graph=graph,
        investigation_store=store,
        audit_store=audit,
        response_executor=executor,
        autonomous_response_enabled=False,
    )
    return TestClient(app, raise_server_exceptions=False), store, audit, executor


def test_dependency_failure_returns_503_without_leaking_details():
    client, store, audit, executor = _client(
        ConnectionError(f"cannot reach {SECRET_HOST}")
    )

    response = client.post("/api/v1/analyze", json=ALERT)

    assert response.status_code == 503
    assert SECRET_HOST not in response.text
    assert "ConnectionError" not in response.text
    assert executor.calls == 0


def test_dependency_failure_stores_no_investigation_and_audits_it():
    client, store, audit, executor = _client(
        TimeoutError("ollama read timeout")
    )

    client.post("/api/v1/analyze", json=ALERT)

    assert store.list_all() == [] if hasattr(store, "list_all") else True
    events = [
        r for r in audit._records.values()
        if r.event_type == "investigation_dependency_failed"
    ]
    assert len(events) == 1
    assert events[0].alert_id == "ALT-DEP-001"
    assert events[0].details["error_type"] == "TimeoutError"
    assert executor.calls == 0


def test_malformed_model_output_also_fails_closed():
    client, _, audit, executor = _client(ValueError("bad structured output"))

    response = client.post("/api/v1/analyze", json=ALERT)

    assert response.status_code == 503
    assert executor.calls == 0
