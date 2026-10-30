"""Regression: legacy V1 response plans cannot execute Cortex in V2."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
import app.services.cortex.cortex_config as cortex_config

from tests.test_api import (
    FakeCriticalInvestigationGraph,
    FakeSuccessfulResponseExecutor,
    submit_investigation,
)

# POST /api/v1/analyze needs an operator: these apps get the test identity store
pytestmark = pytest.mark.usefixtures("operator_identity_for_tests")


@pytest.mark.parametrize("mode", ["SUPERVISED", "AUTONOMOUS", "SHADOW"])
@pytest.mark.parametrize("source", ["injected", "environment"])
def test_legacy_plan_cannot_execute_cortex_or_skip_case(monkeypatch, mode, source):
    monkeypatch.setenv("AUTONOMOUS_RESPONSE_ENABLED", "true")
    executor = FakeSuccessfulResponseExecutor()
    store = InMemoryInvestigationStore()
    audit = InMemoryAuditStore()
    options = {}
    if source == "injected":
        options["response_executor"] = executor
    else:
        monkeypatch.setattr(
            cortex_config,
            "build_cortex_response_executor_from_env",
            lambda: executor,
        )
    app = create_app(
        investigation_graph=FakeCriticalInvestigationGraph(),
        investigation_store=store,
        audit_store=audit,
        autonomous_response_enabled=True,
        response_mode=mode,
        **options,
    )
    response = submit_investigation(TestClient(app))
    assert response.status_code == 200
    assert executor.calls == [], "Legacy plan bypassed V2 action policy"
    assert store.get_case_by_alert_id("ALT-API-001") is not None
    investigation = store.get("ALT-API-001")
    assert investigation is not None
    assert investigation.execution_result is None
    events = [x.event_type for x in audit.list_by_alert_id("ALT-API-001")]
    assert "legacy_response_blocked" in events
    assert "case_created" in events
    assert "cortex_execution_started" not in events
    assert "cortex_execution_completed" not in events
