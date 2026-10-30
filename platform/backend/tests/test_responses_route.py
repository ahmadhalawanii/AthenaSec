"""GET /api/v1/responses: executed containment actions with approval, result, verification, rollback."""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import (
    ActionExecutionResultRecord,
    ActionRollbackRecord,
    ActionVerificationRecord,
    ApprovalRequestRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from tests.test_cases_endpoints import UnusedGraph
from tests.test_investigation_list_stores import BASE, seed


def fill(responses):
    responses.save_proposed_action(ProposedActionRecord(
        proposed_action_id="PACT-1", incident_id="INC-A", investigation_id="INV-ALT-1",
        action_type="block_ip", target_type="ip", target="203.0.113.10",
        parameters={"duration_minutes": 30}, reversible=True, rollback_action_type="unblock_ip",
        reason="Repeated failures", proposed_at=BASE,
    ))
    responses.save_approval_request(ApprovalRequestRecord(
        approval_id="APR-1", incident_id="INC-A", proposed_action_id="PACT-1",
        policy_decision_id="PDEC-1", action_fingerprint="fp", status="APPROVED",
        requested_by="athenasec", requested_at=BASE,
        decided_at=BASE + timedelta(minutes=2), decided_by="analyst-7",
    ))
    responses.save_response_action(ResponseActionRecord(
        response_action_id="RACT-1", incident_id="INC-A", proposed_action_id="PACT-1",
        approval_id="APR-1", executor="cortex", status="completed",
        created_at=BASE + timedelta(minutes=3),
    ))
    responses.save_action_result(ActionExecutionResultRecord(
        action_result_id="RES-1", response_action_id="RACT-1", status="completed",
        message="Cortex blocked the address.", recorded_at=BASE + timedelta(minutes=4),
    ))
    responses.save_action_verification(ActionVerificationRecord(
        verification_id="VER-1", response_action_id="RACT-1", proposed_action_id="PACT-1",
        status="SUCCESS", message="The block is in place.", verified_at=BASE + timedelta(minutes=5),
    ))
    responses.save_action_rollback(ActionRollbackRecord(
        rollback_id="RB-1", response_action_id="RACT-1", proposed_action_id="PACT-1",
        verification_id="VER-1", rollback_action_type="unblock_ip", target="203.0.113.10",
        status="completed", message="Unblocked at expiry.", recorded_at=BASE + timedelta(minutes=34),
    ))


def client_for(responses, *, authenticated=True):
    investigations = InMemoryInvestigationStore()
    seed(investigations)
    identity = InMemoryOperatorIdentityStore()
    app = create_app(investigation_graph=UnusedGraph(), investigation_store=investigations,
                     audit_store=InMemoryAuditStore(), incident_response_store=responses,
                     operator_identity_store=identity, autonomous_response_enabled=False)
    client = TestClient(app)
    if authenticated:
        client.headers["Authorization"] = "Bearer " + identity.provision(operator_id="a", can_read=True)
    return client


@pytest.fixture(params=["memory", "sqlite"])
def responses(request, tmp_path):
    return (InMemoryIncidentResponseStore() if request.param == "memory"
            else SQLiteIncidentResponseStore(tmp_path / "r.db"))


def test_a_run_shows_its_whole_story(responses):
    fill(responses)

    body = client_for(responses).get("/api/v1/responses").json()

    assert body["total"] == 1
    run = body["items"][0]
    assert run["alert_id"] == "ALT-1" and run["action_type"] == "block_ip"
    assert run["target"] == "203.0.113.10" and run["duration_minutes"] == 30
    assert run["approved_by"] == "analyst-7" and run["policy_decision_id"] == "PDEC-1"
    assert run["result"]["status"] == "completed"
    assert run["verification"]["status"] == "SUCCESS"
    assert run["rollback"]["message"] == "Unblocked at expiry."
    assert run["expires_at"].startswith((BASE + timedelta(minutes=32)).strftime("%Y-%m-%dT%H:%M"))


def test_empty_and_filtered_and_protected(responses):
    assert client_for(responses).get("/api/v1/responses").json()["items"] == []
    fill(responses)
    assert client_for(responses).get("/api/v1/responses?incident_id=INC-B").json()["total"] == 0
    assert client_for(responses, authenticated=False).get("/api/v1/responses").status_code == 401
