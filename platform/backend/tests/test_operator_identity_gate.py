"""M8: human approval must bind to verified operator identity, never client text."""
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import IncidentPolicyDecisionRecord, ProposedActionRecord
from app.services.approvals.action_approval import create_approval_request
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph should not be invoked")


def make_client(*, with_store=True):
    identity = InMemoryOperatorIdentityStore() if with_store else None
    response_store = InMemoryIncidentResponseStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=InMemoryInvestigationStore(),
        audit_store=InMemoryAuditStore(),
        incident_response_store=response_store,
        operator_control_key="operator-control-key",
        operator_identity_store=identity,
        autonomous_response_enabled=False,
    )
    return TestClient(app), identity, response_store


def seed(store):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    action = ProposedActionRecord(
        proposed_action_id="PACT-M8", incident_id="INC-M8",
        investigation_id="INV-M8", action_type="block_ip",
        target_type="ip", target="203.0.113.10",
        parameters={"duration_minutes": 480}, reversible=True,
        rollback_action_type="unblock_ip", rollback_parameters={},
        reason="Test", proposed_at=now,
    )
    policy = IncidentPolicyDecisionRecord(
        decision_id="PDEC-M8", incident_id="INC-M8",
        proposed_action_id="PACT-M8", policy_id="POL-ACTION-HUMAN-APPROVAL",
        outcome="APPROVAL_REQUIRED", reason="Human approval required",
        decided_at=now,
    )
    approval = create_approval_request(
        proposed_action=action, policy_decision=policy,
        requested_at=now, expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    store.save_proposed_action(action)
    store.save_policy_decision(policy)
    store.save_approval_request(approval)
    return approval


def request(client, id, *, token=None, decided_by="spoofed-admin"):
    headers = {"Authorization": "Bearer " + token} if token else {}
    headers["X-AthenaSec-Operator-Key"] = "operator-control-key"
    return client.post(
        f"/api/v1/approvals/{id}/decision",
        headers=headers,
        json={"decision": "APPROVED", "reason": "Reviewed the evidence",
              "decided_by": decided_by},
    )


def test_shared_operator_key_cannot_decide_approval():
    client, store, response_store = make_client()
    approval = seed(response_store)
    assert request(client, approval.approval_id).status_code == 401
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"


def test_reader_cannot_approve_even_with_valid_token():
    client, store, response_store = make_client()
    approval = seed(response_store)
    token = store.provision(operator_id="reader-1", can_approve=False)
    assert request(client, approval.approval_id, token=token).status_code == 403
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"


def test_authenticated_approver_identity_overrides_client_claim():
    client, store, response_store = make_client()
    approval = seed(response_store)
    token = store.provision(operator_id="real-analyst", can_approve=True)
    result = request(client, approval.approval_id, token=token)
    assert result.status_code == 200
    assert result.json()["decided_by"] == "real-analyst"
    assert response_store.get_approval_request(approval.approval_id).decided_by == "real-analyst"


def test_revoked_operator_token_denied_before_mutation():
    client, store, response_store = make_client()
    approval = seed(response_store)
    token = store.provision(operator_id="former-analyst", can_approve=True)
    store.revoke(token)
    assert request(client, approval.approval_id, token=token).status_code == 401
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"


def test_missing_identity_backend_fails_closed_even_with_shared_key():
    client, _, response_store = make_client(with_store=False)
    approval = seed(response_store)
    assert request(client, approval.approval_id).status_code == 503
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"


def test_decision_works_without_client_supplied_identity():
    client, store, response_store = make_client()
    approval = seed(response_store)
    token = store.provision(operator_id="trusted-analyst", can_approve=True)
    headers = {"Authorization": "Bearer " + token}
    response = client.post(
        f"/api/v1/approvals/{approval.approval_id}/decision",
        headers=headers,
        json={"decision": "REJECTED", "reason": "Unsafe to contain"},
    )
    assert response.status_code == 200
    assert response.json()["decided_by"] == "trusted-analyst"
    assert response.json()["status"] == "REJECTED"
    assert len(response_store.list_incident_cases(approval.incident_id)) == 1


def test_reader_may_view_approval_but_not_decide():
    client, store, response_store = make_client()
    approval = seed(response_store)
    token = store.provision(operator_id="reader-1")
    response = client.get(
        f"/api/v1/approvals/{approval.approval_id}",
        headers={"Authorization": "Bearer " + token},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "PENDING"
