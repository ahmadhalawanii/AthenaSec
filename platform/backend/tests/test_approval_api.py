from datetime import (
    datetime,
    timezone,
)

from fastapi.testclient import (
    TestClient,
)

from app.main import create_app
from app.schemas import (
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.approvals.action_approval import (
    create_approval_request,
)
from app.services.audit.audit_store import (
    InMemoryAuditStore,
)
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigations.investigation_store import (
    InMemoryInvestigationStore,
)
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore


REQUESTED_AT = datetime(
    2020,
    1,
    1,
    12,
    0,
    tzinfo=timezone.utc,
)


EXPIRES_AT = datetime(
    2099,
    1,
    1,
    12,
    0,
    tzinfo=timezone.utc,
)


class UnusedGraph:
    def invoke(
        self,
        state,
    ):
        raise AssertionError(
            "Investigation graph must not "
            "be used by approval API tests."
        )


def make_action(
    *,
    target: str = "203.0.113.10",
    duration_minutes: int = 480,
):
    return ProposedActionRecord(
        proposed_action_id="PACT-API-001",
        incident_id="INC-API-001",
        investigation_id="INV-API-001",
        action_type="block_ip",
        target_type="ip",
        target=target,
        parameters={
            "duration_minutes": (
                duration_minutes
            ),
        },
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={},
        reason=(
            "Contain the confirmed "
            "malicious source."
        ),
        proposed_at=REQUESTED_AT,
    )


def make_policy():
    return IncidentPolicyDecisionRecord(
        decision_id="PDEC-API-001",
        incident_id="INC-API-001",
        proposed_action_id="PACT-API-001",
        policy_id=(
            "POL-ACTION-HUMAN-APPROVAL"
        ),
        outcome="APPROVAL_REQUIRED",
        reason=(
            "Human approval is required."
        ),
        decided_at=REQUESTED_AT,
    )


def seed_approval(
    response_store,
):
    action = make_action()

    policy = make_policy()

    approval = (
        create_approval_request(
            proposed_action=action,
            policy_decision=policy,
            requested_at=(
                REQUESTED_AT
            ),
            expires_at=(
                EXPIRES_AT
            ),
        )
    )

    response_store.save_proposed_action(
        action
    )

    response_store.save_policy_decision(
        policy
    )

    response_store.save_approval_request(
        approval
    )

    return (
        action,
        policy,
        approval,
    )


def make_client(*, operator_key="operator-key", auth_enabled=True):
    response_store = (
        InMemoryIncidentResponseStore()
    )

    audit_store = (
        InMemoryAuditStore()
    )

    identity = InMemoryOperatorIdentityStore() if auth_enabled else None
    token = identity.provision(operator_id="analyst-001", can_approve=True) if identity else None

    app = create_app(
        investigation_graph=(
            UnusedGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
        incident_response_store=(
            response_store
        ),
        autonomous_response_enabled=False,
        operator_control_key=operator_key,
        operator_identity_store=identity,
    )

    client = TestClient(app)
    if operator_key:
        client.headers["X-AthenaSec-Operator-Key"] = operator_key
    if token:
        client.headers["Authorization"] = "Bearer " + token

    return (
        client,
        response_store,
        audit_store,
    )


def test_get_approval_request_returns_pending_record():
    (
        client,
        response_store,
        _,
    ) = make_client()

    _, _, approval = (
        seed_approval(
            response_store
        )
    )

    response = client.get(
        (
            "/api/v1/approvals/"
            f"{approval.approval_id}"
        )
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["approval_id"]
        == approval.approval_id
    )

    assert (
        body["status"]
        == "PENDING"
    )


def test_missing_approval_returns_404():
    (
        client,
        _,
        _,
    ) = make_client()

    response = client.get(
        "/api/v1/approvals/APR-MISSING"
    )

    assert response.status_code == 404


def test_exact_action_can_be_approved_via_api():
    (
        client,
        response_store,
        audit_store,
    ) = make_client()

    _, _, approval = (
        seed_approval(
            response_store
        )
    )

    response = client.post(
        (
            "/api/v1/approvals/"
            f"{approval.approval_id}"
            "/decision"
        ),
        json={
            "decision": "APPROVED",
            "decided_by": (
                "analyst-001"
            ),
            "reason": (
                "Approved temporary "
                "containment."
            ),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["status"]
        == "APPROVED"
    )

    stored = (
        response_store
        .get_approval_request(
            approval.approval_id
        )
    )

    assert stored is not None

    assert (
        stored.status
        == "APPROVED"
    )

    assert (
        response_store
        .list_incident_cases(
            "INC-API-001"
        )
        == []
    )

    event_types = [
        record.event_type
        for record
        in audit_store.list_by_incident_id(
            "INC-API-001"
        )
    ]

    assert (
        "approval_decided"
        in event_types
    )


def test_rejected_action_creates_incident_case():
    (
        client,
        response_store,
        audit_store,
    ) = make_client()

    _, _, approval = (
        seed_approval(
            response_store
        )
    )

    response = client.post(
        (
            "/api/v1/approvals/"
            f"{approval.approval_id}"
            "/decision"
        ),
        json={
            "decision": "REJECTED",
            "decided_by": (
                "analyst-002"
            ),
            "reason": (
                "Operational impact "
                "is too high."
            ),
        },
    )

    assert response.status_code == 200

    assert (
        response.json()["status"]
        == "REJECTED"
    )

    cases = (
        response_store
        .list_incident_cases(
            "INC-API-001"
        )
    )

    assert len(cases) == 1

    assert (
        cases[0].status
        == "open"
    )

    assert (
        cases[0]
        .policy_decision_id
        == "PDEC-API-001"
    )

    event_types = [
        record.event_type
        for record
        in audit_store.list_by_incident_id(
            "INC-API-001"
        )
    ]

    assert (
        "approval_decided"
        in event_types
    )

    assert (
        "case_created"
        in event_types
    )


def test_modified_action_cannot_use_existing_approval():
    (
        client,
        response_store,
        _,
    ) = make_client()

    _, _, approval = (
        seed_approval(
            response_store
        )
    )

    modified = make_action(
        duration_minutes=600,
    )

    response_store.save_proposed_action(
        modified
    )

    response = client.post(
        (
            "/api/v1/approvals/"
            f"{approval.approval_id}"
            "/decision"
        ),
        json={
            "decision": "APPROVED",
            "decided_by": (
                "analyst-001"
            ),
            "reason": "Approve.",
        },
    )

    assert response.status_code == 409

    stored = (
        response_store
        .get_approval_request(
            approval.approval_id
        )
    )

    assert stored is not None

    assert (
        stored.status
        == "PENDING"
    )


def test_approval_cannot_be_decided_twice():
    (
        client,
        response_store,
        _,
    ) = make_client()

    _, _, approval = (
        seed_approval(
            response_store
        )
    )

    url = (
        "/api/v1/approvals/"
        f"{approval.approval_id}"
        "/decision"
    )

    first = client.post(
        url,
        json={
            "decision": "APPROVED",
            "decided_by": (
                "analyst-001"
            ),
            "reason": "Approved.",
        },
    )

    assert first.status_code == 200

    second = client.post(
        url,
        json={
            "decision": "REJECTED",
            "decided_by": (
                "analyst-002"
            ),
            "reason": "Reject.",
        },
    )

    assert second.status_code == 409


def test_approval_read_requires_operator_credentials():
    client, response_store, _ = make_client()
    _, _, approval = seed_approval(response_store)
    endpoint = f"/api/v1/approvals/{approval.approval_id}"
    original_auth = client.headers.pop("Authorization", None)

    assert client.get(endpoint).status_code == 401
    assert client.get(
        endpoint,
        headers={"Authorization": "Bearer incorrect"},
    ).status_code == 401
    assert client.get(
        endpoint,
        headers={"Authorization": original_auth},
    ).status_code == 200


def test_unknown_approval_id_does_not_leak_without_credentials():
    client, _, _ = make_client()
    client.headers.pop("Authorization", None)
    assert client.get(
        "/api/v1/approvals/APR-UNKNOWN"
    ).status_code == 401


def test_approval_decision_requires_credentials_before_mutation():
    client, response_store, audit_store = make_client()
    _, _, approval = seed_approval(response_store)
    endpoint = f"/api/v1/approvals/{approval.approval_id}/decision"
    client.headers.pop("Authorization", None)
    request = {
        "decision": "APPROVED",
        "decided_by": "claimed-analyst",
        "reason": "Claimed approval without authority.",
    }

    for headers in (
        {},
        {"Authorization": "Bearer incorrect"},
    ):
        result = client.post(endpoint, json=request, headers=headers)
        assert result.status_code == 401
        assert response_store.get_approval_request(
            approval.approval_id
        ).status == "PENDING"
        assert audit_store.list_by_incident_id(approval.incident_id) == []


def test_unconfigured_approval_gate_fails_closed():
    client, response_store, _ = make_client(auth_enabled=False)
    _, _, approval = seed_approval(response_store)
    endpoint = f"/api/v1/approvals/{approval.approval_id}"

    assert client.get(endpoint).status_code == 503
    assert client.post(
        endpoint + "/decision",
        json={
            "decision": "APPROVED",
            "decided_by": "claimed-analyst",
            "reason": "Should not authorize.",
        },
    ).status_code == 503
    assert response_store.get_approval_request(
        approval.approval_id
    ).status == "PENDING"


def test_approval_action_detail_returns_the_proposed_action():
    client, response_store, _ = make_client()
    action, policy, approval = seed_approval(response_store)

    response = client.get(f"/api/v1/approvals/{approval.approval_id}/action")

    assert response.status_code == 200
    body = response.json()
    assert body["approval"]["approval_id"] == approval.approval_id
    assert body["proposed_action"]["proposed_action_id"] == action.proposed_action_id
    assert body["proposed_action"]["target"] == action.target
    assert body["policy_decision"]["decision_id"] == policy.decision_id


def test_approval_action_detail_requires_credentials_and_known_id():
    client, response_store, _ = make_client()
    _, _, approval = seed_approval(response_store)

    assert client.get("/api/v1/approvals/APR-MISSING/action").status_code == 404
    client.headers.pop("Authorization", None)
    assert client.get(f"/api/v1/approvals/{approval.approval_id}/action").status_code == 401
