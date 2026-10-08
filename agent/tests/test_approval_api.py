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
from app.services.action_approval import (
    create_approval_request,
)
from app.services.audit_store import (
    InMemoryAuditStore,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)


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


def make_client():
    response_store = (
        InMemoryIncidentResponseStore()
    )

    audit_store = (
        InMemoryAuditStore()
    )

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
    )

    return (
        TestClient(app),
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
