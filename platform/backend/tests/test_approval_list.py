from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import ApprovalRequestRecord
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore

BASE = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by approval list tests.")


@pytest.fixture(autouse=True)
def isolated_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("ATHENASEC_PERSISTENCE_BACKEND", "sqlite")
    monkeypatch.setenv("ATHENASEC_DB_PATH", str(tmp_path / "approvals.db"))


def approval(number, *, incident_id, status, minutes):
    return ApprovalRequestRecord(
        approval_id=f"APR-{number}",
        incident_id=incident_id,
        proposed_action_id=f"PACT-{number}",
        policy_decision_id=f"POL-{number}",
        action_fingerprint=f"fp-{number}",
        status=status,
        requested_by="system",
        requested_at=BASE + timedelta(minutes=minutes),
    )


def make_client(*, seeded=True, authenticated=True, can_read=True):
    store = InMemoryIncidentResponseStore()

    if seeded:
        for record in (
            approval(1, incident_id="INC-A", status="PENDING", minutes=0),
            approval(2, incident_id="INC-A", status="APPROVED", minutes=10),
            approval(3, incident_id="INC-B", status="PENDING", minutes=20),
        ):
            store.save_approval_request(record)

    identity = InMemoryOperatorIdentityStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=InMemoryInvestigationStore(),
        audit_store=InMemoryAuditStore(),
        incident_response_store=store,
        autonomous_response_enabled=False,
        operator_identity_store=identity,
    )
    client = TestClient(app)

    if authenticated:
        token = identity.provision(
            operator_id="analyst-001", can_read=can_read
        )
        client.headers["Authorization"] = "Bearer " + token

    return client


def ids(response):
    assert response.status_code == 200
    return [item["approval_id"] for item in response.json()["items"]]


def test_empty_state_returns_total_zero():
    body = make_client(seeded=False).get("/api/v1/approvals").json()

    assert body == {"total": 0, "items": [], "next_cursor": None}


def test_envelope_newest_first_and_unchanged_fields():
    body = make_client().get("/api/v1/approvals").json()

    assert set(body) == {"total", "items", "next_cursor"}
    assert body["total"] == 3
    assert body["next_cursor"] is None
    assert [i["approval_id"] for i in body["items"]] == [
        "APR-3",
        "APR-2",
        "APR-1",
    ]
    assert body["items"][2]["proposed_action_id"] == "PACT-1"
    assert body["items"][2]["status"] == "PENDING"


def test_filters():
    client = make_client()

    assert ids(client.get("/api/v1/approvals?status=PENDING")) == [
        "APR-3",
        "APR-1",
    ]
    assert ids(client.get("/api/v1/approvals?incident_id=INC-A")) == [
        "APR-2",
        "APR-1",
    ]
    assert ids(
        client.get("/api/v1/approvals?status=PENDING&incident_id=INC-A")
    ) == ["APR-1"]
    assert ids(client.get("/api/v1/approvals?incident_id=INC-NONE")) == []


def test_paging_with_cursor():
    client = make_client()

    first = client.get("/api/v1/approvals?limit=2").json()

    assert first["total"] == 3
    assert [i["approval_id"] for i in first["items"]] == ["APR-3", "APR-2"]
    assert first["next_cursor"]

    second = client.get(
        "/api/v1/approvals?limit=2&cursor=" + first["next_cursor"]
    ).json()

    assert [i["approval_id"] for i in second["items"]] == ["APR-1"]
    assert second["next_cursor"] is None


def test_paging_respects_filters():
    client = make_client()

    page = client.get("/api/v1/approvals?incident_id=INC-A&limit=1").json()

    assert page["total"] == 2
    assert [i["approval_id"] for i in page["items"]] == ["APR-2"]

    rest = client.get(
        "/api/v1/approvals?incident_id=INC-A&limit=1&cursor="
        + page["next_cursor"]
    ).json()

    assert [i["approval_id"] for i in rest["items"]] == ["APR-1"]
    assert rest["next_cursor"] is None


def test_bad_cursor_returns_400():
    response = make_client().get("/api/v1/approvals?cursor=not-a-cursor")

    assert response.status_code == 400


def test_requires_authentication():
    response = make_client(authenticated=False).get("/api/v1/approvals")

    assert response.status_code == 401


def test_rejects_invalid_token():
    client = make_client(authenticated=False)

    response = client.get(
        "/api/v1/approvals", headers={"Authorization": "Bearer aso_invalid"}
    )

    assert response.status_code == 401


def test_requires_read_permission():
    response = make_client(can_read=False).get("/api/v1/approvals")

    assert response.status_code == 403


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_other_methods_return_405(method):
    response = getattr(make_client(), method)("/api/v1/approvals")

    assert response.status_code == 405


@pytest.mark.parametrize("limit", [0, -1, 201, "abc"])
def test_limit_bounds_enforced(limit):
    response = make_client().get(f"/api/v1/approvals?limit={limit}")

    assert response.status_code == 422
