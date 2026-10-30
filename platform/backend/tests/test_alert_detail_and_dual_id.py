import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigations.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
)
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from tests.test_investigation_list_stores import seed


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by lookup tests.")


@pytest.fixture(autouse=True)
def isolated_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("ATHENASEC_PERSISTENCE_BACKEND", "sqlite")
    monkeypatch.setenv("ATHENASEC_DB_PATH", str(tmp_path / "app.db"))


def make_client(store, *, authenticated=True, can_read=True):
    identity = InMemoryOperatorIdentityStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=store,
        audit_store=InMemoryAuditStore(),
        incident_response_store=InMemoryIncidentResponseStore(),
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


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return seed(InMemoryInvestigationStore())

    return seed(SQLiteInvestigationStore(tmp_path / "lookup.db"))


@pytest.fixture
def client(store):
    return make_client(store)


def test_get_alert_found(client):
    response = client.get("/api/v1/alerts/ALT-1")

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == "ALT-1"
    assert body["incident_id"] == "INC-A"
    assert body["investigation_id"] == "INV-ALT-1"
    assert body["classification"] == "brute_force"
    assert body["risk_assessment"]["score"] == 80
    assert body["status"] == "complete"
    assert body["observed_at"].startswith("2026-03-01T11:30")
    assert body["event_text"] == "event"
    assert body["normalized_event"]
    assert "ml_error" in body


def test_get_alert_contains_list_entry_fields(client):
    entry = next(
        item
        for item in client.get("/api/v1/alerts").json()["items"]
        if item["alert_id"] == "ALT-2"
    )
    detail = client.get("/api/v1/alerts/ALT-2").json()

    for key, value in entry.items():
        assert detail[key] == value


def test_get_alert_not_found(client):
    response = client.get("/api/v1/alerts/NOPE")

    assert response.status_code == 404
    assert response.json() == {"detail": "Alert NOPE was not found."}


def test_get_alert_requires_authentication(store):
    response = make_client(store, authenticated=False).get(
        "/api/v1/alerts/ALT-1"
    )

    assert response.status_code == 401


def test_get_alert_rejects_invalid_token(store):
    client = make_client(store, authenticated=False)

    response = client.get(
        "/api/v1/alerts/ALT-1",
        headers={"Authorization": "Bearer aso_invalid"},
    )

    assert response.status_code == 401


def test_get_alert_requires_read_permission(store):
    response = make_client(store, can_read=False).get(
        "/api/v1/alerts/ALT-1"
    )

    assert response.status_code == 403


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_get_alert_rejects_other_methods(client, method):
    response = getattr(client, method)("/api/v1/alerts/ALT-1")

    assert response.status_code == 405


def test_list_route_still_served(client):
    assert client.get("/api/v1/alerts").json()["total"] == 3


def test_investigation_by_alert_id_unchanged(client):
    response = client.get("/api/v1/investigations/ALT-1")

    assert response.status_code == 200
    assert response.json()["alert_id"] == "ALT-1"


def test_investigation_by_investigation_id(client):
    by_alert = client.get("/api/v1/investigations/ALT-2").json()
    by_inv = client.get("/api/v1/investigations/INV-ALT-2")

    assert by_inv.status_code == 200
    assert by_inv.json() == by_alert


def test_investigation_unknown_id_is_404(client):
    response = client.get("/api/v1/investigations/INV-NOPE")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "Investigation INV-NOPE was not found."
    }


def test_investigation_id_without_stored_summary_is_404(client):
    response = client.get("/api/v1/investigations/INV-ORPHAN")

    assert response.status_code == 404


def test_investigation_route_stays_unauthenticated(store):
    client = make_client(store, authenticated=False)

    assert client.get("/api/v1/investigations/ALT-1").status_code == 200
    assert client.get("/api/v1/investigations/INV-ALT-1").status_code == 200
