from datetime import timedelta
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from tests.test_investigation_list_stores import BASE, seed


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by list tests.")


@pytest.fixture(autouse=True)
def isolated_persistence(monkeypatch, tmp_path):
    monkeypatch.setenv("ATHENASEC_PERSISTENCE_BACKEND", "sqlite")
    monkeypatch.setenv("ATHENASEC_DB_PATH", str(tmp_path / "list.db"))


def make_client(*, authenticated=True, can_read=True):
    identity = InMemoryOperatorIdentityStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=seed(InMemoryInvestigationStore()),
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


@pytest.fixture
def client():
    return make_client()


@pytest.mark.parametrize(
    "path", ["/api/v1/alerts", "/api/v1/investigations"]
)
def test_lists_require_authentication(path):
    response = make_client(authenticated=False).get(path)

    assert response.status_code == 401


@pytest.mark.parametrize(
    "path", ["/api/v1/alerts", "/api/v1/investigations"]
)
def test_lists_reject_invalid_token(path):
    client = make_client(authenticated=False)

    response = client.get(
        path, headers={"Authorization": "Bearer aso_invalid"}
    )

    assert response.status_code == 401


def test_alerts_envelope_and_item_shape(client):
    body = client.get("/api/v1/alerts").json()

    assert set(body) == {"total", "items", "next_cursor"}
    assert body["total"] == 3
    assert body["next_cursor"] is None
    assert [item["alert_id"] for item in body["items"]] == [
        "ALT-3",
        "ALT-2",
        "ALT-1",
    ]
    item = body["items"][2]
    assert item["classification"] == "brute_force"
    assert item["ml_prediction"]["classification"] == "brute_force"
    assert item["risk_assessment"]["score"] == 80
    assert item["status"] == "complete"
    assert item["incident_id"] == "INC-A"
    assert item["observed_at"].startswith("2026-03-01T11:30")


def test_alerts_filters(client):
    def ids(query):
        response = client.get("/api/v1/alerts" + query)
        assert response.status_code == 200
        return [item["alert_id"] for item in response.json()["items"]]

    assert ids("?status=complete") == ["ALT-2", "ALT-1"]
    assert ids("?classification=benign") == ["ALT-3"]
    since = quote((BASE - timedelta(minutes=25)).isoformat())
    assert ids("?since=" + since) == ["ALT-3", "ALT-2"]
    assert ids("?status=complete&classification=benign") == []


def test_alerts_invalid_classification_rejected(client):
    assert (
        client.get("/api/v1/alerts?classification=nonsense").status_code
        == 422
    )


def test_alerts_paginate_with_cursor(client):
    first = client.get("/api/v1/alerts?limit=2").json()

    assert first["total"] == 3
    assert [i["alert_id"] for i in first["items"]] == ["ALT-3", "ALT-2"]
    assert first["next_cursor"]

    second = client.get(
        "/api/v1/alerts?limit=2&cursor=" + first["next_cursor"]
    ).json()

    assert second["total"] == 3
    assert [i["alert_id"] for i in second["items"]] == ["ALT-1"]
    assert second["next_cursor"] is None


def test_alert_pagination_respects_filters(client):
    page = client.get("/api/v1/alerts?status=complete&limit=1").json()

    assert page["total"] == 2
    assert [i["alert_id"] for i in page["items"]] == ["ALT-2"]

    rest = client.get(
        "/api/v1/alerts?status=complete&limit=1&cursor="
        + page["next_cursor"]
    ).json()

    assert [i["alert_id"] for i in rest["items"]] == ["ALT-1"]
    assert rest["next_cursor"] is None


@pytest.mark.parametrize("limit", [0, -1, 201, "abc"])
def test_limit_bounds_enforced(client, limit):
    for path in ("/api/v1/alerts", "/api/v1/investigations"):
        assert client.get(f"{path}?limit={limit}").status_code == 422


def test_invalid_cursor_is_a_400(client):
    for path in ("/api/v1/alerts", "/api/v1/investigations"):
        response = client.get(path + "?cursor=garbage")

        assert response.status_code == 400


def test_investigations_envelope_and_item_shape(client):
    body = client.get("/api/v1/investigations").json()

    assert set(body) == {"total", "items", "next_cursor"}
    assert body["total"] == 4
    assert [i["investigation_id"] for i in body["items"]] == [
        "INV-ORPHAN",
        "INV-ALT-3",
        "INV-ALT-2",
        "INV-ALT-1",
    ]
    item = body["items"][3]
    assert item["incident_id"] == "INC-A"
    assert item["primary_alert_id"] == "ALT-1"
    assert item["status"] == "complete"
    assert item["classification"] == "brute_force"
    assert item["risk_score"] == 80
    assert item["risk_band"] == "high"
    assert item["policy_outcome"] == "create_case"
    orphan = body["items"][0]
    assert orphan["classification"] is None
    assert orphan["risk_score"] is None


def test_investigations_filters(client):
    def ids(query):
        response = client.get("/api/v1/investigations" + query)
        assert response.status_code == 200
        return [i["investigation_id"] for i in response.json()["items"]]

    assert ids("?incident_id=INC-A") == ["INV-ALT-2", "INV-ALT-1"]
    assert ids("?status=open") == ["INV-ORPHAN"]
    assert ids("?incident_id=INC-A&status=open") == []
    assert ids("?incident_id=INC-NONE") == []


def test_investigations_paginate_with_cursor(client):
    seen = []
    cursor = None

    while True:
        query = "?limit=3" + (f"&cursor={cursor}" if cursor else "")
        body = client.get("/api/v1/investigations" + query).json()
        assert body["total"] == 4
        seen.extend(i["investigation_id"] for i in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert seen == [
        "INV-ORPHAN",
        "INV-ALT-3",
        "INV-ALT-2",
        "INV-ALT-1",
    ]


def test_empty_store_returns_empty_envelope():
    identity = InMemoryOperatorIdentityStore()
    token = identity.provision(operator_id="analyst-001")
    client = TestClient(
        create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            autonomous_response_enabled=False,
            operator_identity_store=identity,
        ),
        headers={"Authorization": "Bearer " + token},
    )

    for path in ("/api/v1/alerts", "/api/v1/investigations"):
        assert client.get(path).json() == {
            "total": 0,
            "items": [],
            "next_cursor": None,
        }


def test_existing_investigation_detail_route_still_resolves(client):
    # The list route must not shadow GET /investigations/{alert_id}.
    assert client.get("/api/v1/investigations/ALT-1").status_code == 200
    assert (
        client.get("/api/v1/investigations/NOPE").status_code == 404
    )


@pytest.mark.parametrize(
    "path", ["/api/v1/alerts", "/api/v1/investigations"]
)
def test_lists_require_read_permission(path):
    response = make_client(can_read=False).get(path)

    assert response.status_code == 403
