"""GET /api/v1/audit, /api/v1/audit/{event_id}, /api/v1/audit/verify. Admin only.

Operator events and incident events are created here; the app ships none.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import AuditRecord, IncidentAuditRecord
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.audit.operator_audit_store import (
    InMemoryOperatorAuditStore,
    OperatorAuditSchemaNotReady,
)
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal

T0 = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("No investigation required")


class SessionStore:
    def __init__(self):
        self.principals = {
            "admin-session": BrowserPrincipal(
                "admin-1", "admin@example.test", "Admin", "Administrator",
                True, True, "csrf-admin"),
            "analyst-session": BrowserPrincipal(
                "analyst-1", "analyst@example.test", "Analyst", "Analyst",
                True, False, "csrf-analyst"),
        }

    def resolve_session(self, session):
        return self.principals.get(session)


def operator_event(store, index, **overrides):
    fields = dict(
        actor_id=f"admin-{index}", actor_role="Administrator", category="user",
        action="suspend", target=f"user-{index}", result="Success",
        source_ip="198.51.100.4", event_type="user_suspended",
        detail={"index": index}, occurred_at=T0 + timedelta(hours=index),
    )
    fields.update(overrides)
    return store.append_event(**fields)


def incident_event(audit_store, index, **overrides):
    fields = dict(
        audit_id=f"AUD-{index:03d}", incident_id=f"INC-{index}",
        event_type="approval_decided", entity_type="approval_request",
        entity_id=f"APR-{index}", message="Human approval decision was recorded.",
        details={"decided_by": "someone"}, timestamp=T0 + timedelta(hours=index, minutes=30),
    )
    fields.update(overrides)
    return audit_store.save_incident_event(IncidentAuditRecord(**fields))


class Harness:
    def __init__(self, session="admin-session", operator_store=None):
        self.operator_store = operator_store or InMemoryOperatorAuditStore()
        self.audit_store = InMemoryAuditStore()
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=self.audit_store,
            incident_response_store=InMemoryIncidentResponseStore(),
            browser_auth_store=SessionStore(),
            operator_audit_store=self.operator_store,
            autonomous_response_enabled=False,
            operator_control_key="test-operator-key",
        )
        self.client = TestClient(app)
        if session is not None:
            self.client.cookies.set(SESSION_COOKIE_NAME, session)

    def get(self, path):
        return self.client.get(path)


EVENT_FIELDS = {
    "seq", "event_id", "occurred_at", "actor_id", "actor_role", "category",
    "action", "target", "result", "source_ip", "source", "incident_id",
    "event_type", "message", "detail", "prev_hash", "row_hash",
}


def ids(response):
    return [item["event_id"] for item in response.json()["items"]]


# ---- empty state -----------------------------------------------------------

def test_empty_audit_list():
    response = Harness().get("/api/v1/audit")

    assert response.status_code == 200
    assert response.json() == {
        "total": 0, "items": [], "next_cursor": None, "alert_events": [],
    }


def test_empty_verify():
    response = Harness().get("/api/v1/audit/verify")

    assert response.status_code == 200
    assert response.json() == {
        "valid": True, "checked": 0, "first_broken_seq": None, "head_hash": None,
    }


# ---- shape and merge -------------------------------------------------------

def test_items_merge_both_sources_newest_first_with_stable_shape():
    h = Harness()
    first = operator_event(h.operator_store, 1)
    incident_event(h.audit_store, 1)
    third = operator_event(h.operator_store, 2)

    response = h.get("/api/v1/audit")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert [i["event_id"] for i in body["items"]] == [third.event_id, "AUD-001", first.event_id]
    assert all(set(item) == EVENT_FIELDS for item in body["items"])
    assert response.headers["cache-control"] == "no-store"

    operator, incident = body["items"][0], body["items"][1]
    assert operator["source"] == "operator" and operator["row_hash"] and operator["incident_id"] is None
    assert incident["source"] == "incident" and incident["row_hash"] is None
    assert incident["incident_id"] == "INC-1"
    assert incident["actor_role"] == "System"
    assert incident["category"] == "approval_request" and incident["target"] == "APR-1"
    assert incident["message"] == "Human approval decision was recorded."
    assert incident["detail"] == {"decided_by": "someone"}


# ---- filters ---------------------------------------------------------------

def test_filters():
    h = Harness()
    operator_event(h.operator_store, 1, category="user", result="Success", actor_id="admin-a")
    operator_event(h.operator_store, 2, category="policy", result="Denied", actor_id="admin-b",
                   event_type="policy_update", action="update policy", target="policy-v3")
    incident_event(h.audit_store, 3, incident_id="INC-X", entity_type="alert",
                   entity_id="ALERT-9", event_type="alert_received")

    def query(qs):
        return h.get("/api/v1/audit" + qs)

    assert [i["actor_id"] for i in query("?actor=admin-b").json()["items"]] == ["admin-b"]
    assert query("?category=policy").json()["total"] == 1
    assert query("?result=Denied").json()["total"] == 1
    assert query("?event_type=alert_received").json()["items"][0]["source"] == "incident"
    assert query("?incident_id=INC-X").json()["total"] == 1
    assert query("?incident_id=INC-NONE").json()["total"] == 0
    assert query("?alert_id=ALERT-9").json()["items"][0]["target"] == "ALERT-9"
    assert query("?q=POLICY-V3").json()["total"] == 1
    assert query("?q=nothing-matches").json()["total"] == 0
    assert query("?actor=system").json()["total"] == 1
    assert query("?result=Failed").json()["total"] == 0


def test_since_and_until_cover_both_sources():
    h = Harness()
    operator_event(h.operator_store, 1)
    incident_event(h.audit_store, 2)
    operator_event(h.operator_store, 3)
    since = (T0 + timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    until = (T0 + timedelta(hours=2, minutes=45)).isoformat().replace("+00:00", "Z")

    response = h.get(f"/api/v1/audit?since={since}&until={until}")

    assert response.status_code == 200
    assert [i["event_id"] for i in response.json()["items"]] == ["AUD-002"]


def test_naive_timestamps_are_read_as_utc():
    h = Harness()
    operator_event(h.operator_store, 1)

    response = h.get("/api/v1/audit?since=2026-05-01T00:00:00")

    assert response.status_code == 200 and response.json()["total"] == 1


def test_alert_id_returns_legacy_alert_events():
    h = Harness()
    h.audit_store.save(AuditRecord(
        audit_id="LEG-1", alert_id="ALERT-1", timestamp=T0,
        event_type="investigation_created", message="legacy", details={"k": "v"},
    ))
    h.audit_store.save(AuditRecord(
        audit_id="LEG-2", alert_id="ALERT-2", timestamp=T0,
        event_type="investigation_created", message="other", details={},
    ))

    body = h.get("/api/v1/audit?alert_id=ALERT-1").json()

    assert [r["audit_id"] for r in body["alert_events"]] == ["LEG-1"]
    assert h.get("/api/v1/audit").json()["alert_events"] == []


# ---- paging ----------------------------------------------------------------

def test_cursor_pages_cover_every_event_once():
    h = Harness()
    for i in range(1, 6):
        operator_event(h.operator_store, i)
    incident_event(h.audit_store, 9)

    seen, cursor, pages = [], None, 0
    while True:
        url = "/api/v1/audit?limit=2" + (f"&cursor={cursor}" if cursor else "")
        body = h.get(url).json()
        seen += [i["event_id"] for i in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert pages == 3 and len(seen) == 6 and len(set(seen)) == 6
    assert body["total"] == 6


def test_bad_cursor_and_inverted_range_are_400():
    h = Harness()

    assert h.get("/api/v1/audit?cursor=nope").status_code == 400
    response = h.get("/api/v1/audit?since=2026-06-01T00:00:00Z&until=2026-05-01T00:00:00Z")
    assert response.status_code == 400
    assert "detail" in response.json()


@pytest.mark.parametrize("qs", ["?result=Maybe", "?limit=0", "?limit=201", "?since=yesterday"])
def test_invalid_query_is_422(qs):
    assert Harness().get("/api/v1/audit" + qs).status_code == 422


# ---- get by id -------------------------------------------------------------

def test_get_operator_and_incident_event_by_id():
    h = Harness()
    op = operator_event(h.operator_store, 1)
    incident_event(h.audit_store, 2)

    operator_body = h.get(f"/api/v1/audit/{op.event_id}").json()
    incident_body = h.get("/api/v1/audit/AUD-002").json()

    assert set(operator_body) == EVENT_FIELDS and operator_body["row_hash"] == op.row_hash
    assert incident_body["source"] == "incident" and incident_body["event_id"] == "AUD-002"


def test_unknown_event_is_404_with_detail():
    response = Harness().get("/api/v1/audit/nope")

    assert response.status_code == 404
    assert response.json() == {"detail": "Audit event nope was not found."}


def test_verify_is_not_shadowed_by_event_id_route():
    assert Harness().get("/api/v1/audit/verify").json()["valid"] is True


# ---- verify ----------------------------------------------------------------

def test_verify_reports_intact_chain_and_head():
    h = Harness()
    operator_event(h.operator_store, 1)
    last = operator_event(h.operator_store, 2)

    body = h.get("/api/v1/audit/verify").json()

    assert body == {"valid": True, "checked": 2, "first_broken_seq": None,
                    "head_hash": last.row_hash}


def test_verify_reports_tampering():
    h = Harness()
    for i in range(1, 4):
        operator_event(h.operator_store, i)
    h.operator_store._events[1] = h.operator_store._events[1].model_copy(
        update={"actor_id": "forged"})

    body = h.get("/api/v1/audit/verify").json()

    assert body["valid"] is False
    assert body["first_broken_seq"] == 2 and body["head_hash"] is None


# ---- auth ------------------------------------------------------------------

PATHS = ["/api/v1/audit", "/api/v1/audit/verify", "/api/v1/audit/OPAUD-x"]


@pytest.mark.parametrize("path", PATHS)
def test_no_session_is_401(path):
    assert Harness(session=None).get(path).status_code == 401


@pytest.mark.parametrize("path", PATHS)
def test_forged_session_is_401(path):
    assert Harness(session="forged").get(path).status_code == 401


@pytest.mark.parametrize("path", PATHS)
def test_analyst_is_403(path):
    response = Harness(session="analyst-session").get(path)

    assert response.status_code == 403
    assert response.json() == {"detail": "Administrator permission required."}


def test_bearer_token_is_not_enough():
    h = Harness(session=None)

    response = h.client.get("/api/v1/audit", headers={"Authorization": "Bearer operator-token"})

    assert response.status_code == 401


def test_denied_requests_do_not_leak_events():
    h = Harness(session="analyst-session")
    operator_event(h.operator_store, 1)

    assert "admin-1" not in h.get("/api/v1/audit").text


# ---- schema not ready and read-only ---------------------------------------

class UnmigratedStore:
    def _fail(self, *args, **kwargs):
        raise OperatorAuditSchemaNotReady("migrate")

    list_events = get_event = verify_chain = _fail


@pytest.mark.parametrize("path", ["/api/v1/audit", "/api/v1/audit/OPAUD-x", "/api/v1/audit/verify"])
def test_unmigrated_postgres_table_is_503(path):
    response = Harness(operator_store=UnmigratedStore()).get(path)

    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", ["/api/v1/audit", "/api/v1/audit/OPAUD-x"])
def test_audit_routes_have_no_writes(method, path):
    h = Harness()
    h.client.headers["X-AthenaSec-CSRF"] = "csrf-admin"

    assert h.client.request(method, path, json={}).status_code == 405
