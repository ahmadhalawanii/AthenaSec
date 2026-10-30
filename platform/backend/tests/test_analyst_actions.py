"""Website analyst actions: close/reopen and assign alerts and cases, tick case actions.

Each change needs a browser session plus the CSRF token, is stored, shows in the GET
routes, and writes an operator audit event.
"""

from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import CaseActionRecord
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.audit.operator_audit_store import InMemoryOperatorAuditStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal
from app.services.cases.case_workflow_store import InMemoryCaseWorkflowStore
from app.services.investigations.alert_workflow_store import (
    InMemoryAlertWorkflowStore,
    SQLiteAlertWorkflowStore,
)
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from tests.test_cases_endpoints import UnusedGraph, case_record, enrich_alert_1
from tests.test_investigation_list_stores import seed

CSRF = {"X-AthenaSec-CSRF": "csrf-1"}


class Sessions:
    principals = {
        "analyst": BrowserPrincipal("u-1", "a@x.test", "Sara Analyst", "Analyst", True, False, "csrf-1"),
        "noread": BrowserPrincipal("u-2", "b@x.test", "No Read", "Analyst", False, False, "csrf-2"),
    }

    def resolve_session(self, session):
        return self.principals.get(session)


class Harness:
    def __init__(self, session="analyst"):
        self.investigations = InMemoryInvestigationStore()
        self.responses = InMemoryIncidentResponseStore()
        self.workflow = InMemoryCaseWorkflowStore()
        self.alerts = InMemoryAlertWorkflowStore()
        self.audit = InMemoryOperatorAuditStore()
        seed(self.investigations)
        enrich_alert_1(self.investigations)
        self.responses.save_incident_case(case_record("CASE-1", "INC-A", investigation_id="INV-ALT-1"))
        self.responses.save_incident_case(case_record("CASE-2", "INC-A", minutes=2))
        self.workflow.replace_actions("CASE-2", [
            CaseActionRecord(case_id="CASE-2", position=0, label="Call the asset owner"),
            CaseActionRecord(case_id="CASE-2", position=1, label="Reset the account",
                             approval_id="APR-9"),
        ])
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=self.investigations,
            audit_store=InMemoryAuditStore(),
            incident_response_store=self.responses,
            case_workflow_store=self.workflow,
            alert_workflow_store=self.alerts,
            operator_audit_store=self.audit,
            browser_auth_store=Sessions(),
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)
        if session:
            self.client.cookies.set(SESSION_COOKIE_NAME, session)

    def post(self, path, body=None, headers=CSRF):
        return self.client.post(path, json=body, headers=headers)

    def events(self, event_type):
        return sorted(self.audit.list_events(event_type=event_type), key=lambda e: e.seq)


# ---- alerts ----------------------------------------------------------------

def test_alerts_start_open_and_unassigned():
    item = Harness().client.get("/api/v1/alerts/ALT-1").json()

    assert item["analyst_status"] == "open" and item["assigned_analyst"] is None


def test_close_and_reopen_an_alert():
    h = Harness()

    closed = h.post("/api/v1/alerts/ALT-1/status", {"status": "closed"})

    assert closed.status_code == 200 and closed.json()["analyst_status"] == "closed"
    listed = {a["alert_id"]: a for a in h.client.get("/api/v1/alerts").json()["items"]}
    assert listed["ALT-1"]["analyst_status"] == "closed"
    assert h.alerts.get("ALT-1").updated_by == "u-1"
    assert h.post("/api/v1/alerts/ALT-1/status", {"status": "open"}).json()["analyst_status"] == "open"
    changes = h.events("alert_status_changed")
    assert [e.action for e in changes] == ["close", "reopen"]


def test_assign_alert_to_me_keeps_status():
    h = Harness()
    h.post("/api/v1/alerts/ALT-1/status", {"status": "closed"})

    assigned = h.post("/api/v1/alerts/ALT-1/assign")

    assert assigned.json()["assigned_analyst"] == "Sara Analyst"
    assert assigned.json()["analyst_status"] == "closed"
    assert len(h.events("alert_assigned")) == 1
    h.post("/api/v1/alerts/ALT-1/assign")
    assert len(h.events("alert_assigned")) == 1  # no change, no second event


def test_unknown_alert_is_404_and_bad_status_is_422():
    h = Harness()

    assert h.post("/api/v1/alerts/NOPE/status", {"status": "closed"}).status_code == 404
    assert h.post("/api/v1/alerts/ALT-1/status", {"status": "deleted"}).status_code == 422


def test_changes_need_a_session_csrf_and_read_permission():
    assert Harness(session=None).post("/api/v1/alerts/ALT-1/assign").status_code == 401
    assert Harness().post("/api/v1/alerts/ALT-1/assign", headers={}).status_code == 403
    assert Harness("noread").post("/api/v1/alerts/ALT-1/assign",
                                  headers={"X-AthenaSec-CSRF": "csrf-2"}).status_code == 403


def test_sqlite_alert_workflow_store_round_trips(tmp_path):
    from datetime import datetime, timezone
    from app.schemas import AlertWorkflowRecord

    store = SQLiteAlertWorkflowStore(tmp_path / "a.db")
    record = AlertWorkflowRecord(alert_id="A", status="closed", assigned_analyst="S",
                                 updated_at=datetime(2026, 10, 1, tzinfo=timezone.utc), updated_by="u")
    store.save(record)
    store.save(record.model_copy(update={"status": "open"}))

    assert store.get("A").status == "open"
    assert list(store.list_all()) == ["A"]
    assert store.get("B") is None


# ---- cases -----------------------------------------------------------------

def test_close_and_reopen_a_case_adds_timeline_notes():
    h = Harness()

    closed = h.post("/api/v1/cases/CASE-1/status", {"status": "closed"})

    assert closed.status_code == 200
    assert closed.json()["status"] == "closed" and closed.json()["closed_at"] is not None
    assert h.responses.get_incident_case("CASE-1").status == "closed"
    assert closed.json()["timeline"][-1]["title"] == "Case closed"
    reopened = h.post("/api/v1/cases/CASE-1/status", {"status": "open"}).json()
    assert reopened["status"] == "open" and reopened["closed_at"] is None
    assert [e.action for e in h.events("case_status_changed")] == ["close", "reopen"]


def test_assign_case_to_me():
    h = Harness()

    case = h.post("/api/v1/cases/CASE-1/assign").json()

    assert case["assigned_analyst"] == "Sara Analyst"
    assert case["timeline"][-1]["title"] == "Case assigned"
    assert len(h.events("case_assigned")) == 1


def test_tick_and_untick_a_manual_case_action():
    h = Harness()

    ticked = h.client.put("/api/v1/cases/CASE-2/actions/0", json={"done": True}, headers=CSRF)

    assert ticked.status_code == 200
    assert ticked.json()["recommended_actions"][0]["done"] is True
    assert h.workflow.list_actions("CASE-2")[0].done is True
    unticked = h.client.put("/api/v1/cases/CASE-2/actions/0", json={"done": False}, headers=CSRF)
    assert unticked.json()["recommended_actions"][0]["done"] is False
    assert len(h.events("case_action_updated")) == 2


def test_approval_linked_actions_cannot_be_ticked():
    h = Harness()

    response = h.client.put("/api/v1/cases/CASE-2/actions/1", json={"done": True}, headers=CSRF)

    assert response.status_code == 409
    assert h.client.put("/api/v1/cases/CASE-2/actions/7", json={"done": True},
                        headers=CSRF).status_code == 404


def test_unknown_case_is_404():
    assert Harness().post("/api/v1/cases/NOPE/status", {"status": "closed"}).status_code == 404
