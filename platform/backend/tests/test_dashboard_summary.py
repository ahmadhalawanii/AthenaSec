"""GET /api/v1/dashboard/summary and the stores it reads.

The summary is computed per request. Every record is built here; the app ships none.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.services.dashboard.dashboard_summary as dashboard_module
from app.main import create_app
from app.schemas import (
    ApprovalRequestRecord,
    AttackPrediction,
    CaseWorkflowRecord,
    IncidentAlertRecord,
    IncidentCaseRecord,
    IncidentInvestigationRecord,
    IncidentRecord,
    RiskAssessment,
)
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.cases.case_workflow_store import (
    CaseWorkflowSchemaNotReady,
    InMemoryCaseWorkflowStore,
)
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal
from tests.test_investigation_store import make_investigation

NOW = datetime(2026, 3, 1, 12, 30, tzinfo=timezone.utc)


def ago(**kwargs):
    return NOW - timedelta(**kwargs)


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by dashboard tests.")


def add_alert(store, number, observed_at, classification, band, *, status="complete",
              investigation_status=None):
    alert_id, incident_id = f"ALT-{number}", f"INC-{number}"
    base = make_investigation()
    store.save_incident(IncidentRecord(
        incident_id=incident_id, title=incident_id, status="open",
        created_at=observed_at, updated_at=observed_at))
    store.save_incident_alert(IncidentAlertRecord(
        incident_id=incident_id, alert_id=alert_id, source="manual",
        event_text="event", observed_at=observed_at))
    store.save(base.model_copy(update={
        "alert_id": alert_id, "incident_id": incident_id,
        "investigation_id": f"INV-{number}", "status": status,
        "analysis": base.analysis.model_copy(update={"classification": classification}),
        "risk_assessment": RiskAssessment(score=50, band=band, factors=[]),
        "ml_prediction": AttackPrediction(
            classification=classification, confidence=0.9, model_version="test"),
    }))
    store.save_incident_investigation(IncidentInvestigationRecord(
        investigation_id=f"INV-{number}", incident_id=incident_id,
        primary_alert_id=alert_id,
        status=investigation_status or ("complete" if status == "complete" else "failed"),
        started_at=observed_at, updated_at=observed_at))


def add_approval(store, approval_id, status, requested_at, decided_at=None):
    store.save_approval_request(ApprovalRequestRecord(
        approval_id=approval_id, incident_id="INC-1", proposed_action_id="PACT-1",
        policy_decision_id="PDEC-1", action_fingerprint="fp", status=status,
        requested_by="athenasec", requested_at=requested_at, decided_at=decided_at,
        decided_by="analyst-001" if decided_at else None))


def add_case(store, case_id, status, created_at):
    store.save_incident_case(IncidentCaseRecord(
        case_id=case_id, incident_id="INC-1", status=status, reason="r",
        created_at=created_at, updated_at=created_at))


def seed(investigation_store, response_store, workflow_store):
    add_alert(investigation_store, 1, ago(minutes=60), "brute_force", "high")
    add_alert(investigation_store, 2, ago(minutes=40), "privilege_escalation", "medium")
    add_alert(investigation_store, 3, NOW.replace(minute=10), "benign", "low", status="failed")
    add_alert(investigation_store, 4, datetime(2026, 2, 28, 12, 59, tzinfo=timezone.utc),
              "brute_force", "high")
    add_alert(investigation_store, 5, datetime(2026, 2, 28, 13, 0, tzinfo=timezone.utc),
              "brute_force", "high")
    add_alert(investigation_store, 6, datetime(2026, 2, 10, 9, 0, tzinfo=timezone.utc),
              "benign", "low")
    add_alert(investigation_store, 7, datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc),
              "benign", "low")

    add_approval(response_store, "APR-P1", "PENDING", ago(days=40))
    add_approval(response_store, "APR-P2", "PENDING", ago(hours=1))
    add_approval(response_store, "APR-A", "APPROVED", ago(hours=3), ago(hours=2))
    add_approval(response_store, "APR-X", "EXPIRED", datetime(2026, 2, 28, 12, 0, tzinfo=timezone.utc))
    add_approval(response_store, "APR-R", "REJECTED", ago(days=10), ago(days=10))

    add_case(response_store, "C-1", "open", ago(hours=1))
    add_case(response_store, "C-2", "investigating", ago(days=2))
    add_case(response_store, "C-3", "contained", ago(days=10))
    add_case(response_store, "C-4", "resolved", ago(days=20))
    add_case(response_store, "C-5", "closed", ago(days=50))

    for case_id, owner in (("C-1", "analyst-001"), ("C-2", "analyst-001"),
                           ("C-3", "someone-else"), ("C-4", "analyst-001")):
        workflow_store.save_workflow(CaseWorkflowRecord(
            case_id=case_id, assigned_analyst=owner, updated_at=NOW))


class SessionStore:
    def __init__(self):
        self.principals = {
            "admin": BrowserPrincipal("admin-1", "a@example.test", "Admin", "Administrator",
                                      True, True, "csrf"),
            "analyst": BrowserPrincipal("analyst-1", "n@example.test", "Analyst", "Analyst",
                                        True, False, "csrf"),
        }

    def resolve_session(self, session):
        return self.principals.get(session)


class Harness:
    def __init__(self, monkeypatch, *, with_data=True, auth="bearer", can_read=True,
                 workflow_store=None):
        monkeypatch.setattr(dashboard_module, "utc_now", lambda: NOW)
        self.investigation_store = InMemoryInvestigationStore()
        self.response_store = InMemoryIncidentResponseStore()
        self.workflow_store = workflow_store or InMemoryCaseWorkflowStore()
        identity = InMemoryOperatorIdentityStore()

        if with_data:
            seed(self.investigation_store, self.response_store, self.workflow_store)

        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=self.investigation_store,
            audit_store=InMemoryAuditStore(),
            incident_response_store=self.response_store,
            case_workflow_store=self.workflow_store,
            browser_auth_store=SessionStore(),
            operator_identity_store=identity,
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)

        if auth == "bearer":
            token = identity.provision(operator_id="analyst-001", can_read=can_read)
            self.client.headers["Authorization"] = "Bearer " + token
        elif auth in ("admin", "analyst"):
            self.client.cookies.set(SESSION_COOKIE_NAME, auth)

    def summary(self, query=""):
        return self.client.get("/api/v1/dashboard/summary" + query)


SUMMARY_FIELDS = {
    "window", "role", "generated_at", "window_start", "alerts", "investigations", "approvals",
    "cases", "my_cases", "response", "recent_alerts", "series",
}


# ---- empty state -----------------------------------------------------------

def test_empty_state_is_all_zeros_not_missing(monkeypatch):
    response = Harness(monkeypatch, with_data=False).summary()

    assert response.status_code == 200
    body = response.json()
    assert set(body) == SUMMARY_FIELDS
    assert body["alerts"] == {"total": 0, "by_classification": {}, "by_risk_band": {}, "by_status": {}}
    assert body["investigations"] == {"total": 0, "by_status": {}}
    assert body["approvals"] == {"pending": 0, "decided": 0}
    assert body["cases"] == {"active": 0, "by_status": {}, "opened_in_window": 0}
    assert body["my_cases"] == 0 and body["response"] is None
    assert body["recent_alerts"] == [] and body["series"] == []
    assert body["generated_at"].startswith("2026-03-01T12:30")


# ---- counts per window -----------------------------------------------------

def test_24h_window_counts(monkeypatch):
    body = Harness(monkeypatch).summary().json()

    assert body["window"] == "24h"
    assert body["window_start"].startswith("2026-02-28T13:00")
    assert body["alerts"] == {
        "total": 4,
        "by_classification": {"benign": 1, "brute_force": 2, "privilege_escalation": 1},
        "by_risk_band": {"high": 2, "low": 1, "medium": 1},
        "by_status": {"complete": 3, "failed": 1},
    }
    assert body["investigations"] == {"total": 4, "by_status": {"complete": 3, "failed": 1}}


@pytest.mark.parametrize("window,total,start", [
    ("24h", 4, "2026-02-28T13:00"),
    ("7d", 5, "2026-02-23T00:00"),
    ("30d", 6, "2026-01-31T00:00"),
])
def test_alert_total_per_window(monkeypatch, window, total, start):
    body = Harness(monkeypatch).summary(f"?window={window}").json()

    assert body["window"] == window
    assert body["alerts"]["total"] == total
    assert body["investigations"]["total"] == total
    assert body["window_start"].startswith(start)


def test_window_edges_are_inclusive_at_start_and_exclusive_before(monkeypatch):
    h = Harness(monkeypatch)
    recent = {a["alert_id"] for a in h.summary("?window=24h").json()["recent_alerts"]}

    assert "ALT-5" in recent and "ALT-4" not in recent


# ---- approvals and cases ---------------------------------------------------

def test_pending_approvals_are_current_and_decided_are_windowed(monkeypatch):
    h = Harness(monkeypatch)

    assert h.summary("?window=24h").json()["approvals"] == {"pending": 2, "decided": 1}
    assert h.summary("?window=7d").json()["approvals"] == {"pending": 2, "decided": 2}
    assert h.summary("?window=30d").json()["approvals"] == {"pending": 2, "decided": 3}


def test_cases_active_is_current_and_opened_is_windowed(monkeypatch):
    h = Harness(monkeypatch)
    by_status = {"closed": 1, "contained": 1, "investigating": 1, "open": 1, "resolved": 1}

    for window, opened in (("24h", 1), ("7d", 2), ("30d", 4)):
        cases = h.summary(f"?window={window}").json()["cases"]
        assert cases == {"active": 3, "by_status": by_status, "opened_in_window": opened}


# ---- series ----------------------------------------------------------------

def test_24h_series_is_hourly_zero_filled_and_sums_to_total(monkeypatch):
    body = Harness(monkeypatch).summary().json()
    series = body["series"]

    assert len(series) == 24
    assert series[0]["bucket_start"].startswith("2026-02-28T13:00")
    assert series[-1]["bucket_start"].startswith("2026-03-01T12:00")
    starts = [p["bucket_start"] for p in series]
    assert starts == sorted(starts)
    assert sum(p["alerts"] for p in series) == body["alerts"]["total"]
    counts = {p["bucket_start"][:13]: p["alerts"] for p in series}
    assert counts["2026-02-28T13"] == 1
    assert counts["2026-03-01T11"] == 2
    assert counts["2026-03-01T12"] == 1
    assert counts["2026-03-01T05"] == 0


@pytest.mark.parametrize("window,buckets", [("7d", 7), ("30d", 30)])
def test_long_windows_use_daily_buckets(monkeypatch, window, buckets):
    body = Harness(monkeypatch).summary(f"?window={window}").json()

    assert len(body["series"]) == buckets
    assert all(p["bucket_start"].endswith("T00:00:00Z") for p in body["series"])
    assert sum(p["alerts"] for p in body["series"]) == body["alerts"]["total"]


def test_series_is_empty_when_window_has_no_alerts(monkeypatch):
    h = Harness(monkeypatch, with_data=False)
    add_alert(h.investigation_store, 9, ago(days=20), "benign", "low")

    body = h.summary("?window=24h").json()

    assert body["alerts"]["total"] == 0 and body["series"] == []
    assert len(h.summary("?window=30d").json()["series"]) == 30


# ---- recent alerts ---------------------------------------------------------

def test_recent_alerts_are_newest_first_capped_at_five(monkeypatch):
    h = Harness(monkeypatch, with_data=False)
    for number in range(1, 9):
        add_alert(h.investigation_store, number, ago(minutes=number * 5), "benign", "low")

    recent = h.summary().json()["recent_alerts"]

    assert [a["alert_id"] for a in recent] == ["ALT-1", "ALT-2", "ALT-3", "ALT-4", "ALT-5"]
    assert {"alert_id", "classification", "risk_assessment", "status", "observed_at"} <= set(recent[0])
    assert h.summary().json()["alerts"]["total"] == 8


# ---- role views ------------------------------------------------------------

def test_bearer_caller_defaults_to_analyst_view(monkeypatch):
    body = Harness(monkeypatch).summary().json()

    assert body["role"] == "Analyst"
    assert body["my_cases"] == 2
    assert body["response"] is None


def test_my_cases_counts_only_active_cases_assigned_to_the_caller(monkeypatch):
    h = Harness(monkeypatch)
    h.workflow_store.save_workflow(CaseWorkflowRecord(
        case_id="C-3", assigned_analyst="analyst-001", updated_at=NOW))

    assert h.summary().json()["my_cases"] == 3


def test_administrator_session_defaults_to_administrator_view(monkeypatch):
    body = Harness(monkeypatch, auth="admin").summary().json()
    runtime = Harness(monkeypatch, auth="admin").client.get("/api/v1/runtime/status").json()

    assert body["role"] == "Administrator"
    assert body["my_cases"] is None
    assert body["response"] == {
        "response_mode": runtime["response_mode"],
        "operator_execution_enabled": runtime["operator_execution_enabled"],
        "effective_execution_enabled": runtime["effective_execution_enabled"],
    }


def test_administrator_can_ask_for_the_analyst_view(monkeypatch):
    body = Harness(monkeypatch, auth="admin").summary("?role=Analyst").json()

    assert body["role"] == "Analyst"
    assert body["response"] is None
    assert body["my_cases"] == 0  # no case is assigned to admin-1


@pytest.mark.parametrize("auth", ["bearer", "analyst"])
def test_non_administrators_cannot_request_the_administrator_view(monkeypatch, auth):
    response = Harness(monkeypatch, auth=auth).summary("?role=Administrator")

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Administrator permission required for the administrator summary."}


def test_analyst_session_defaults_to_analyst_view(monkeypatch):
    body = Harness(monkeypatch, auth="analyst").summary().json()

    assert body["role"] == "Analyst" and body["response"] is None


def test_role_changes_the_view_not_the_shared_counts(monkeypatch):
    h = Harness(monkeypatch, auth="admin")
    admin = h.summary().json()
    analyst = h.summary("?role=Analyst").json()

    for key in ("alerts", "investigations", "approvals", "cases", "series", "recent_alerts"):
        assert admin[key] == analyst[key]


# ---- validation and auth ---------------------------------------------------

@pytest.mark.parametrize("query", ["?window=1h", "?window=", "?role=Owner", "?window=24H"])
def test_invalid_parameters_are_422(monkeypatch, query):
    assert Harness(monkeypatch).summary(query).status_code == 422


def test_requires_authentication(monkeypatch):
    assert Harness(monkeypatch, auth=None).summary().status_code == 401


def test_rejects_invalid_token(monkeypatch):
    h = Harness(monkeypatch, auth=None)

    response = h.client.get("/api/v1/dashboard/summary",
                            headers={"Authorization": "Bearer aso_invalid"})

    assert response.status_code == 401


def test_requires_read_permission(monkeypatch):
    assert Harness(monkeypatch, can_read=False).summary().status_code == 403


# ---- failure and read-only -------------------------------------------------

class UnmigratedWorkflowStore(InMemoryCaseWorkflowStore):
    armed = False

    def get_workflow(self, case_id):
        if self.armed:
            raise CaseWorkflowSchemaNotReady("migrate")
        return super().get_workflow(case_id)


def test_unmigrated_workflow_tables_give_503(monkeypatch):
    store = UnmigratedWorkflowStore()
    h = Harness(monkeypatch, workflow_store=store)
    store.armed = True

    response = h.summary()

    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_summary_is_read_only(monkeypatch, method):
    assert Harness(monkeypatch).client.request(
        method, "/api/v1/dashboard/summary", json={}).status_code == 405


def test_reading_the_summary_changes_nothing(monkeypatch):
    h = Harness(monkeypatch)
    before = (h.response_store.list_approval_requests(), h.response_store.list_all_incident_cases(),
              h.investigation_store.list_alerts())

    h.summary()
    h.summary("?window=30d")

    after = (h.response_store.list_approval_requests(), h.response_store.list_all_incident_cases(),
             h.investigation_store.list_alerts())
    assert before == after


# ---- IncidentResponseStore.list_approval_requests --------------------------

@pytest.fixture(params=["memory", "sqlite"])
def response_store(request, tmp_path):
    if request.param == "memory":
        return InMemoryIncidentResponseStore()

    return SQLiteIncidentResponseStore(tmp_path / "approvals.db")


def test_list_approval_requests_empty(response_store):
    assert response_store.list_approval_requests() == []
    assert response_store.list_approval_requests(status="PENDING") == []


def test_list_approval_requests_newest_first_with_status_filter(response_store):
    add_approval(response_store, "APR-1", "PENDING", ago(hours=3))
    add_approval(response_store, "APR-3", "APPROVED", ago(hours=1), ago(minutes=30))
    add_approval(response_store, "APR-2", "PENDING", ago(hours=2))

    assert [a.approval_id for a in response_store.list_approval_requests()] == [
        "APR-3", "APR-2", "APR-1"]
    assert [a.approval_id for a in response_store.list_approval_requests(status="PENDING")] == [
        "APR-2", "APR-1"]
    assert response_store.list_approval_requests(status="REJECTED") == []


def test_postgres_list_approval_requests_binds_status():
    log = []
    record = ApprovalRequestRecord(
        approval_id="APR-1", incident_id="INC-1", proposed_action_id="P", policy_decision_id="D",
        action_fingerprint="fp", status="PENDING", requested_by="x", requested_at=NOW)

    class Result:
        def fetchall(self):
            return [(record.model_dump_json(),)]

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, statement, params=None):
            log.append((" ".join(str(statement).split()), params))
            return Result()

    store = PostgresIncidentResponseStore("postgresql://x/y", connect=lambda url: Conn())
    log.clear()

    assert [a.approval_id for a in store.list_approval_requests(status="PEN'; --")] == ["APR-1"]
    text, params = log[-1]
    assert "WHERE status = %s" in text and params == ("PEN'; --",)
    assert text.endswith("ORDER BY requested_at DESC, approval_id DESC")

    store.list_approval_requests()
    assert "WHERE" not in log[-1][0]


def test_sqlite_store_has_no_new_tables(tmp_path):
    path = tmp_path / "tables.db"
    SQLiteIncidentResponseStore(path)

    with sqlite3.connect(path) as connection:
        tables = {r[0] for r in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}

    assert not {"dashboard", "dashboard_summary", "summary_cache"} & tables
