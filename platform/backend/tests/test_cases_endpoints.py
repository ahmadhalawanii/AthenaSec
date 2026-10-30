"""Read-only Cases: GET /api/v1/cases and /api/v1/cases/{case_id}.

Cases come from incident_cases only (not the legacy cases table). Every record is built
here; the app ships none.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import (
    ApprovalRequestRecord,
    CaseActionRecord,
    CaseNoteRecord,
    CaseWorkflowRecord,
    IncidentCaseRecord,
    IncidentCorrelationProfile,
    InvestigationTraceStep,
    ProposedActionRecord,
)
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.cases.case_workflow_store import (
    CaseWorkflowSchemaNotReady,
    InMemoryCaseWorkflowStore,
)
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal
from tests.test_investigation_list_stores import BASE, seed


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by case tests.")


def case_record(case_id, incident_id, *, investigation_id=None, status="open", minutes=0,
                reason="Automatic containment is not permitted."):
    when = BASE + timedelta(minutes=minutes)
    return IncidentCaseRecord(
        case_id=case_id, incident_id=incident_id, investigation_id=investigation_id,
        status=status, reason=reason, created_at=when, updated_at=when,
    )


def enrich_alert_1(investigation_store):
    """Give ALT-1 the metadata, proposed action, approval and trace the view derives from."""

    base = investigation_store.get("ALT-1")
    action = ProposedActionRecord(
        proposed_action_id="PACT-1", incident_id="INC-A", investigation_id="INV-ALT-1",
        action_type="block_ip", target_type="ip", target="203.0.113.10", reversible=True,
        reason="Repeated failures", proposed_at=BASE,
    )
    approval = ApprovalRequestRecord(
        approval_id="APR-1", incident_id="INC-A", proposed_action_id="PACT-1",
        policy_decision_id="PDEC-1", action_fingerprint="fp", status="PENDING",
        requested_by="athenasec", requested_at=BASE,
    )
    trace = [
        InvestigationTraceStep(sequence=1, step_type="analysis", status="completed",
                               recorded_at=BASE + timedelta(minutes=1)),
        InvestigationTraceStep(sequence=2, step_type="evidence_gathering", status="failed: timeout",
                               recorded_at=BASE + timedelta(minutes=3)),
    ]
    investigation_store.save(base.model_copy(update={
        "alert_metadata": {
            "source_ip": "203.0.113.10", "agent_name": "web-01", "agent_ip": "10.0.0.5",
            "mitre_ids": ["T1110"],
        },
        "proposed_actions": [action],
        "approval_requests": [approval],
        "investigation_trace": trace,
    }))
    investigation_store.save_correlation_profile(IncidentCorrelationProfile(
        incident_id="INC-A", classification="brute_force", source_ips=["203.0.113.10"],
        mitre_ids=["T1110", "T1078"], first_seen=BASE, last_seen=BASE,
    ))


class Harness:
    def __init__(self, *, with_data=True, can_read=True, authenticated=True,
                 workflow_store=None):
        self.investigation_store = InMemoryInvestigationStore()
        self.response_store = InMemoryIncidentResponseStore()
        self.workflow_store = workflow_store or InMemoryCaseWorkflowStore()
        self.identity = InMemoryOperatorIdentityStore()

        if with_data:
            seed(self.investigation_store)
            enrich_alert_1(self.investigation_store)
            for record in (
                case_record("CASE-1", "INC-A", investigation_id="INV-ALT-1", minutes=1),
                case_record("CASE-2", "INC-A", status="investigating", minutes=2),
                case_record("CASE-3", "INC-B", investigation_id="INV-ORPHAN", minutes=3),
                case_record("CASE-4", "INC-GONE", status="closed", minutes=4),
            ):
                self.response_store.save_incident_case(record)

            self.workflow_store.save_workflow(CaseWorkflowRecord(
                case_id="CASE-1", assigned_analyst="analyst-7", summary="Analyst summary",
                updated_at=BASE + timedelta(hours=2), version=3,
            ))
            self.workflow_store.append_note(CaseNoteRecord(
                case_id="CASE-1", seq=1, occurred_at=BASE + timedelta(minutes=2),
                title="Called the owner", description="Owner confirmed", author="analyst-7",
            ))

        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=self.investigation_store,
            audit_store=InMemoryAuditStore(),
            incident_response_store=self.response_store,
            case_workflow_store=self.workflow_store,
            autonomous_response_enabled=False,
            operator_identity_store=self.identity,
        )
        self.client = TestClient(app)

        if authenticated:
            token = self.identity.provision(operator_id="analyst-001", can_read=can_read)
            self.client.headers["Authorization"] = "Bearer " + token

    def get(self, path):
        return self.client.get(path)


CASE_FIELDS = {
    "case_id", "incident_id", "investigation_id", "alert_id", "policy_id", "classification",
    "risk_score", "risk_band", "status", "reason", "assigned_analyst", "summary", "endpoint",
    "source_ip", "evidence", "recommended_actions", "mitre_ids", "timeline", "version",
    "created_at", "updated_at", "closed_at",
}


def ids(response):
    return [item["case_id"] for item in response.json()["items"]]


# ---- empty state -----------------------------------------------------------

def test_empty_state():
    response = Harness(with_data=False).get("/api/v1/cases")

    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": [], "next_cursor": None}


# ---- shape and derivation --------------------------------------------------

def test_list_shape_order_and_names():
    response = Harness().get("/api/v1/cases")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"total", "items", "next_cursor"}
    assert body["total"] == 4
    assert ids(response) == ["CASE-4", "CASE-3", "CASE-2", "CASE-1"]
    assert all(set(item) == CASE_FIELDS for item in body["items"])
    assert "assigned_analyst" in CASE_FIELDS and "recommended_actions" in CASE_FIELDS
    assert "mitre_ids" in CASE_FIELDS and "assigned_to" not in CASE_FIELDS


def test_case_with_workflow_and_investigation():
    case = Harness().get("/api/v1/cases/CASE-1").json()

    assert case["status"] == "open"
    assert case["incident_id"] == "INC-A"
    assert case["investigation_id"] == "INV-ALT-1"
    assert case["alert_id"] == "ALT-1"
    assert case["assigned_analyst"] == "analyst-7"
    assert case["summary"] == "Analyst summary"
    assert case["version"] == 3
    assert case["classification"] == "brute_force"
    assert case["risk_score"] == 80 and case["risk_band"] == "high"
    assert case["policy_id"] == "POL-BF-HIGH"
    assert case["endpoint"] == "web-01"
    assert case["source_ip"] == "203.0.113.10"
    assert case["mitre_ids"] == ["T1110", "T1078"]
    assert [e["evidence_id"] for e in case["evidence"]] == ["E001"]
    assert case["evidence"][0]["content"] == "SSH failures detected."
    assert case["updated_at"].startswith("2026-03-01T14:00")
    assert case["closed_at"] is None


def test_default_recommended_actions_come_from_proposed_actions():
    case = Harness().get("/api/v1/cases/CASE-1").json()

    assert case["recommended_actions"] == [{
        "position": 0, "label": "block_ip 203.0.113.10", "done": False,
        "proposed_action_id": "PACT-1", "approval_id": "APR-1",
    }]


def test_stored_actions_override_derived_ones():
    h = Harness()
    h.workflow_store.replace_actions("CASE-1", [
        CaseActionRecord(case_id="CASE-1", position=0, label="Reset credentials", done=True),
        CaseActionRecord(case_id="CASE-1", position=1, label="Notify owner"),
    ])

    actions = h.get("/api/v1/cases/CASE-1").json()["recommended_actions"]

    assert [(a["label"], a["done"]) for a in actions] == [
        ("Reset credentials", True), ("Notify owner", False),
    ]


def test_timeline_merges_agent_steps_and_analyst_notes_in_time_order():
    timeline = Harness().get("/api/v1/cases/CASE-1").json()["timeline"]

    assert [e["seq"] for e in timeline] == [1, 2, 3]
    assert [e["source"] for e in timeline] == ["agent", "analyst", "agent"]
    assert timeline[0]["title"] == "Analysis" and timeline[0]["failed"] is False
    assert timeline[1]["title"] == "Called the owner" and timeline[1]["author"] == "analyst-7"
    assert timeline[2]["description"] == "failed: timeout" and timeline[2]["failed"] is True
    times = [e["occurred_at"] for e in timeline]
    assert times == sorted(times)


def test_case_without_workflow_uses_defaults_and_latest_investigation():
    case = Harness().get("/api/v1/cases/CASE-2").json()

    assert case["assigned_analyst"] is None
    assert case["version"] == 1 and case["closed_at"] is None
    assert case["investigation_id"] == "INV-ALT-2"
    assert case["alert_id"] == "ALT-2"
    assert case["classification"] == "privilege_escalation"
    assert case["summary"] == "SSH brute force detected."
    assert case["recommended_actions"] == [] and case["timeline"] == []


def test_case_whose_investigation_summary_is_missing_still_renders():
    case = Harness().get("/api/v1/cases/CASE-3").json()

    assert case["investigation_id"] == "INV-ORPHAN"
    assert case["alert_id"] == "ALT-MISSING"
    for key in ("classification", "risk_score", "risk_band", "policy_id", "summary",
                "endpoint", "source_ip", "assigned_analyst"):
        assert case[key] is None
    assert case["evidence"] == [] and case["mitre_ids"] == []


def test_case_with_no_investigation_at_all_still_renders():
    case = Harness().get("/api/v1/cases/CASE-4").json()

    assert case["status"] == "closed"
    assert case["investigation_id"] is None and case["alert_id"] is None
    assert case["reason"] == "Automatic containment is not permitted."


# ---- filters ---------------------------------------------------------------

def test_filters():
    h = Harness()

    assert ids(h.get("/api/v1/cases?status=investigating")) == ["CASE-2"]
    assert ids(h.get("/api/v1/cases?status=closed")) == ["CASE-4"]
    assert ids(h.get("/api/v1/cases?incident_id=INC-A")) == ["CASE-2", "CASE-1"]
    assert ids(h.get("/api/v1/cases?assigned_analyst=analyst-7")) == ["CASE-1"]
    assert ids(h.get("/api/v1/cases?assigned_analyst=nobody")) == []
    assert ids(h.get("/api/v1/cases?alert_id=ALT-2")) == ["CASE-2"]
    assert ids(h.get("/api/v1/cases?q=analyst%20summary")) == ["CASE-1"]
    assert ids(h.get("/api/v1/cases?q=WEB-01")) == ["CASE-1"]
    assert ids(h.get("/api/v1/cases?q=CASE-3")) == ["CASE-3"]
    assert ids(h.get("/api/v1/cases?q=nothing-matches")) == []
    assert ids(h.get("/api/v1/cases?status=closed&incident_id=INC-B")) == []


def test_total_respects_filters():
    assert Harness().get("/api/v1/cases?incident_id=INC-A").json()["total"] == 2


# ---- paging ----------------------------------------------------------------

def test_cursor_pages_cover_every_case_once():
    h = Harness()
    first = h.get("/api/v1/cases?limit=3").json()

    assert [i["case_id"] for i in first["items"]] == ["CASE-4", "CASE-3", "CASE-2"]
    assert first["total"] == 4 and first["next_cursor"]

    second = h.get("/api/v1/cases?limit=3&cursor=" + first["next_cursor"]).json()
    assert [i["case_id"] for i in second["items"]] == ["CASE-1"]
    assert second["next_cursor"] is None


def test_bad_cursor_is_400():
    response = Harness().get("/api/v1/cases?cursor=nope")

    assert response.status_code == 400 and "detail" in response.json()


@pytest.mark.parametrize("qs", ["?status=bogus", "?limit=0", "?limit=201", "?limit=abc"])
def test_invalid_query_is_422(qs):
    assert Harness().get("/api/v1/cases" + qs).status_code == 422


# ---- get by id -------------------------------------------------------------

def test_unknown_case_is_404_with_detail():
    response = Harness().get("/api/v1/cases/CASE-99")

    assert response.status_code == 404
    assert response.json() == {"detail": "Case CASE-99 was not found."}


def test_detail_matches_list_item():
    h = Harness()
    listed = {i["case_id"]: i for i in h.get("/api/v1/cases").json()["items"]}

    assert h.get("/api/v1/cases/CASE-1").json() == listed["CASE-1"]


# ---- legacy cases are not exposed -----------------------------------------

def test_legacy_cases_table_is_not_listed():
    from app.services.cases.case_service import create_case_record

    h = Harness(with_data=False)
    legacy = h.investigation_store
    investigation = seed(legacy).get("ALT-1")
    legacy.save_case(create_case_record(investigation))

    assert h.get("/api/v1/cases").json()["total"] == 0


# ---- auth ------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/v1/cases", "/api/v1/cases/CASE-1"])
def test_requires_authentication(path):
    assert Harness(authenticated=False).get(path).status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/cases", "/api/v1/cases/CASE-1"])
def test_rejects_invalid_token(path):
    h = Harness(authenticated=False)

    response = h.client.get(path, headers={"Authorization": "Bearer aso_invalid"})

    assert response.status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/cases", "/api/v1/cases/CASE-1"])
def test_requires_read_permission(path):
    assert Harness(can_read=False).get(path).status_code == 403


class SessionStore:
    def __init__(self, role, can_read):
        self.principal = BrowserPrincipal(
            "u-1", "u@example.test", "User", role, can_read, False, "csrf")

    def resolve_session(self, session):
        return self.principal if session == "good" else None


@pytest.mark.parametrize("role", ["Analyst", "Administrator"])
def test_browser_session_of_either_role_can_read(role):
    h = Harness()
    app = create_app(
        investigation_graph=UnusedGraph(), investigation_store=h.investigation_store,
        audit_store=InMemoryAuditStore(), incident_response_store=h.response_store,
        case_workflow_store=h.workflow_store, browser_auth_store=SessionStore(role, True),
        autonomous_response_enabled=False,
    )
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, "good")

    response = client.get("/api/v1/cases")

    assert response.status_code == 200 and response.json()["total"] == 4


def test_browser_session_without_read_flag_is_403():
    h = Harness()
    app = create_app(
        investigation_graph=UnusedGraph(), investigation_store=h.investigation_store,
        audit_store=InMemoryAuditStore(), incident_response_store=h.response_store,
        case_workflow_store=h.workflow_store, browser_auth_store=SessionStore("Analyst", False),
        autonomous_response_enabled=False,
    )
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, "good")

    assert client.get("/api/v1/cases").status_code == 403


# ---- schema not ready, read-only ------------------------------------------

class UnmigratedWorkflowStore(InMemoryCaseWorkflowStore):
    """Seeds like the in-memory store, then behaves like Postgres before migration 0004."""

    armed = False

    def _guard(self):
        if self.armed:
            raise CaseWorkflowSchemaNotReady("migrate")

    def get_workflow(self, case_id):
        self._guard()
        return super().get_workflow(case_id)

    def list_actions(self, case_id):
        self._guard()
        return super().list_actions(case_id)

    def list_notes(self, case_id):
        self._guard()
        return super().list_notes(case_id)


@pytest.mark.parametrize("path", ["/api/v1/cases", "/api/v1/cases/CASE-1"])
def test_unmigrated_workflow_tables_give_503(path):
    workflow_store = UnmigratedWorkflowStore()
    h = Harness(workflow_store=workflow_store)
    workflow_store.armed = True

    response = h.get(path)

    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", ["/api/v1/cases", "/api/v1/cases/CASE-1"])
def test_case_routes_are_read_only(method, path):
    h = Harness()

    assert h.client.request(method, path, json={}).status_code in (405,)


def test_reads_do_not_write_workflow_state():
    h = Harness()
    before = (h.workflow_store.get_workflow("CASE-1"), h.workflow_store.get_workflow("CASE-2"),
              h.workflow_store.list_notes("CASE-2"))

    h.get("/api/v1/cases")
    h.get("/api/v1/cases/CASE-2")

    after = (h.workflow_store.get_workflow("CASE-1"), h.workflow_store.get_workflow("CASE-2"),
             h.workflow_store.list_notes("CASE-2"))
    assert before == after
    assert h.workflow_store.get_workflow("CASE-2") is None
