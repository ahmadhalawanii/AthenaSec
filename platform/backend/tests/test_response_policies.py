"""GET /api/v1/policies, /policies/versions and PUT /api/v1/policies.

The policy document is stored, versioned and shown, but the agent never reads it, so every
response carries enforced=false. All data is built here; the app ships none.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.audit.operator_audit_store import (
    InMemoryOperatorAuditStore,
    OperatorAuditSchemaNotReady,
)
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.policy.response_policy_store import (
    InMemoryResponsePolicyStore,
    PolicySchemaNotReady,
)
from app.services.execution.target_protection import StaticTargetProtectionRegistry
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal

CSRF = {"X-AthenaSec-CSRF": "csrf-admin"}


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by policy tests.")


class SessionStore:
    def __init__(self):
        self.principals = {
            "admin": BrowserPrincipal("admin-1", "a@example.test", "Admin", "Administrator",
                                      True, True, "csrf-admin"),
            "analyst": BrowserPrincipal("analyst-1", "n@example.test", "Analyst", "Analyst",
                                        True, False, "csrf-analyst"),
        }

    def resolve_session(self, session):
        return self.principals.get(session)


class Harness:
    def __init__(self, *, auth="admin", can_read=True, policy_store=None, audit_store=None,
                 registry=None):
        self.policy_store = policy_store or InMemoryResponsePolicyStore()
        self.audit = audit_store or InMemoryOperatorAuditStore()
        identity = InMemoryOperatorIdentityStore()
        kwargs = {}
        if registry is not None:
            kwargs["target_protection_registry"] = registry
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            response_policy_store=self.policy_store,
            operator_audit_store=self.audit,
            browser_auth_store=SessionStore(),
            operator_identity_store=identity,
            autonomous_response_enabled=False,
            **kwargs,
        )
        self.client = TestClient(app)

        if auth == "bearer":
            token = identity.provision(operator_id="analyst-001", can_read=can_read)
            self.client.headers["Authorization"] = "Bearer " + token
        elif auth in ("admin", "analyst"):
            self.client.cookies.set(SESSION_COOKIE_NAME, auth)

    def get(self, path="/api/v1/policies"):
        return self.client.get(path)

    def put(self, body, headers=CSRF):
        return self.client.put("/api/v1/policies", json=body, headers=headers)


def body(base=0, white=(), black=(), reason="initial policy"):
    return {"base_version": base, "whitelist": list(white), "blacklist": list(black),
            "reason": reason}


def ip(value, note=""):
    return {"value": value, "type": "ip", "note": note}


DOCUMENT_FIELDS = {"version", "whitelist", "blacklist", "protected_targets", "enforced",
                   "enforcement_note", "created_at", "created_by", "reason"}


# ---- empty state -----------------------------------------------------------

def test_get_before_any_save_is_an_empty_unenforced_document():
    response = Harness().get()

    assert response.status_code == 200
    doc = response.json()
    assert set(doc) == DOCUMENT_FIELDS
    assert doc["version"] == 0
    assert doc["whitelist"] == [] and doc["blacklist"] == [] and doc["protected_targets"] == []
    assert doc["enforced"] is False
    assert "agent does not read" in doc["enforcement_note"]
    assert doc["created_at"] is None and doc["created_by"] is None and doc["reason"] is None


def test_versions_before_any_save_is_empty_and_unknown_version_is_404():
    h = Harness()

    assert h.get("/api/v1/policies/versions").json() == {
        "total": 0, "items": [], "next_cursor": None}
    response = h.get("/api/v1/policies/versions/1")
    assert response.status_code == 404
    assert response.json() == {"detail": "Policy version 1 was not found."}


# ---- save and read back ----------------------------------------------------

def test_put_saves_version_one_and_get_returns_it_unenforced():
    h = Harness()

    saved = h.put(body(white=[ip("10.0.0.1", "scanner")], reason="first"))

    assert saved.status_code == 200
    doc = saved.json()
    assert set(doc) == DOCUMENT_FIELDS
    assert doc["version"] == 1 and doc["enforced"] is False
    assert doc["created_by"] == "admin-1" and doc["reason"] == "first"
    assert doc["whitelist"] == [{"value": "10.0.0.1", "type": "ip", "note": "scanner"}]
    assert h.get().json() == doc


def test_each_save_is_a_new_version_and_history_is_kept():
    h = Harness()
    h.put(body(0, white=[ip("10.0.0.1")], reason="one"))
    h.put(body(1, white=[ip("10.0.0.2")], black=[{"value": "Evil.Example.COM", "type": "hostname"}],
              reason="two"))

    assert h.get().json()["version"] == 2
    assert [e["value"] for e in h.get("/api/v1/policies/versions/1").json()["whitelist"]] == ["10.0.0.1"]
    assert h.get("/api/v1/policies/versions/2").json()["blacklist"][0]["value"] == "evil.example.com"

    listing = h.get("/api/v1/policies/versions").json()
    assert listing["total"] == 2
    assert [v["version"] for v in listing["items"]] == [2, 1]
    assert listing["items"][0] == {
        "version": 2, "created_at": listing["items"][0]["created_at"], "created_by": "admin-1",
        "reason": "two", "whitelist_count": 1, "blacklist_count": 1, "enforced": False}


def test_versions_paginate():
    h = Harness()
    for base in range(3):
        h.put(body(base, reason=f"r{base}"))

    first = h.get("/api/v1/policies/versions?limit=2").json()
    second = h.get("/api/v1/policies/versions?limit=2&cursor=" + first["next_cursor"]).json()

    assert [v["version"] for v in first["items"]] == [3, 2]
    assert [v["version"] for v in second["items"]] == [1] and second["next_cursor"] is None
    assert h.get("/api/v1/policies/versions?cursor=nope").status_code == 400


def test_entries_are_normalised():
    h = Harness()

    doc = h.put(body(white=[
        {"value": " 2001:0DB8:0:0:0:0:0:1 ", "type": "ip"},
        {"value": "10.1.2.0/24", "type": "cidr"},
        {"value": "Host.Example.Com.", "type": "hostname"},
        {"value": " svc-backup ", "type": "account"},
    ])).json()

    assert [e["value"] for e in doc["whitelist"]] == [
        "2001:db8::1", "10.1.2.0/24", "host.example.com", "svc-backup"]
    assert all(e["note"] == "" for e in doc["whitelist"])


def test_empty_lists_are_a_valid_policy():
    doc = Harness().put(body()).json()

    assert doc["version"] == 1 and doc["whitelist"] == [] and doc["blacklist"] == []


# ---- stale version: 409 ----------------------------------------------------

@pytest.mark.parametrize("stale", [0, 2, 9])
def test_stale_or_wrong_base_version_is_409_and_nothing_is_saved(stale):
    h = Harness()
    h.put(body(0, white=[ip("10.0.0.1")]))

    response = h.put(body(stale, white=[ip("10.0.0.9")]))

    assert response.status_code == 409
    assert response.json() == {
        "detail": f"Policy version is stale: the latest version is 1, base_version was {stale}."}
    assert h.get().json()["version"] == 1
    assert [e["value"] for e in h.get().json()["whitelist"]] == ["10.0.0.1"]


def test_first_save_with_nonzero_base_is_409():
    h = Harness()

    assert h.put(body(3)).status_code == 409
    assert h.get().json()["version"] == 0


def test_two_editors_with_the_same_base_cannot_both_save():
    h = Harness()

    assert h.put(body(0, reason="editor A")).status_code == 200
    assert h.put(body(0, reason="editor B")).status_code == 409
    assert h.get().json()["reason"] == "editor A"


# ---- invalid policy: 422 ---------------------------------------------------

INVALID = {
    "bad ip": body(white=[ip("999.1.1.1")]),
    "ip with prefix": body(white=[ip("10.0.0.1/24")]),
    "cidr with host bits": body(white=[{"value": "10.0.0.5/24", "type": "cidr"}]),
    "cidr whole space": body(black=[{"value": "0.0.0.0/0", "type": "cidr"}]),
    "bad cidr": body(white=[{"value": "10.0.0.0/33", "type": "cidr"}]),
    "bad hostname": body(white=[{"value": "bad_host!.example", "type": "hostname"}]),
    "hostname label too long": body(white=[{"value": "a" * 64 + ".example", "type": "hostname"}]),
    "account with space": body(white=[{"value": "two words", "type": "account"}]),
    "empty value": body(white=[{"value": "", "type": "ip"}]),
    "blank value": body(white=[{"value": "   ", "type": "account"}]),
    "unknown type": body(white=[{"value": "x", "type": "isolate_host"}]),
    "note too long": body(white=[ip("10.0.0.1", "n" * 501)]),
    "duplicate in whitelist": body(white=[ip("10.0.0.1"), ip("10.0.0.1")]),
    "duplicate after normalising": body(black=[{"value": "A.example", "type": "hostname"},
                                               {"value": "a.example.", "type": "hostname"}]),
    "in both lists": body(white=[ip("10.0.0.1")], black=[ip("10.0.0.1")]),
    "empty reason": body(reason=""),
    "reason too long": body(reason="r" * 501),
    "negative base": body(base=-1),
    "too many entries": body(white=[ip(f"10.{i // 250}.{i % 250}.1") for i in range(1001)]),
    "missing whitelist": {"base_version": 0, "blacklist": [], "reason": "x"},
    "missing base_version": {"whitelist": [], "blacklist": [], "reason": "x"},
    "base not a number": {**body(), "base_version": "one"},
    "extra field enforced": {**body(), "enforced": True},
    "extra field protected_targets": {**body(), "protected_targets": []},
    "entry extra field": body(white=[{"value": "10.0.0.1", "type": "ip", "action": "block"}]),
    "not an object": ["list"],
}


@pytest.mark.parametrize("name", list(INVALID))
def test_invalid_policy_is_422_and_changes_nothing(name):
    h = Harness()
    h.put(body(0, white=[ip("10.0.0.1")]))

    response = h.put(INVALID[name])

    assert response.status_code == 422, name
    assert h.get().json()["version"] == 1
    assert len(h.audit.list_events()) == 1  # only the earlier successful save


def test_same_value_of_different_types_is_not_a_conflict():
    doc = Harness().put(body(white=[{"value": "svc", "type": "account"},
                                    {"value": "svc", "type": "hostname"}]))

    assert doc.status_code == 200


# ---- access ----------------------------------------------------------------

READ_PATHS = ["/api/v1/policies", "/api/v1/policies/versions", "/api/v1/policies/versions/1"]


@pytest.mark.parametrize("path", READ_PATHS)
def test_reads_need_credentials(path):
    assert Harness(auth=None).get(path).status_code == 401


@pytest.mark.parametrize("path", READ_PATHS)
def test_reads_need_the_read_permission(path):
    assert Harness(auth="bearer", can_read=False).get(path).status_code == 403


@pytest.mark.parametrize("auth", ["admin", "analyst", "bearer"])
def test_any_reader_can_read_the_policy(auth):
    h = Harness(auth=auth)

    assert h.get().status_code == 200
    assert h.get("/api/v1/policies/versions").status_code == 200


def test_put_without_credentials_is_401():
    assert Harness(auth=None).put(body()).status_code == 401


def test_put_with_a_bearer_token_is_401():
    assert Harness(auth="bearer").put(body()).status_code == 401


def test_put_by_an_analyst_is_403_even_with_their_own_csrf_token():
    h = Harness(auth="analyst")

    response = h.put(body(), headers={"X-AthenaSec-CSRF": "csrf-analyst"})

    assert response.status_code == 403
    assert response.json() == {"detail": "Administrator permission required."}
    assert h.get().json()["version"] == 0


@pytest.mark.parametrize("headers", [{}, {"X-AthenaSec-CSRF": "wrong"}])
def test_put_by_an_administrator_needs_the_csrf_token(headers):
    h = Harness()

    response = h.put(body(), headers=headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF token required."}
    assert h.get().json()["version"] == 0


def test_denied_writes_leave_no_audit_event():
    h = Harness(auth="analyst")

    h.put(body(), headers={"X-AthenaSec-CSRF": "csrf-analyst"})
    Harness(auth="admin").put(body(), headers={})

    assert h.audit.list_events() == []


def test_only_get_and_put_are_allowed():
    h = Harness()

    for method in ("POST", "PATCH", "DELETE"):
        assert h.client.request(method, "/api/v1/policies", json={}, headers=CSRF).status_code == 405
    for method in ("PUT", "POST", "DELETE"):
        assert h.client.request(method, "/api/v1/policies/versions", json={}, headers=CSRF).status_code == 405
    assert h.client.put("/api/v1/policies/versions/1", json={}, headers=CSRF).status_code == 405


@pytest.mark.parametrize("path", ["/api/v1/policies/versions/0", "/api/v1/policies/versions/abc",
                                  "/api/v1/policies/versions?limit=0"])
def test_invalid_version_path_or_limit_is_422(path):
    assert Harness().get(path).status_code == 422


# ---- audit -----------------------------------------------------------------

def test_a_save_is_recorded_in_the_operator_audit_log():
    h = Harness()

    h.put(body(0, white=[ip("10.0.0.1")], black=[ip("10.0.0.2")], reason="why"))

    (event,) = h.audit.list_events()
    assert (event.actor_id, event.actor_role, event.category) == ("admin-1", "Administrator", "policy")
    assert (event.action, event.target, event.result) == ("update", "policy-v1", "Success")
    assert event.detail == {"base_version": 0, "version": 1, "whitelist_count": 1,
                            "blacklist_count": 1, "reason": "why", "enforced": False}
    assert h.audit.verify_chain().valid


def test_a_stale_save_is_recorded_as_failed():
    h = Harness()
    h.put(body(0))
    h.put(body(0))

    failed = h.audit.list_events(result="Failed")

    assert len(failed) == 1
    assert failed[0].detail["error"] == "stale_version" and failed[0].detail["current_version"] == 1


def test_reads_write_no_audit_events():
    h = Harness()
    h.put(body())
    before = len(h.audit.list_events())

    h.get()
    h.get("/api/v1/policies/versions")
    h.get("/api/v1/policies/versions/1")

    assert len(h.audit.list_events()) == before


class UnmigratedAuditStore(InMemoryOperatorAuditStore):
    def append_event(self, **fields):
        raise OperatorAuditSchemaNotReady("migrate")


def test_unmigrated_audit_table_is_reported_honestly_after_the_policy_is_stored():
    h = Harness(audit_store=UnmigratedAuditStore())

    response = h.put(body(reason="stored anyway"))

    assert response.status_code == 503
    assert "policy change was stored" in response.json()["detail"]
    assert "alembic upgrade head" in response.json()["detail"]
    assert h.policy_store.get_current().reason == "stored anyway"


# ---- protected targets: read-only view of the agent's own state ------------

def test_protected_targets_come_from_target_protection_and_cannot_be_edited():
    registry = StaticTargetProtectionRegistry(
        protected_ips=("192.0.2.1",), protected_accounts=("root",),
        protected_endpoints=("dc-01",), allowlisted_ips=("192.0.2.99",))
    h = Harness(registry=registry)

    doc = h.get().json()

    assert doc["protected_targets"] == [
        {"value": "192.0.2.1/32", "type": "ip"},  # the agent stores IPs as CIDR
        {"value": "root", "type": "account"},
        {"value": "dc-01", "type": "endpoint"},
    ]
    saved = h.put(body(white=[ip("192.0.2.99")])).json()
    assert saved["protected_targets"] == doc["protected_targets"]
    assert registry.inspect(target_type="ip", target="192.0.2.1").protected_target is True


def test_saving_a_policy_does_not_change_what_the_agent_sees():
    registry = StaticTargetProtectionRegistry(protected_ips=("192.0.2.1",))
    h = Harness(registry=registry)

    h.put(body(white=[ip("192.0.2.1")], black=[ip("203.0.113.5")]))

    protected = registry.inspect(target_type="ip", target="192.0.2.1")
    other = registry.inspect(target_type="ip", target="203.0.113.5")
    assert protected.protected_target is True and protected.allowlisted_target is False
    assert other.protected_target is False and other.allowlisted_target is False


# ---- the agent never reads the stored policy -------------------------------

APP_DIR = Path(__file__).resolve().parents[1] / "app"
POLICY_STORAGE_NAMES = ("response_policy_store", "PolicyVersionRecord", "response_policy_versions",
                        "policy_document")
ALLOWED = {"main.py", "persistence_config.py", "response_policy_store.py", "policy_document.py",
           "schemas.py"}


def test_no_agent_module_reads_the_stored_policy():
    offenders = []

    for path in APP_DIR.rglob("*.py"):
        if path.name in ALLOWED:
            continue
        text = path.read_text(encoding="utf-8")
        if any(name in text for name in POLICY_STORAGE_NAMES):
            offenders.append(str(path.relative_to(APP_DIR)))

    assert offenders == []


def test_main_only_serves_the_stored_policy_through_the_policy_routes():
    text = (APP_DIR / "main.py").read_text(encoding="utf-8")
    lines = [i for i, line in enumerate(text.splitlines())
             if "configured_response_policy_store" in line]
    graph_or_risk = re.findall(
        r"(?:risk_engine|policy_engine|apply_structured_action_policy|persist_action_policy_lifecycle)"
        r"[^\n]*configured_response_policy_store", text)

    assert lines and graph_or_risk == []


def test_enforced_can_never_be_true_in_a_response():
    from app.schemas import PolicyDocument

    with pytest.raises(ValueError):
        PolicyDocument(enforced=True, enforcement_note="x")


# ---- schema not ready ------------------------------------------------------

class UnmigratedPolicyStore(InMemoryResponsePolicyStore):
    def _fail(self, *args, **kwargs):
        raise PolicySchemaNotReady("migrate")

    get_current = get_version = list_versions = append_version = _fail


@pytest.mark.parametrize("path", READ_PATHS)
def test_unmigrated_policy_table_gives_503_on_reads(path):
    response = Harness(policy_store=UnmigratedPolicyStore()).get(path)

    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


def test_unmigrated_policy_table_gives_503_on_put():
    h = Harness(policy_store=UnmigratedPolicyStore())

    assert h.put(body()).status_code == 503
    assert h.audit.list_events() == []
