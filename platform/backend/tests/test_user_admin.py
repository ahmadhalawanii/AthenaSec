"""User administration routes: create, edit, suspend/reactivate, delete, reset password.

Administrator + CSRF only; every change audited; the signed-in admin cannot lock
themselves out, and AthenaSec always keeps one active administrator.
"""

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import UserRecord
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.audit.operator_audit_store import InMemoryOperatorAuditStore
from app.services.auth.web_auth import (
    SESSION_COOKIE_NAME,
    BrowserPrincipal,
    InvalidCredentials,
    UserConflict,
)
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore

CSRF = {"X-AthenaSec-CSRF": "csrf-admin"}
T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


class FakeAccounts:
    """The administration API of PostgresBrowserAuthStore, in memory."""

    def __init__(self):
        self.users = {
            "admin-1": self._user("admin-1", "admin@x.test", "Admin One", "Administrator"),
            "analyst-1": self._user("analyst-1", "analyst@x.test", "Ana Lyst", "Analyst"),
        }
        self.passwords = {}
        self.principals = {
            "admin": BrowserPrincipal("admin-1", "admin@x.test", "Admin One", "Administrator",
                                      True, True, "csrf-admin"),
            "analyst": BrowserPrincipal("analyst-1", "analyst@x.test", "Ana Lyst", "Analyst",
                                        True, True, "csrf-analyst"),
        }

    @staticmethod
    def _user(user_id, email, name, role, active=True, department="", phone=""):
        return UserRecord(user_id=user_id, email=email, name=name, role=role, active=active,
                          department=department, phone=phone, can_read_approvals=True,
                          can_decide_approvals=True, created_at=T0)

    def resolve_session(self, session):
        return self.principals.get(session)

    def _unique(self, email, user_id=None):
        if any(u.email == email.casefold() and u.user_id != user_id for u in self.users.values()):
            raise UserConflict("Another account already uses this email address.")

    def list_users(self, *, role=None, active=None, q=None):
        return [u for u in self.users.values()
                if (role is None or u.role == role) and (active is None or u.active == active)]

    def get_user(self, user_id):
        return self.users.get(user_id)

    def create_user(self, *, name, email, role, department="", phone=""):
        self._unique(email)
        user_id = f"USR-{len(self.users):04d}"
        self.users[user_id] = self._user(user_id, email.casefold(), name, role,
                                         department=department, phone=phone)
        self.passwords[user_id] = "TempPassword-123456"
        return self.users[user_id], "TempPassword-123456", "otpauth://totp/AthenaSec:x?secret=ABC"

    def update_user(self, user_id, *, name, email, role, department, phone):
        if user_id not in self.users:
            return None
        self._unique(email, user_id)
        self.users[user_id] = self.users[user_id].model_copy(update={
            "name": name, "email": email.casefold(), "role": role,
            "department": department, "phone": phone})
        return self.users[user_id]

    def disable_user(self, user_id):
        self.users[user_id] = self.users[user_id].model_copy(update={"active": False})

    def enable_user(self, user_id):
        self.users[user_id] = self.users[user_id].model_copy(update={"active": True})

    def delete_user(self, user_id):
        return self.users.pop(user_id, None) is not None

    def reset_password(self, user_id):
        self.passwords[user_id] = "NewTempPassword-99"
        return "NewTempPassword-99"

    def reset_mfa(self, user_id):
        return None if user_id not in self.users else "otpauth://totp/AthenaSec:x?secret=NEWKEY&issuer=AthenaSec"


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("not used")


class Harness:
    def __init__(self, session="admin", accounts=None):
        self.accounts = accounts or FakeAccounts()
        self.audit = InMemoryOperatorAuditStore()
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            operator_audit_store=self.audit,
            browser_auth_store=self.accounts,
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)
        if session:
            self.client.cookies.set(SESSION_COOKIE_NAME, session)

    def events(self, event_type):
        return self.audit.list_events(event_type=event_type)


NEW = {"name": "New Person", "email": "New@X.test", "role": "Analyst",
       "department": "SOC", "phone": "+971 50 000 0000"}


def test_create_returns_credentials_once_and_audits():
    h = Harness()

    response = h.client.post("/api/v1/users", json=NEW, headers=CSRF)

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "new@x.test" and body["user"]["department"] == "SOC"
    assert body["temporary_password"] and body["totp_uri"].startswith("otpauth://")
    assert response.headers["Cache-Control"] == "no-store"
    event = h.events("user_created")[0]
    assert event.target == body["user"]["user_id"]
    assert "TempPassword" not in str(event.detail)


def test_duplicate_email_is_409_and_bad_role_is_422():
    h = Harness()

    assert h.client.post("/api/v1/users", json={**NEW, "email": "analyst@x.test"},
                         headers=CSRF).status_code == 409
    assert h.client.post("/api/v1/users", json={**NEW, "role": "Root"}, headers=CSRF).status_code == 422


def test_edit_records_what_changed():
    h = Harness()

    response = h.client.put("/api/v1/users/analyst-1", headers=CSRF, json={
        "name": "Ana Lyst", "email": "analyst@x.test", "role": "Analyst",
        "department": "Threat Intel", "phone": ""})

    assert response.status_code == 200 and response.json()["department"] == "Threat Intel"
    assert h.events("user_updated")[0].detail == {"department": {"from": "", "to": "Threat Intel"}}


def test_admin_cannot_change_own_role_or_suspend_or_delete_self():
    h = Harness()
    me = {"name": "Admin One", "email": "admin@x.test", "role": "Analyst", "department": "", "phone": ""}

    assert h.client.put("/api/v1/users/admin-1", json=me, headers=CSRF).status_code == 409
    assert h.client.post("/api/v1/users/admin-1/status", json={"active": False},
                         headers=CSRF).status_code == 409
    assert h.client.delete("/api/v1/users/admin-1", headers=CSRF).status_code == 409


def test_last_active_administrator_is_kept():
    # admin-1 is the only active administrator; admin-2 (suspended) acts on them
    accounts = FakeAccounts()
    accounts.users["admin-2"] = accounts._user("admin-2", "two@x.test", "Admin Two",
                                               "Administrator", active=False)
    accounts.principals["admin2"] = BrowserPrincipal("admin-2", "two@x.test", "Admin Two",
                                                    "Administrator", True, True, "csrf-admin")
    h = Harness(session="admin2", accounts=accounts)
    demote = {"name": "Admin One", "email": "admin@x.test", "role": "Analyst",
              "department": "", "phone": ""}

    assert h.client.delete("/api/v1/users/admin-1", headers=CSRF).status_code == 409
    assert h.client.post("/api/v1/users/admin-1/status", json={"active": False},
                         headers=CSRF).status_code == 409
    assert h.client.put("/api/v1/users/admin-1", json=demote, headers=CSRF).status_code == 409
    assert accounts.users["admin-1"].active and accounts.users["admin-1"].role == "Administrator"


def test_suspend_and_reactivate():
    h = Harness()

    off = h.client.post("/api/v1/users/analyst-1/status", json={"active": False}, headers=CSRF)
    on = h.client.post("/api/v1/users/analyst-1/status", json={"active": True}, headers=CSRF)

    assert off.json()["active"] is False and on.json()["active"] is True
    assert len(h.events("user_disabled")) == 1 and len(h.events("user_enabled")) == 1


def test_delete_user():
    h = Harness()

    assert h.client.delete("/api/v1/users/analyst-1", headers=CSRF).status_code == 204
    assert "analyst-1" not in h.accounts.users
    assert h.client.delete("/api/v1/users/analyst-1", headers=CSRF).status_code == 404
    assert len(h.events("user_deleted")) == 1


def test_reset_password_returns_a_new_temporary_password():
    h = Harness()

    response = h.client.post("/api/v1/users/analyst-1/reset-password", headers=CSRF)

    assert response.status_code == 200
    assert response.json()["temporary_password"] == "NewTempPassword-99"
    assert response.json()["totp_uri"] is None
    assert len(h.events("user_password_reset")) == 1


def test_only_administrators_with_csrf():
    assert Harness("analyst").client.post(
        "/api/v1/users", json=NEW, headers={"X-AthenaSec-CSRF": "csrf-analyst"}).status_code == 403
    assert Harness().client.post("/api/v1/users", json=NEW).status_code == 403
    assert Harness(session=None).client.post("/api/v1/users", json=NEW, headers=CSRF).status_code == 401


# ---- the real store, against an isolated PostgreSQL database -----------------

@pytest.mark.skipif(not os.getenv("ATHENASEC_TEST_PG_URL"), reason="ATHENASEC_TEST_PG_URL is not configured")
def test_postgres_store_administration_round_trip():
    from app.services.auth.web_auth import PostgresBrowserAuthStore

    store = PostgresBrowserAuthStore(os.environ["ATHENASEC_TEST_PG_URL"], bytes.fromhex("b2" * 32))
    suffix = uuid4().hex[:8]
    user, password, uri = store.create_user(name="Round Trip", email=f"rt-{suffix}@x.test",
                                            role="Analyst", department="SOC", phone="1")

    assert user.department == "SOC" and len(password) >= 14 and uri.startswith("otpauth://")
    store.begin_login(user.email, password)  # the temporary password works

    with pytest.raises(UserConflict):
        store.create_user(name="Dup", email=user.email, role="Analyst")

    updated = store.update_user(user.user_id, name="Renamed", email=user.email, role="Administrator",
                                department="IR", phone="2")
    assert (updated.name, updated.role, updated.department) == ("Renamed", "Administrator", "IR")

    new_password = store.reset_password(user.user_id)
    with pytest.raises(InvalidCredentials):
        store.begin_login(user.email, password)
    store.begin_login(user.email, new_password)

    store.disable_user(user.user_id)
    assert store.get_user(user.user_id).active is False
    store.enable_user(user.user_id)
    assert store.get_user(user.user_id).active is True

    assert store.delete_user(user.user_id) is True
    assert store.get_user(user.user_id) is None
    assert store.reset_password(user.user_id) is None


# ---- two-factor reset and the temporary-password lock ------------------------

def test_admin_resets_someones_two_factor():
    h = Harness()

    response = h.client.post("/api/v1/users/analyst-1/reset-mfa", headers=CSRF)

    assert response.status_code == 200
    assert "secret=NEWKEY" in response.json()["totp_uri"]
    assert h.events("user_mfa_reset")[0].target == "analyst-1"
    assert h.client.post("/api/v1/users/nobody/reset-mfa", headers=CSRF).status_code == 404
    assert Harness("analyst").client.post("/api/v1/users/admin-1/reset-mfa",
                                          headers={"X-AthenaSec-CSRF": "csrf-analyst"}).status_code == 403


def test_temporary_password_allows_only_changing_it():
    accounts = FakeAccounts()
    accounts.principals["temp"] = BrowserPrincipal("analyst-1", "analyst@x.test", "Ana Lyst", "Analyst",
                                                  True, True, "csrf-temp", must_change_password=True)
    h = Harness(session="temp", accounts=accounts)

    me = h.client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["must_change_password"] is True
    assert h.client.get("/api/v1/alerts").status_code == 403
    assert h.client.get("/api/v1/me/settings").status_code == 403
    assert "new password" in h.client.get("/api/v1/me/profile").json()["detail"]


def test_signed_in_users_report_no_password_change_needed():
    assert Harness().client.get("/api/v1/auth/me").json()["must_change_password"] is False


@pytest.mark.skipif(not os.getenv("ATHENASEC_TEST_PG_URL"), reason="ATHENASEC_TEST_PG_URL is not configured")
def test_postgres_temporary_password_and_two_factor_reset():
    import time
    from urllib.parse import parse_qs, urlparse
    import base64
    from app.services.auth.web_auth import PostgresBrowserAuthStore, _totp

    def secret_of(uri):
        encoded = parse_qs(urlparse(uri).query)["secret"][0]
        return base64.b32decode(encoded + "=" * (-len(encoded) % 8))

    store = PostgresBrowserAuthStore(os.environ["ATHENASEC_TEST_PG_URL"], bytes.fromhex("b2" * 32))
    user, password, uri = store.create_user(name="Temp", email=f"tmp-{uuid4().hex[:8]}@x.test", role="Analyst")
    counter = int(time.time() // 30)

    session, principal = store.complete_mfa(store.begin_login(user.email, password), _totp(secret_of(uri), counter))
    assert principal.must_change_password is True
    assert store.resolve_session(session).must_change_password is True

    store.change_password(user.user_id, password, "MyOwnPassword-12345")
    assert store.resolve_session(session).must_change_password is False

    new_uri = store.reset_mfa(user.user_id)
    assert secret_of(new_uri) != secret_of(uri)
    assert store.resolve_session(session) is None  # signed out everywhere
    with pytest.raises(InvalidCredentials):
        store.complete_mfa(store.begin_login(user.email, "MyOwnPassword-12345"), _totp(secret_of(uri), counter + 1))
    _, again = store.complete_mfa(store.begin_login(user.email, "MyOwnPassword-12345"),
                                  _totp(secret_of(new_uri), counter + 1))
    assert again.user_id == user.user_id and again.must_change_password is False

    store.reset_password(user.user_id)
    assert store.get_user(user.user_id) is not None
    store.delete_user(user.user_id)
