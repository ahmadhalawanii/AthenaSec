"""Users directory reads: GET /api/v1/users and /api/v1/users/{user_id}.

All records are built here; the app ships no users.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import UserRecord
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.web_auth import (
    SESSION_COOKIE_NAME,
    BrowserPrincipal,
    UsersSchemaNotReady,
)

BASE = datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("No investigation required")


def make_user(index, **overrides):
    fields = dict(
        user_id=f"user-{index:02d}",
        email=f"person{index:02d}@example.test",
        name=f"Person {index:02d}",
        role="Analyst",
        department="Security Operations",
        phone="+61 400 000 000",
        active=True,
        can_read_approvals=True,
        can_decide_approvals=False,
        created_at=BASE + timedelta(days=index),
        last_login_at=BASE + timedelta(days=index, hours=2),
    )
    fields.update(overrides)
    return UserRecord(**fields)


class FakeUserDirectoryStore:
    """Mirrors PostgresBrowserAuthStore's read API with in-test records."""

    def __init__(self, users=(), schema_ready=True):
        self.users = list(users)
        self.schema_ready = schema_ready
        self.principals = {
            "admin-session": BrowserPrincipal(
                "admin-1", "admin@example.test", "Admin", "Administrator",
                True, True, "csrf-admin",
            ),
            "analyst-session": BrowserPrincipal(
                "analyst-1", "analyst@example.test", "Analyst", "Analyst",
                True, False, "csrf-analyst",
            ),
        }

    def resolve_session(self, session):
        return self.principals.get(session)

    def list_users(self, *, role=None, active=None, q=None):
        if not self.schema_ready:
            raise UsersSchemaNotReady("migrate")
        users = [
            u for u in self.users
            if (role is None or u.role == role)
            and (active is None or u.active == active)
            and (not q or q.casefold() in u.email.casefold()
                 or q.casefold() in u.name.casefold())
        ]
        users.sort(key=lambda u: (u.created_at, u.user_id), reverse=True)
        return users

    def get_user(self, user_id):
        if not self.schema_ready:
            raise UsersSchemaNotReady("migrate")
        return next((u for u in self.users if u.user_id == user_id), None)


def make_client(store, session="admin-session"):
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=InMemoryInvestigationStore(),
        audit_store=InMemoryAuditStore(),
        incident_response_store=InMemoryIncidentResponseStore(),
        browser_auth_store=store,
        autonomous_response_enabled=False,
        operator_control_key="test-operator-key",
    )
    client = TestClient(app)
    if session is not None:
        client.cookies.set(SESSION_COOKIE_NAME, session)
    return client


USER_FIELDS = {
    "user_id", "email", "name", "role", "department", "phone", "active",
    "mfa_enabled", "can_read_approvals", "can_decide_approvals",
    "created_at", "last_login_at",
}


# ---- empty state -----------------------------------------------------------

def test_list_users_empty_state():
    response = make_client(FakeUserDirectoryStore()).get("/api/v1/users")

    assert response.status_code == 200
    assert response.json() == {"total": 0, "items": [], "next_cursor": None}


# ---- shape -----------------------------------------------------------------

def test_list_users_shape_and_no_secrets():
    store = FakeUserDirectoryStore([make_user(1)])

    response = make_client(store).get("/api/v1/users")

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert set(body["items"][0]) == USER_FIELDS
    assert body["items"][0]["mfa_enabled"] is True
    assert response.headers["cache-control"] == "no-store"

    text = response.text.lower()
    for secret in ("password", "salt", "digest", "totp", "secret", "failures"):
        assert secret not in text


def test_get_user_by_id():
    store = FakeUserDirectoryStore([make_user(1), make_user(2)])

    response = make_client(store).get("/api/v1/users/user-02")

    assert response.status_code == 200
    assert set(response.json()) == USER_FIELDS
    assert response.json()["user_id"] == "user-02"


def test_user_with_missing_dates_serialises_nulls():
    store = FakeUserDirectoryStore(
        [make_user(1, created_at=None, last_login_at=None)]
    )

    item = make_client(store).get("/api/v1/users/user-01").json()

    assert item["created_at"] is None
    assert item["last_login_at"] is None


# ---- filters and paging ----------------------------------------------------

def test_filters_role_active_and_search():
    store = FakeUserDirectoryStore([
        make_user(1, role="Administrator"),
        make_user(2, active=False),
        make_user(3, name="Zed Zimmer"),
    ])
    client = make_client(store)

    def ids(query):
        return [u["user_id"] for u in client.get("/api/v1/users" + query).json()["items"]]

    assert ids("?role=Administrator") == ["user-01"]
    assert ids("?active=false") == ["user-02"]
    assert ids("?active=true&role=Analyst") == ["user-03"]
    assert ids("?q=zimmer") == ["user-03"]
    assert client.get("/api/v1/users?q=nobody").json()["total"] == 0


def test_pagination_newest_first_and_cursor_walks_all_pages():
    store = FakeUserDirectoryStore([make_user(i) for i in range(1, 6)])
    client = make_client(store)

    first = client.get("/api/v1/users?limit=2").json()
    assert first["total"] == 5
    assert [u["user_id"] for u in first["items"]] == ["user-05", "user-04"]
    assert first["next_cursor"]

    second = client.get(f"/api/v1/users?limit=2&cursor={first['next_cursor']}").json()
    assert [u["user_id"] for u in second["items"]] == ["user-03", "user-02"]

    third = client.get(f"/api/v1/users?limit=2&cursor={second['next_cursor']}").json()
    assert [u["user_id"] for u in third["items"]] == ["user-01"]
    assert third["next_cursor"] is None


def test_bad_cursor_is_400():
    response = make_client(FakeUserDirectoryStore([make_user(1)])).get(
        "/api/v1/users?cursor=not-a-cursor"
    )

    assert response.status_code == 400
    assert "detail" in response.json()


# ---- 404 and 422 -----------------------------------------------------------

def test_unknown_user_is_404_with_detail():
    response = make_client(FakeUserDirectoryStore()).get("/api/v1/users/user-99")

    assert response.status_code == 404
    assert response.json() == {"detail": "User user-99 was not found."}


@pytest.mark.parametrize(
    "query",
    ["?role=Owner", "?active=maybe", "?limit=0", "?limit=201", "?limit=abc"],
)
def test_invalid_query_is_422(query):
    response = make_client(FakeUserDirectoryStore()).get("/api/v1/users" + query)

    assert response.status_code == 422


# ---- auth ------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/v1/users", "/api/v1/users/user-01"])
def test_no_session_is_401(path):
    store = FakeUserDirectoryStore([make_user(1)])

    assert make_client(store, session=None).get(path).status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/users", "/api/v1/users/user-01"])
def test_invalid_session_is_401(path):
    store = FakeUserDirectoryStore([make_user(1)])

    assert make_client(store, session="forged").get(path).status_code == 401


@pytest.mark.parametrize("path", ["/api/v1/users", "/api/v1/users/user-01"])
def test_analyst_is_403(path):
    store = FakeUserDirectoryStore([make_user(1)])

    response = make_client(store, session="analyst-session").get(path)

    assert response.status_code == 403
    assert response.json() == {"detail": "Administrator permission required."}


def test_bearer_token_cannot_read_users():
    store = FakeUserDirectoryStore([make_user(1)])
    client = make_client(store, session=None)

    response = client.get(
        "/api/v1/users", headers={"Authorization": "Bearer some-operator-token"}
    )

    assert response.status_code == 401


def test_no_browser_auth_store_is_503(monkeypatch):
    monkeypatch.setenv("ATHENASEC_PERSISTENCE_BACKEND", "sqlite")
    client = make_client(None)
    client.cookies.set(SESSION_COOKIE_NAME, "anything")

    response = client.get("/api/v1/users")

    assert response.status_code == 503


def test_store_without_directory_support_is_503():
    class AuthOnlyStore:
        def resolve_session(self, session):
            return FakeUserDirectoryStore().principals["admin-session"]

    response = make_client(AuthOnlyStore()).get("/api/v1/users")

    assert response.status_code == 503
    assert response.json() == {"detail": "User directory unavailable."}


def test_unmigrated_schema_is_503_with_instruction():
    store = FakeUserDirectoryStore([make_user(1)], schema_ready=False)
    client = make_client(store)

    for path in ("/api/v1/users", "/api/v1/users/user-01"):
        response = client.get(path)
        assert response.status_code == 503
        assert "alembic upgrade head" in response.json()["detail"]


# ---- writes ----------------------------------------------------------------
# Creating, editing and deleting users is covered by test_user_admin.py. The
# collection itself only accepts POST (create).

@pytest.mark.parametrize("method", ["put", "patch", "delete"])
def test_users_collection_only_accepts_create(method):
    client = make_client(FakeUserDirectoryStore([make_user(1)]))
    client.headers["X-AthenaSec-CSRF"] = "csrf-admin"

    response = client.request(method.upper(), "/api/v1/users", json={})

    assert response.status_code == 405
