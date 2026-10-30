"""PostgresBrowserAuthStore user directory methods against a recording connection."""

from datetime import datetime, timezone

import psycopg
import pytest

from app.services.auth import web_auth
from app.services.auth.web_auth import PostgresBrowserAuthStore, UsersSchemaNotReady

T1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T2 = datetime(2026, 2, 1, tzinfo=timezone.utc)


def row(user_id, name="Name", role="Analyst", active=True, created=T1, login=None,
        email=None):
    return (
        user_id, email or f"{user_id}@example.test", name, role, "", "", active,
        True, False, created, login,
    )


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class RecordingConnection:
    def __init__(self, log, rows, error):
        self.log, self.rows, self.error = log, rows, error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params=None):
        self.log.append((" ".join(str(statement).split()), params))
        if self.error is not None and "athenasec_web_users u" in str(statement):
            raise self.error
        return Result(self.rows)


@pytest.fixture
def make_store(monkeypatch):
    def build(rows=(), error=None):
        log = []
        monkeypatch.setattr(
            web_auth.psycopg, "connect",
            lambda *a, **k: RecordingConnection(log, list(rows), error),
        )
        store = PostgresBrowserAuthStore("postgresql://test/test", b"k" * 32)
        log.clear()
        return store, log

    return build


def test_list_users_maps_rows_and_orders_newest_first(make_store):
    store, _ = make_store([
        row("u-old", created=T1),
        row("u-new", created=T2, login=T2),
        row("u-undated", created=None),
    ])

    users = store.list_users()

    assert [u.user_id for u in users] == ["u-new", "u-old", "u-undated"]
    assert users[0].last_login_at == T2
    assert users[0].mfa_enabled is True
    assert users[0].role == "Analyst"


def test_list_users_empty(make_store):
    store, _ = make_store([])

    assert store.list_users() == []
    assert store.get_user("nobody") is None


def test_list_users_query_is_parameterised_and_excludes_credentials(make_store):
    store, log = make_store([])

    store.list_users(role="Administrator", active=False)

    sql, params = log[-1]
    assert "u.role = %s" in sql and "u.active = %s" in sql
    assert params == ("Administrator", False)
    for secret in ("password_salt", "password_digest", "last_totp_counter",
                   "failures", "locked_until"):
        assert secret not in sql
    assert "SELECT u.user_id" in sql
    assert not sql.startswith(("INSERT", "UPDATE", "DELETE"))


def test_search_does_not_reach_sql_and_filters_name_and_email(make_store):
    store, log = make_store([
        row("a", name="Alice Jones"),
        row("b", name="Bob", email="carol@example.test"),
    ])

    assert [u.user_id for u in store.list_users(q="ALICE")] == ["a"]
    assert [u.user_id for u in store.list_users(q="carol")] == ["b"]
    assert "ALICE" not in str(log) and "carol" not in str(log)


def test_get_user_binds_id(make_store):
    store, log = make_store([row("u-1")])

    user = store.get_user("u-1'; DROP TABLE x;--")

    assert user.user_id == "u-1"
    sql, params = log[-1]
    assert "WHERE u.user_id = %s" in sql
    assert params == ("u-1'; DROP TABLE x;--",)


@pytest.mark.parametrize("call", ["list_users", "get_user"])
def test_missing_columns_raise_schema_not_ready(make_store, call):
    store, _ = make_store(error=psycopg.errors.UndefinedColumn("no column"))

    with pytest.raises(UsersSchemaNotReady):
        getattr(store, call)(*(["u-1"] if call == "get_user" else []))


def test_fallbacks_read_auth_events(make_store):
    store, log = make_store([])

    store.list_users()

    sql, _ = log[-1]
    assert "COALESCE(u.created_at" in sql and "'user_created'" in sql
    assert "COALESCE(u.last_login_at" in sql
    assert "'mfa_verified_session_started'" in sql
