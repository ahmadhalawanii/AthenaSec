"""Response policy store: append-only versions with optimistic concurrency, three backends."""

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.schemas import PolicyEntry
from app.services.policy.response_policy_store import (
    InMemoryResponsePolicyStore,
    PolicySchemaNotReady,
    PolicyVersionConflict,
    PostgresResponsePolicyStore,
    SQLiteResponsePolicyStore,
)

T0 = datetime(2026, 7, 1, 9, 0, tzinfo=timezone.utc)


def entry(value, type_="ip", note=""):
    return PolicyEntry(value=value, type=type_, note=note)


def save(store, base, *, white=(), black=(), reason="change", by="admin-1", minutes=0):
    return store.append_version(
        base_version=base, whitelist=list(white), blacklist=list(black), reason=reason,
        created_by=by, created_at=T0 + timedelta(minutes=minutes))


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryResponsePolicyStore()

    return SQLiteResponsePolicyStore(tmp_path / "policy.db")


# ---- empty and sequence ----------------------------------------------------

def test_empty_store(store):
    assert store.get_current() is None
    assert store.get_version(1) is None
    assert store.list_versions() == []


def test_versions_count_up_from_one_and_list_newest_first(store):
    first = save(store, 0, white=[entry("10.0.0.1")])
    second = save(store, 1, black=[entry("evil.example.com", "hostname", "known bad")], minutes=1)
    third = save(store, 2, minutes=2)

    assert [first.version, second.version, third.version] == [1, 2, 3]
    assert [r.version for r in store.list_versions()] == [3, 2, 1]
    assert store.get_current().version == 3


def test_round_trip_keeps_entries_and_metadata(store):
    saved = save(store, 0, white=[entry("2001:db8::1", "ip"), entry("10.0.0.0/8", "cidr", "lan")],
                 black=[entry("svc-bad", "account")], reason="initial", by="admin-9")

    loaded = store.get_version(1)

    assert loaded == saved
    assert loaded.whitelist[1].note == "lan"
    assert loaded.created_by == "admin-9" and loaded.reason == "initial"
    assert loaded.created_at == T0


def test_old_versions_are_unchanged_by_later_saves(store):
    save(store, 0, white=[entry("10.0.0.1")])
    save(store, 1, white=[entry("10.0.0.2")], minutes=1)

    assert [e.value for e in store.get_version(1).whitelist] == ["10.0.0.1"]
    assert [e.value for e in store.get_current().whitelist] == ["10.0.0.2"]


# ---- optimistic concurrency ------------------------------------------------

@pytest.mark.parametrize("base", [0, 2, 7])
def test_stale_or_wrong_base_version_conflicts_and_saves_nothing(store, base):
    save(store, 0)

    with pytest.raises(PolicyVersionConflict) as caught:
        save(store, base, minutes=1)

    assert caught.value.current_version == 1
    assert len(store.list_versions()) == 1


def test_first_save_must_use_base_zero(store):
    with pytest.raises(PolicyVersionConflict) as caught:
        save(store, 3)

    assert caught.value.current_version == 0
    assert store.list_versions() == []


def test_concurrent_editors_cannot_both_win(store):
    results, lock = [], threading.Lock()

    def editor(name):
        try:
            record = save(store, 0, reason=name, by=name)
            outcome = ("saved", record.version)
        except PolicyVersionConflict as exc:
            outcome = ("conflict", exc.current_version)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=editor, args=(f"e{n}",)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for kind, _ in results if kind == "saved") == 1
    assert sum(1 for kind, _ in results if kind == "conflict") == 7
    assert [r.version for r in store.list_versions()] == [1]


# ---- sqlite specifics ------------------------------------------------------

def test_sqlite_rows_cannot_be_updated_or_deleted(tmp_path):
    path = tmp_path / "policy.db"
    store = SQLiteResponsePolicyStore(path)
    save(store, 0, white=[entry("10.0.0.1")])

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("UPDATE response_policy_versions SET reason = 'x'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("DELETE FROM response_policy_versions")

    assert store.get_current().reason == "change"


def test_sqlite_state_survives_reopening(tmp_path):
    path = tmp_path / "policy.db"
    save(SQLiteResponsePolicyStore(path), 0, white=[entry("10.0.0.1")])

    reopened = SQLiteResponsePolicyStore(path)

    assert reopened.get_current().version == 1
    assert save(reopened, 1).version == 2


# ---- postgres, recording connection ---------------------------------------

class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class Connection:
    def __init__(self, log, script, error):
        self.log, self.script, self.error = log, script, error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params=None):
        text = " ".join(str(statement).split())
        self.log.append((text, params))
        if self.error is not None:
            raise self.error
        for needle, rows in self.script:
            if needle in text:
                return Result(rows)
        return Result([])


def pg(script=(), error=None):
    log = []
    return PostgresResponsePolicyStore(
        "postgresql://test/test", connect=lambda url: Connection(log, list(script), error)), log


def test_postgres_constructor_creates_no_tables():
    _, log = pg()

    assert log == []


def test_postgres_append_locks_checks_then_inserts():
    store, log = pg(script=[("SELECT COALESCE(MAX(version), 0)", [(4,)])])

    record = save(store, 4, white=[entry("10.0.0.1")])

    statements = [text for text, _ in log]
    assert "pg_advisory_xact_lock" in statements[0]
    assert "SELECT COALESCE(MAX(version), 0)" in statements[1]
    assert statements[2].startswith("INSERT INTO response_policy_versions")
    assert record.version == 5
    params = log[2][1]
    assert params[0] == 5 and params[2] == T0 and params[3:] == ("admin-1", "change")
    assert '"whitelist"' in params[1] and "10.0.0.1" in params[1]


def test_postgres_conflict_inserts_nothing():
    store, log = pg(script=[("SELECT COALESCE(MAX(version), 0)", [(4,)])])

    with pytest.raises(PolicyVersionConflict) as caught:
        save(store, 3)

    assert caught.value.current_version == 4
    assert not any(text.startswith("INSERT") for text, _ in log)


def test_postgres_missing_table_raises_schema_not_ready():
    store, _ = pg(error=psycopg.errors.UndefinedTable("missing"))

    for call in (store.get_current, store.list_versions, lambda: store.get_version(1),
                 lambda: save(store, 0)):
        with pytest.raises(PolicySchemaNotReady):
            call()


def test_postgres_reads_map_rows_and_bind_version():
    document = '{"blacklist":[{"note":"","type":"account","value":"bad"}],"whitelist":[]}'
    store, log = pg(script=[("FROM response_policy_versions", [(3, document, T0, "admin-1", "why")])])

    record = store.get_version(3)

    assert record.version == 3 and record.blacklist[0].value == "bad"
    assert log[-1][1] == (3,) and "WHERE version = %s" in log[-1][0]
    assert store.get_current().created_at == T0
    assert [r.version for r in store.list_versions()] == [3]
