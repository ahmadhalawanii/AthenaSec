"""Operator audit store: hash chain, validation, tamper detection, three backends.

All events are created here; the app ships none.
"""

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.schemas import AuditEvent
from app.services.audit.operator_audit_store import (
    GENESIS_HASH,
    InMemoryOperatorAuditStore,
    OperatorAuditSchemaNotReady,
    PostgresOperatorAuditStore,
    SQLiteOperatorAuditStore,
    canonical_detail,
    compute_row_hash,
    verify_chain,
)

T0 = datetime(2026, 4, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def event_kwargs(index=1, **overrides):
    fields = dict(
        actor_id=f"admin-{index}",
        actor_role="Administrator",
        category="user",
        action="suspend",
        target=f"user-{index}",
        result="Success",
        source_ip="203.0.113.7",
        event_type="user_suspended",
        detail={"reason": "test", "n": index},
        occurred_at=T0 + timedelta(minutes=index),
    )
    fields.update(overrides)
    return fields


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryOperatorAuditStore()

    return SQLiteOperatorAuditStore(tmp_path / "audit.db")


# ---- empty and chain -------------------------------------------------------

def test_empty_store(store):
    assert store.list_events() == []
    assert store.get_event("OPAUD-missing") is None
    result = store.verify_chain()
    assert (result.valid, result.checked, result.head_hash) == (True, 0, None)


def test_chain_links_from_genesis_and_recomputes(store):
    first = store.append_event(**event_kwargs(1))
    second = store.append_event(**event_kwargs(2))
    third = store.append_event(**event_kwargs(3))

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.row_hash
    assert third.prev_hash == second.row_hash
    assert [first.seq, second.seq, third.seq] == sorted([first.seq, second.seq, third.seq])
    assert len({first.row_hash, second.row_hash, third.row_hash}) == 3

    expected = compute_row_hash(
        first.row_hash,
        event_id=second.event_id, occurred_at=second.occurred_at,
        actor_id=second.actor_id, actor_role=second.actor_role,
        category=second.category, action=second.action, target=second.target,
        result=second.result, source_ip=second.source_ip,
        event_type=second.event_type, detail=second.detail,
    )
    assert second.row_hash == expected

    verified = store.verify_chain()
    assert verified.valid and verified.checked == 3
    assert verified.head_hash == third.row_hash


def test_round_trip_preserves_hashed_fields(store):
    appended = store.append_event(**event_kwargs(1, detail={"b": 2, "a": [1, "x", None, True]}))

    loaded = store.get_event(appended.event_id)

    assert loaded == appended
    assert loaded.source == "operator"
    assert loaded.occurred_at == T0 + timedelta(minutes=1)
    assert store.list_events()[0] == appended


def test_events_listed_newest_first_with_filters(store):
    store.append_event(**event_kwargs(1, category="user", result="Success"))
    store.append_event(**event_kwargs(2, category="policy", result="Denied",
                                      actor_id="analyst-9", actor_role="Analyst",
                                      event_type="policy_update"))
    store.append_event(**event_kwargs(3, category="user", result="Failed"))

    def targets(**filters):
        return [e.target for e in store.list_events(**filters)]

    assert targets() == ["user-3", "user-2", "user-1"]
    assert targets(category="policy") == ["user-2"]
    assert targets(result="Failed") == ["user-3"]
    assert targets(actor="analyst-9") == ["user-2"]
    assert targets(event_type="policy_update") == ["user-2"]
    assert targets(since=T0 + timedelta(minutes=2)) == ["user-3", "user-2"]
    assert targets(until=T0 + timedelta(minutes=2)) == ["user-2", "user-1"]
    assert targets(since=T0 + timedelta(minutes=2), until=T0 + timedelta(minutes=2)) == ["user-2"]


# ---- validation ------------------------------------------------------------

@pytest.mark.parametrize(
    "overrides",
    [
        {"actor_role": "Owner"},
        {"result": "Maybe"},
        {"actor_id": "  "},
        {"category": ""},
        {"action": ""},
        {"target": ""},
        {"detail": ["not", "an", "object"]},
        {"detail": {"when": datetime(2026, 1, 1)}},
        {"detail": {"n": float("nan")}},
        {"source_ip": "not-an-ip"},
    ],
)
def test_invalid_events_are_rejected_and_nothing_is_written(store, overrides):
    with pytest.raises((ValueError, TypeError)):
        store.append_event(**event_kwargs(1, **overrides))

    assert store.list_events() == []


def test_source_ip_is_normalised_and_optional(store):
    v6 = store.append_event(**event_kwargs(1, source_ip="2001:0DB8:0:0:0:0:0:1"))
    none = store.append_event(**event_kwargs(2, source_ip=None))

    assert v6.source_ip == "2001:db8::1"
    assert none.source_ip is None
    assert store.verify_chain().valid


def test_event_ids_are_unique(store):
    ids = {store.append_event(**event_kwargs(i)).event_id for i in range(1, 6)}

    assert len(ids) == 5


# ---- tamper detection ------------------------------------------------------

def test_in_memory_edit_is_detected():
    store = InMemoryOperatorAuditStore()
    for i in range(1, 4):
        store.append_event(**event_kwargs(i))

    store._events[1] = store._events[1].model_copy(update={"result": "Failed"})

    result = store.verify_chain()
    assert result.valid is False
    assert result.first_broken_seq == store._events[1].seq
    assert result.checked == 1
    assert result.head_hash is None


def test_in_memory_deleted_middle_row_is_detected():
    store = InMemoryOperatorAuditStore()
    for i in range(1, 4):
        store.append_event(**event_kwargs(i))

    removed = store._events.pop(1)

    result = store.verify_chain()
    assert result.valid is False
    assert result.first_broken_seq != removed.seq


def test_verify_chain_function_detects_swapped_order():
    store = InMemoryOperatorAuditStore()
    for i in range(1, 4):
        store.append_event(**event_kwargs(i))
    events = list(store._events)

    assert verify_chain([events[1], events[0], events[2]]).valid is False


def test_sqlite_triggers_block_update_and_delete(tmp_path):
    path = tmp_path / "audit.db"
    store = SQLiteOperatorAuditStore(path)
    store.append_event(**event_kwargs(1))

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("UPDATE operator_audit_events SET result = 'Failed'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("DELETE FROM operator_audit_events")

    assert store.verify_chain().valid


def test_sqlite_direct_edit_after_trigger_removal_is_detected(tmp_path):
    path = tmp_path / "audit.db"
    store = SQLiteOperatorAuditStore(path)
    for i in range(1, 4):
        store.append_event(**event_kwargs(i))

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER operator_audit_events_no_update")
        connection.execute("DROP TRIGGER operator_audit_events_no_delete")
        connection.execute("UPDATE operator_audit_events SET target = 'forged' WHERE seq = 2")

    result = store.verify_chain()
    assert result.valid is False
    assert result.first_broken_seq == 2

    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE operator_audit_events SET target = 'user-2' WHERE seq = 2")
        connection.execute("DELETE FROM operator_audit_events WHERE seq = 2")

    assert store.verify_chain().valid is False


def test_sqlite_state_survives_reopening(tmp_path):
    path = tmp_path / "audit.db"
    first = SQLiteOperatorAuditStore(path).append_event(**event_kwargs(1))

    second = SQLiteOperatorAuditStore(path).append_event(**event_kwargs(2))

    assert second.prev_hash == first.row_hash
    assert SQLiteOperatorAuditStore(path).verify_chain().checked == 2


# ---- concurrency -----------------------------------------------------------

def test_concurrent_appends_keep_one_linear_chain(store):
    errors = []

    def worker(offset):
        try:
            for i in range(5):
                store.append_event(**event_kwargs(offset * 10 + i))
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(1, 5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    result = store.verify_chain()
    assert result.valid and result.checked == 20
    assert len({e.prev_hash for e in store.list_events()}) == 20


def test_canonical_detail_is_order_independent():
    assert canonical_detail({"b": 1, "a": 2}) == canonical_detail({"a": 2, "b": 1})


# ---- postgres, recording connection ---------------------------------------

class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class PgConnection:
    def __init__(self, script, log, error=None):
        self.script, self.log, self.error = script, log, error

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


def pg_store(script=(), error=None):
    log = []
    store = PostgresOperatorAuditStore(
        "postgresql://test/test",
        connect=lambda url: PgConnection(list(script), log, error),
    )
    return store, log


def test_postgres_constructor_creates_no_tables():
    _, log = pg_store()

    assert log == []


def test_postgres_append_locks_then_chains_then_inserts():
    store, log = pg_store(script=[
        ("SELECT row_hash", [("f" * 64,)]),
        ("RETURNING seq", [(41,)]),
    ])

    event = store.append_event(**event_kwargs(1))

    statements = [text for text, _ in log]
    assert "pg_advisory_xact_lock" in statements[0]
    assert "ORDER BY seq DESC LIMIT 1" in statements[1]
    assert statements[2].startswith("INSERT INTO operator_audit_events")
    assert event.seq == 41
    assert event.prev_hash == "f" * 64
    params = log[2][1]
    assert params[0] == event.event_id
    assert params[-2:] == ("f" * 64, event.row_hash)
    assert params[10] == canonical_detail(event.detail)


def test_postgres_first_event_uses_genesis():
    store, _ = pg_store(script=[("RETURNING seq", [(1,)])])

    assert store.append_event(**event_kwargs(1)).prev_hash == GENESIS_HASH


def test_postgres_missing_table_raises_schema_not_ready():
    error = psycopg.errors.UndefinedTable("missing")
    store, _ = pg_store(error=error)

    for call in (
        lambda: store.append_event(**event_kwargs(1)),
        lambda: store.list_events(),
        lambda: store.get_event("x"),
        lambda: store.verify_chain(),
    ):
        with pytest.raises(OperatorAuditSchemaNotReady):
            call()


def test_postgres_invalid_event_never_reaches_database():
    store, log = pg_store()

    with pytest.raises(ValueError):
        store.append_event(**event_kwargs(1, result="Maybe"))

    assert log == []


def test_postgres_list_binds_filters():
    store, log = pg_store()
    since = T0

    store.list_events(actor="a'; DROP TABLE x;--", result="Denied", since=since)

    text, params = log[-1]
    assert "actor_id = %s" in text and "result = %s" in text and "occurred_at >= %s" in text
    assert params == ("a'; DROP TABLE x;--", "Denied", since)
    assert "DROP TABLE" not in text
    assert text.endswith("ORDER BY seq DESC")


def test_postgres_verify_reads_oldest_first_and_checks_chain():
    good = InMemoryOperatorAuditStore()
    events = [good.append_event(**event_kwargs(i)) for i in (1, 2)]
    rows = [
        (e.seq, e.event_id, e.occurred_at, e.actor_id, e.actor_role, e.category,
         e.action, e.target, e.result, e.source_ip, e.event_type,
         canonical_detail(e.detail), e.prev_hash, e.row_hash)
        for e in events
    ]
    store, log = pg_store(script=[("FROM operator_audit_events ORDER BY seq ASC", rows)])

    result = store.verify_chain()

    assert result.valid and result.checked == 2
    assert "ORDER BY seq ASC" in log[-1][0]

    tampered = [rows[0], rows[1][:7] + ("forged",) + rows[1][8:]]
    store, _ = pg_store(script=[("ORDER BY seq ASC", tampered)])
    assert store.verify_chain().valid is False


def test_audit_event_model_has_no_credential_fields():
    assert not {"password", "token", "secret"} & set(AuditEvent.model_fields)
