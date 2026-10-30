"""AuditStore.list_incident_events (cross-incident listing) on all three backends."""

from datetime import datetime, timedelta, timezone

import pytest

from app.schemas import IncidentAuditRecord
from app.services.audit.audit_store import (
    InMemoryAuditStore,
    PostgresAuditStore,
    SQLiteAuditStore,
)

T0 = datetime(2026, 5, 1, 8, 0, tzinfo=timezone.utc)


def record(index, **overrides):
    fields = dict(
        audit_id=f"AUD-{index}", incident_id=f"INC-{index % 2}",
        event_type="alert_received" if index % 2 else "approval_decided",
        entity_type="alert", entity_id=f"A-{index}", message="m", details={},
        timestamp=T0 + timedelta(hours=index),
    )
    fields.update(overrides)
    return IncidentAuditRecord(**fields)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    store = (
        InMemoryAuditStore()
        if request.param == "memory"
        else SQLiteAuditStore(tmp_path / "audit.db")
    )
    for index in range(1, 5):
        store.save_incident_event(record(index))
    return store


def listed(store, **filters):
    return [r.audit_id for r in store.list_incident_events(**filters)]


def test_all_events_newest_first(store):
    assert listed(store) == ["AUD-4", "AUD-3", "AUD-2", "AUD-1"]


def test_filters(store):
    assert listed(store, incident_id="INC-1") == ["AUD-3", "AUD-1"]
    assert listed(store, event_type="approval_decided") == ["AUD-4", "AUD-2"]
    assert listed(store, since=T0 + timedelta(hours=3)) == ["AUD-4", "AUD-3"]
    assert listed(store, until=T0 + timedelta(hours=2)) == ["AUD-2", "AUD-1"]
    assert listed(store, incident_id="INC-1", event_type="approval_decided") == []


def test_empty_store_lists_nothing(tmp_path):
    assert InMemoryAuditStore().list_incident_events() == []
    assert SQLiteAuditStore(tmp_path / "e.db").list_incident_events() == []


def test_time_filter_compares_instants_not_text(tmp_path):
    store = SQLiteAuditStore(tmp_path / "tz.db")
    plus_ten = timezone(timedelta(hours=10))
    # 2026-05-01 22:00 +10:00 is 12:00 UTC, earlier than 13:00 UTC.
    store.save_incident_event(record(1, timestamp=datetime(2026, 5, 1, 22, 0, tzinfo=plus_ten)))
    store.save_incident_event(record(2, timestamp=datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc)))

    assert listed(store, since=datetime(2026, 5, 1, 12, 30, tzinfo=timezone.utc)) == ["AUD-2"]


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return self.rows


class Connection:
    def __init__(self, log, rows):
        self.log, self.rows = log, rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params=None):
        self.log.append((" ".join(str(statement).split()), params))
        return Result(self.rows if "SELECT payload" in str(statement) else [])


def test_postgres_binds_filters_and_orders_newest_first():
    log = []
    rows = [(record(1).model_dump_json(),)]
    store = PostgresAuditStore("postgresql://x/y", connect=lambda url: Connection(log, rows))
    log.clear()
    since = T0

    result = store.list_incident_events(incident_id="INC-1'; --", event_type="e", since=since)

    text, params = log[-1]
    assert [r.audit_id for r in result] == ["AUD-1"]
    assert "incident_id = %s" in text and "event_type = %s" in text and "timestamp >= %s" in text
    assert text.endswith("ORDER BY timestamp DESC, audit_id DESC")
    assert params == ("INC-1'; --", "e", since)
    assert "--" not in text


def test_postgres_without_filters_has_no_where():
    log = []
    store = PostgresAuditStore("postgresql://x/y", connect=lambda url: Connection(log, []))
    log.clear()

    assert store.list_incident_events() == []
    assert "WHERE" not in log[-1][0]
