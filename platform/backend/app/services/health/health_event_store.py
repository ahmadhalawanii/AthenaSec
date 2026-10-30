"""Health events: one row each time a service's observed status changes.

Written only when GET /api/v1/system/health sees a status differ from the last event
recorded for that service (that is its one write; it takes no client input). A first
observation of "up" or "unconfigured" is not a change and records nothing, so a healthy
or unused service adds no rows. Live status is never read from here.

The Postgres table is created by Alembic migration 0006, never by this module.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import HealthEvent

_ADVISORY_LOCK_KEY = 7_265_043_003
_COLUMNS = "event_id, occurred_at, severity, source, status, message"
_QUIET_FIRST_STATUSES = {"up", "unconfigured"}


class HealthSchemaNotReady(RuntimeError):
    """health_events does not exist yet (run alembic upgrade head)."""


def should_record(previous_status: str | None, status: str) -> bool:
    if previous_status is None:
        return status not in _QUIET_FIRST_STATUSES

    return previous_status != status


class HealthEventStore(Protocol):
    def record_status(self, *, source: str, status: str, severity: str, message: str,
                      occurred_at: datetime | None = None) -> HealthEvent | None: ...

    def list_events(self, *, severity: str | None = None, source: str | None = None,
                    since: datetime | None = None,
                    until: datetime | None = None) -> list[HealthEvent]: ...


def _event_from_row(row) -> HealthEvent:
    occurred = row[1]

    if isinstance(occurred, str):
        occurred = datetime.fromisoformat(occurred)

    return HealthEvent(event_id=row[0], occurred_at=occurred, severity=row[2],
                       source=row[3], status=row[4], message=row[5])


def _now(value):
    return datetime.now(timezone.utc) if value is None else value


class InMemoryHealthEventStore:
    def __init__(self):
        self._events: list[HealthEvent] = []
        self._lock = threading.Lock()

    def record_status(self, *, source, status, severity, message, occurred_at=None):
        with self._lock:
            previous = next((e.status for e in reversed(self._events) if e.source == source), None)

            if not should_record(previous, status):
                return None

            event = HealthEvent(event_id=len(self._events) + 1, occurred_at=_now(occurred_at),
                                severity=severity, source=source, status=status, message=message)
            self._events.append(event)

        return event

    def list_events(self, *, severity=None, source=None, since=None, until=None):
        selected = [
            e for e in self._events
            if (severity is None or e.severity == severity)
            and (source is None or e.source == source)
            and (since is None or e.occurred_at >= since)
            and (until is None or e.occurred_at <= until)
        ]

        return sorted(selected, key=lambda e: e.event_id, reverse=True)


class SQLiteHealthEventStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, isolation_level=None, timeout=30)

    def _initialize_database(self) -> None:
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS health_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    occurred_at TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('Info','Warning','Critical')),
                    source TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('up','degraded','down','starting','unconfigured')),
                    message TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_health_events_source ON health_events(source, event_id)"
            )
        finally:
            connection.close()

    def record_status(self, *, source, status, severity, message, occurred_at=None):
        occurred = _now(occurred_at)
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                last = connection.execute(
                    "SELECT status FROM health_events WHERE source = ? ORDER BY event_id DESC LIMIT 1",
                    (source,),
                ).fetchone()

                if not should_record(last[0] if last else None, status):
                    connection.execute("COMMIT")
                    return None

                cursor = connection.execute(
                    "INSERT INTO health_events (occurred_at, severity, source, status, message) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (occurred.isoformat(), severity, source, status, message),
                )
                event_id = cursor.lastrowid
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

        return HealthEvent(event_id=event_id, occurred_at=occurred, severity=severity,
                           source=source, status=status, message=message)

    def list_events(self, *, severity=None, source=None, since=None, until=None):
        connection = self._connect()

        try:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM health_events ORDER BY event_id DESC").fetchall()
        finally:
            connection.close()

        # Times are compared as instants in Python; stored offsets may differ.
        return [
            e for e in (_event_from_row(row) for row in rows)
            if (severity is None or e.severity == severity)
            and (source is None or e.source == source)
            and (since is None or e.occurred_at >= since)
            and (until is None or e.occurred_at <= until)
        ]


class PostgresHealthEventStore:
    """Reads and appends only; the table comes from migration 0006."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def record_status(self, *, source, status, severity, message, occurred_at=None):
        occurred = _now(occurred_at)

        try:
            with self._connect(self.database_url) as connection:
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
                last = connection.execute(
                    "SELECT status FROM health_events WHERE source = %s "
                    "ORDER BY event_id DESC LIMIT 1", (source,)).fetchone()

                if not should_record(last[0] if last else None, status):
                    return None

                event_id = connection.execute(
                    "INSERT INTO health_events (occurred_at, severity, source, status, message) "
                    "VALUES (%s, %s, %s, %s, %s) RETURNING event_id",
                    (occurred, severity, source, status, message)).fetchone()[0]
        except psycopg.errors.UndefinedTable as exc:
            raise HealthSchemaNotReady("Run alembic upgrade head.") from exc

        return HealthEvent(event_id=event_id, occurred_at=occurred, severity=severity,
                           source=source, status=status, message=message)

    def list_events(self, *, severity=None, source=None, since=None, until=None):
        clauses, params = [], []

        for column, value in (("severity", severity), ("source", source)):
            if value is not None:
                clauses.append(f"{column} = %s")
                params.append(value)

        if since is not None:
            clauses.append("occurred_at >= %s")
            params.append(since)

        if until is not None:
            clauses.append("occurred_at <= %s")
            params.append(until)

        where = " WHERE " + " AND ".join(clauses) if clauses else ""

        try:
            with self._connect(self.database_url) as connection:
                rows = connection.execute(
                    f"SELECT {_COLUMNS} FROM health_events{where} ORDER BY event_id DESC",
                    tuple(params)).fetchall()
        except psycopg.errors.UndefinedTable as exc:
            raise HealthSchemaNotReady("Run alembic upgrade head.") from exc

        return [_event_from_row(row) for row in rows]
