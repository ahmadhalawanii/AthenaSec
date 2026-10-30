"""The analyst's handling of each alert: open or closed, and who it is assigned to.

Kept apart from the investigation record (which the agent writes and never changes
afterwards). One row per alert, created the first time an analyst acts on it; an alert
with no row is open and unassigned.

The Postgres table is created by Alembic migration 0008, never by this module.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import AlertWorkflowRecord

_COLUMNS = "alert_id, status, assigned_analyst, updated_at, updated_by"


class AlertWorkflowSchemaNotReady(RuntimeError):
    """alert_workflow does not exist yet (run alembic upgrade head)."""


class AlertWorkflowStore(Protocol):
    def get(self, alert_id: str) -> AlertWorkflowRecord | None: ...

    def list_all(self) -> dict[str, AlertWorkflowRecord]: ...

    def save(self, record: AlertWorkflowRecord) -> AlertWorkflowRecord: ...


def _record(alert_id, status, assigned_analyst, updated_at, updated_by):
    if isinstance(updated_at, str):
        updated_at = datetime.fromisoformat(updated_at)

    return AlertWorkflowRecord(
        alert_id=alert_id, status=status, assigned_analyst=assigned_analyst,
        updated_at=updated_at, updated_by=updated_by,
    )


class InMemoryAlertWorkflowStore:
    def __init__(self):
        self._records: dict[str, AlertWorkflowRecord] = {}
        self._lock = threading.Lock()

    def get(self, alert_id):
        return self._records.get(alert_id)

    def list_all(self):
        return dict(self._records)

    def save(self, record):
        with self._lock:
            self._records[record.alert_id] = record

        return record


class SQLiteAlertWorkflowStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_workflow (
                    alert_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
                    assigned_analyst TEXT,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _fetch(self, statement, params=()):
        connection = sqlite3.connect(self.database_path)

        try:
            return connection.execute(statement, params).fetchall()
        finally:
            connection.close()

    def get(self, alert_id):
        rows = self._fetch(f"SELECT {_COLUMNS} FROM alert_workflow WHERE alert_id = ?", (alert_id,))

        return _record(*rows[0]) if rows else None

    def list_all(self):
        return {row[0]: _record(*row) for row in self._fetch(f"SELECT {_COLUMNS} FROM alert_workflow")}

    def save(self, record):
        connection = sqlite3.connect(self.database_path)

        try:
            connection.execute(
                f"INSERT OR REPLACE INTO alert_workflow ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
                (record.alert_id, record.status, record.assigned_analyst,
                 record.updated_at.isoformat(), record.updated_by),
            )
            connection.commit()
        finally:
            connection.close()

        return record


class PostgresAlertWorkflowStore:
    """Reads and writes only; the table comes from migration 0008."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def _run(self, statement, params=(), *, fetch=False):
        try:
            with self._connect(self.database_url) as connection:
                result = connection.execute(statement, params)
                return result.fetchall() if fetch else None
        except psycopg.errors.UndefinedTable as exc:
            raise AlertWorkflowSchemaNotReady("Run alembic upgrade head.") from exc

    def get(self, alert_id):
        rows = self._run(
            f"SELECT {_COLUMNS} FROM alert_workflow WHERE alert_id = %s", (alert_id,), fetch=True
        )

        return _record(*rows[0]) if rows else None

    def list_all(self):
        rows = self._run(f"SELECT {_COLUMNS} FROM alert_workflow", fetch=True)

        return {row[0]: _record(*row) for row in rows}

    def save(self, record):
        self._run(
            f"""
            INSERT INTO alert_workflow ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (alert_id) DO UPDATE SET
                status = EXCLUDED.status,
                assigned_analyst = EXCLUDED.assigned_analyst,
                updated_at = EXCLUDED.updated_at,
                updated_by = EXCLUDED.updated_by
            """,
            (record.alert_id, record.status, record.assigned_analyst,
             record.updated_at, record.updated_by),
        )

        return record
