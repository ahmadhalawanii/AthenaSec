"""Small JSON documents the website saves: the system configuration and each user's settings.

One row per key ("configuration", "user-settings:<user_id>"). Each save checks the
version the caller last saw, so two people editing at once cannot overwrite each other.

The Postgres table is created by Alembic migration 0009, never by this module.
"""

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import psycopg

_COLUMNS = "key, document, version, updated_at, updated_by"


class SettingsSchemaNotReady(RuntimeError):
    """app_settings does not exist yet (run alembic upgrade head)."""


class SettingsVersionConflict(Exception):
    def __init__(self, current_version: int):
        super().__init__(f"Latest version is {current_version}.")
        self.current_version = current_version


@dataclass(frozen=True)
class SettingsDocument:
    key: str
    document: dict
    version: int
    updated_at: datetime
    updated_by: str


class SettingsStore(Protocol):
    def get(self, key: str) -> SettingsDocument | None: ...

    def put(self, key: str, document: dict, *, base_version: int | None,
            updated_by: str) -> SettingsDocument: ...


def _row(key, document, version, updated_at, updated_by):
    if isinstance(document, str):
        document = json.loads(document)
    if isinstance(updated_at, str):
        updated_at = datetime.fromisoformat(updated_at)
    return SettingsDocument(key, document, version, updated_at, updated_by)


def _check(current: SettingsDocument | None, base_version: int | None) -> int:
    # base_version None skips the check (per-user settings: only their owner writes them)
    version = current.version if current is not None else 0
    if base_version is not None and base_version != version:
        raise SettingsVersionConflict(version)
    return version + 1


class InMemorySettingsStore:
    def __init__(self):
        self._rows: dict[str, SettingsDocument] = {}
        self._lock = threading.Lock()

    def get(self, key):
        return self._rows.get(key)

    def put(self, key, document, *, base_version, updated_by):
        with self._lock:
            version = _check(self._rows.get(key), base_version)
            row = SettingsDocument(key, dict(document), version, datetime.now(timezone.utc), updated_by)
            self._rows[key] = row
        return row


class SQLiteSettingsStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    document TEXT NOT NULL,
                    version INTEGER NOT NULL CHECK (version >= 1),
                    updated_at TEXT NOT NULL,
                    updated_by TEXT NOT NULL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self):
        return sqlite3.connect(self.database_path, isolation_level=None, timeout=30)

    def get(self, key):
        connection = self._connect()
        try:
            row = connection.execute(f"SELECT {_COLUMNS} FROM app_settings WHERE key = ?", (key,)).fetchone()
        finally:
            connection.close()
        return _row(*row) if row else None

    def put(self, key, document, *, base_version, updated_by):
        now = datetime.now(timezone.utc)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    f"SELECT {_COLUMNS} FROM app_settings WHERE key = ?", (key,)
                ).fetchone()
                version = _check(_row(*row) if row else None, base_version)
                connection.execute(
                    f"INSERT OR REPLACE INTO app_settings ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
                    (key, json.dumps(document, sort_keys=True), version, now.isoformat(), updated_by),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()
        return SettingsDocument(key, dict(document), version, now, updated_by)


class PostgresSettingsStore:
    """Reads and writes only; the table comes from migration 0009."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def get(self, key):
        try:
            with self._connect(self.database_url) as connection:
                row = connection.execute(
                    f"SELECT {_COLUMNS} FROM app_settings WHERE key = %s", (key,)
                ).fetchone()
        except psycopg.errors.UndefinedTable as exc:
            raise SettingsSchemaNotReady("Run alembic upgrade head.") from exc
        return _row(*row) if row else None

    def put(self, key, document, *, base_version, updated_by):
        now = datetime.now(timezone.utc)
        try:
            with self._connect(self.database_url) as connection:
                row = connection.execute(
                    f"SELECT {_COLUMNS} FROM app_settings WHERE key = %s FOR UPDATE", (key,)
                ).fetchone()
                version = _check(_row(*row) if row else None, base_version)
                connection.execute(
                    f"""
                    INSERT INTO app_settings ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (key) DO UPDATE SET document = EXCLUDED.document,
                        version = EXCLUDED.version, updated_at = EXCLUDED.updated_at,
                        updated_by = EXCLUDED.updated_by
                    """,
                    (key, json.dumps(document, sort_keys=True), version, now, updated_by),
                )
        except psycopg.errors.UndefinedTable as exc:
            raise SettingsSchemaNotReady("Run alembic upgrade head.") from exc
        return SettingsDocument(key, dict(document), version, now, updated_by)
