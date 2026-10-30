"""Append-only, versioned storage for the action policy (whitelist and blacklist of agent actions).

Unlike the target policy store, the agent reads this one: the newest version is the policy
the action policy engine enforces. Until an administrator saves a version, the built-in
default (action_catalogue.default_action_policy) applies.

Every save is a new row (version = previous + 1); rows are never updated or deleted.
append_version() takes the version the caller last saw and raises ActionPolicyVersionConflict
if it is no longer the latest, so two administrators cannot overwrite each other.

The Postgres table is created by Alembic migration 0007, never by this module.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import ActionPolicyContent, ActionPolicyDocument
from app.services.policy.action_catalogue import default_action_policy

_ADVISORY_LOCK_KEY = 7_265_043_007
_COLUMNS = "version, document, created_at, created_by, reason"


class ActionPolicySchemaNotReady(RuntimeError):
    """action_policy_versions does not exist yet (run alembic upgrade head)."""


class ActionPolicyVersionConflict(Exception):
    def __init__(self, current_version: int):
        super().__init__(f"Latest action policy version is {current_version}.")
        self.current_version = current_version


class ActionPolicyStore(Protocol):
    def get_current(self) -> ActionPolicyDocument | None: ...

    def list_versions(self) -> list[ActionPolicyDocument]: ...

    def append_version(
        self,
        *,
        base_version: int,
        content: ActionPolicyContent,
        reason: str,
        created_by: str,
        created_at: datetime | None = None,
    ) -> ActionPolicyDocument: ...


def default_document() -> ActionPolicyDocument:
    return ActionPolicyDocument(version=0, is_default=True, **default_action_policy().model_dump())


def current_or_default(store: ActionPolicyStore | None) -> ActionPolicyDocument:
    """The policy in force: the newest saved version, or the built-in default."""

    if store is None:
        return default_document()

    return store.get_current() or default_document()


def _document(content: ActionPolicyContent) -> str:
    return json.dumps(content.model_dump(), sort_keys=True, separators=(",", ":"))


def _record(version, document, created_at, created_by, reason) -> ActionPolicyDocument:
    if isinstance(document, str):
        document = json.loads(document)

    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)

    return ActionPolicyDocument(
        version=version, created_at=created_at, created_by=created_by, reason=reason, **document
    )


def _now(created_at):
    return datetime.now(timezone.utc) if created_at is None else created_at


class InMemoryActionPolicyStore:
    def __init__(self):
        self._versions: list[ActionPolicyDocument] = []
        self._lock = threading.Lock()

    def get_current(self):
        return self._versions[-1] if self._versions else None

    def list_versions(self):
        return list(reversed(self._versions))

    def append_version(self, *, base_version, content, reason, created_by, created_at=None):
        with self._lock:
            current = len(self._versions)

            if base_version != current:
                raise ActionPolicyVersionConflict(current)

            record = _record(current + 1, content.model_dump(), _now(created_at), created_by, reason)
            self._versions.append(record)

        return record


class SQLiteActionPolicyStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        # Explicit transactions (BEGIN IMMEDIATE) so the version check and insert are atomic
        return sqlite3.connect(self.database_path, isolation_level=None, timeout=30)

    def _initialize_database(self) -> None:
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS action_policy_versions (
                    version INTEGER PRIMARY KEY CHECK (version >= 1),
                    document TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )
            for name, operation in (("update", "UPDATE"), ("delete", "DELETE")):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS action_policy_versions_no_{name}
                    BEFORE {operation} ON action_policy_versions
                    BEGIN
                        SELECT RAISE(ABORT, 'action_policy_versions is append-only');
                    END
                    """
                )
        finally:
            connection.close()

    def _fetch(self, statement, params=(), *, one=False):
        connection = self._connect()

        try:
            result = connection.execute(statement, params)
            return result.fetchone() if one else result.fetchall()
        finally:
            connection.close()

    def get_current(self):
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM action_policy_versions ORDER BY version DESC LIMIT 1", one=True
        )

        return _record(*row) if row else None

    def list_versions(self):
        rows = self._fetch(f"SELECT {_COLUMNS} FROM action_policy_versions ORDER BY version DESC")

        return [_record(*row) for row in rows]

    def append_version(self, *, base_version, content, reason, created_by, created_at=None):
        created_at = _now(created_at)
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM action_policy_versions"
                ).fetchone()[0]

                if current != base_version:
                    raise ActionPolicyVersionConflict(current)

                connection.execute(
                    f"INSERT INTO action_policy_versions ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
                    (current + 1, _document(content), created_at.isoformat(), created_by, reason),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

        return _record(current + 1, content.model_dump(), created_at, created_by, reason)


class PostgresActionPolicyStore:
    """Reads and appends only; the table and its triggers come from migration 0007."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def _fetch(self, statement, params=(), *, one=False):
        try:
            with self._connect(self.database_url) as connection:
                result = connection.execute(statement, params)
                return result.fetchone() if one else result.fetchall()
        except psycopg.errors.UndefinedTable as exc:
            raise ActionPolicySchemaNotReady("Run alembic upgrade head.") from exc

    def get_current(self):
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM action_policy_versions ORDER BY version DESC LIMIT 1", one=True
        )

        return _record(*row) if row else None

    def list_versions(self):
        rows = self._fetch(f"SELECT {_COLUMNS} FROM action_policy_versions ORDER BY version DESC")

        return [_record(*row) for row in rows]

    def append_version(self, *, base_version, content, reason, created_by, created_at=None):
        created_at = _now(created_at)

        try:
            with self._connect(self.database_url) as connection:
                connection.execute("SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,))
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM action_policy_versions"
                ).fetchone()[0]

                if current != base_version:
                    raise ActionPolicyVersionConflict(current)

                connection.execute(
                    f"INSERT INTO action_policy_versions ({_COLUMNS}) VALUES (%s, %s, %s, %s, %s)",
                    (current + 1, _document(content), created_at, created_by, reason),
                )
        except psycopg.errors.UndefinedTable as exc:
            raise ActionPolicySchemaNotReady("Run alembic upgrade head.") from exc

        return _record(current + 1, content.model_dump(), created_at, created_by, reason)
