"""Append-only, versioned storage for the response policy DOCUMENT.

STORAGE ONLY. Nothing in the agent (graph nodes, risk engine, policy engine, structured
action policy, Cortex) reads this table, so saving a policy changes no agent behaviour.
A test enforces that no agent module imports this one.

Every save is a new row (version = previous + 1); rows are never updated or deleted.
append_version() takes the version the caller last saw and raises PolicyVersionConflict
if it is no longer the latest, so concurrent editors cannot overwrite each other.

The Postgres table is created by Alembic migration 0005, never by this module.
"""

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import PolicyEntry, PolicyVersionRecord

_ADVISORY_LOCK_KEY = 7_265_043_002
_COLUMNS = "version, document, created_at, created_by, reason"


class PolicySchemaNotReady(RuntimeError):
    """response_policy_versions does not exist yet (run alembic upgrade head)."""


class PolicyVersionConflict(Exception):
    def __init__(self, current_version: int):
        super().__init__(f"Latest policy version is {current_version}.")
        self.current_version = current_version


class ResponsePolicyStore(Protocol):
    def get_current(self) -> PolicyVersionRecord | None: ...

    def get_version(self, version: int) -> PolicyVersionRecord | None: ...

    def list_versions(self) -> list[PolicyVersionRecord]: ...

    def append_version(
        self,
        *,
        base_version: int,
        whitelist: list[PolicyEntry],
        blacklist: list[PolicyEntry],
        reason: str,
        created_by: str,
        created_at: datetime | None = None,
    ) -> PolicyVersionRecord: ...


def _document(whitelist, blacklist) -> str:
    return json.dumps(
        {
            "whitelist": [e.model_dump() for e in whitelist],
            "blacklist": [e.model_dump() for e in blacklist],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _record_from_row(row) -> PolicyVersionRecord:
    document = json.loads(row[1])
    created_at = row[2]

    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)

    return PolicyVersionRecord(
        version=row[0],
        whitelist=[PolicyEntry(**e) for e in document["whitelist"]],
        blacklist=[PolicyEntry(**e) for e in document["blacklist"]],
        created_at=created_at,
        created_by=row[3],
        reason=row[4],
    )


def _now(created_at):
    return datetime.now(timezone.utc) if created_at is None else created_at


class InMemoryResponsePolicyStore:
    def __init__(self):
        self._versions: list[PolicyVersionRecord] = []
        self._lock = threading.Lock()

    def get_current(self):
        return self._versions[-1] if self._versions else None

    def get_version(self, version):
        return next((r for r in self._versions if r.version == version), None)

    def list_versions(self):
        return list(reversed(self._versions))

    def append_version(self, *, base_version, whitelist, blacklist, reason, created_by,
                       created_at=None):
        with self._lock:
            current = len(self._versions)

            if base_version != current:
                raise PolicyVersionConflict(current)

            record = PolicyVersionRecord(
                version=current + 1, whitelist=whitelist, blacklist=blacklist,
                created_at=_now(created_at), created_by=created_by, reason=reason,
            )
            self._versions.append(record)

        return record


class SQLiteResponsePolicyStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        # Explicit transactions (BEGIN IMMEDIATE) so version checks and inserts are atomic.
        return sqlite3.connect(self.database_path, isolation_level=None, timeout=30)

    def _initialize_database(self) -> None:
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS response_policy_versions (
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
                    CREATE TRIGGER IF NOT EXISTS response_policy_versions_no_{name}
                    BEFORE {operation} ON response_policy_versions
                    BEGIN
                        SELECT RAISE(ABORT, 'response_policy_versions is append-only');
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
            f"SELECT {_COLUMNS} FROM response_policy_versions ORDER BY version DESC LIMIT 1",
            one=True,
        )

        return _record_from_row(row) if row else None

    def get_version(self, version):
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM response_policy_versions WHERE version = ?",
            (version,), one=True,
        )

        return _record_from_row(row) if row else None

    def list_versions(self):
        rows = self._fetch(
            f"SELECT {_COLUMNS} FROM response_policy_versions ORDER BY version DESC"
        )

        return [_record_from_row(row) for row in rows]

    def append_version(self, *, base_version, whitelist, blacklist, reason, created_by,
                       created_at=None):
        created_at = _now(created_at)
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM response_policy_versions"
                ).fetchone()[0]

                if current != base_version:
                    raise PolicyVersionConflict(current)

                connection.execute(
                    f"INSERT INTO response_policy_versions ({_COLUMNS}) VALUES (?, ?, ?, ?, ?)",
                    (current + 1, _document(whitelist, blacklist), created_at.isoformat(),
                     created_by, reason),
                )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

        return PolicyVersionRecord(
            version=current + 1, whitelist=whitelist, blacklist=blacklist,
            created_at=created_at, created_by=created_by, reason=reason,
        )


class PostgresResponsePolicyStore:
    """Reads and appends only; the table and its triggers come from migration 0005."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def _fetch(self, statement, params=(), *, one=False):
        try:
            with self._connect(self.database_url) as connection:
                result = connection.execute(statement, params)
                return result.fetchone() if one else result.fetchall()
        except psycopg.errors.UndefinedTable as exc:
            raise PolicySchemaNotReady("Run alembic upgrade head.") from exc

    def get_current(self):
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM response_policy_versions ORDER BY version DESC LIMIT 1",
            one=True,
        )

        return _record_from_row(row) if row else None

    def get_version(self, version):
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM response_policy_versions WHERE version = %s",
            (version,), one=True,
        )

        return _record_from_row(row) if row else None

    def list_versions(self):
        rows = self._fetch(
            f"SELECT {_COLUMNS} FROM response_policy_versions ORDER BY version DESC"
        )

        return [_record_from_row(row) for row in rows]

    def append_version(self, *, base_version, whitelist, blacklist, reason, created_by,
                       created_at=None):
        created_at = _now(created_at)

        try:
            with self._connect(self.database_url) as connection:
                connection.execute(
                    "SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,)
                )
                current = connection.execute(
                    "SELECT COALESCE(MAX(version), 0) FROM response_policy_versions"
                ).fetchone()[0]

                if current != base_version:
                    raise PolicyVersionConflict(current)

                connection.execute(
                    f"INSERT INTO response_policy_versions ({_COLUMNS}) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (current + 1, _document(whitelist, blacklist), created_at,
                     created_by, reason),
                )
        except psycopg.errors.UndefinedTable as exc:
            raise PolicySchemaNotReady("Run alembic upgrade head.") from exc

        return PolicyVersionRecord(
            version=current + 1, whitelist=whitelist, blacklist=blacklist,
            created_at=created_at, created_by=created_by, reason=reason,
        )
