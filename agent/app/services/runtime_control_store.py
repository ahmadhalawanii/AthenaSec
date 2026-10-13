import sqlite3
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import (
    RuntimeControlChangeRecord,
    RuntimeControlStateRecord,
)


class RuntimeControlStore(
    Protocol
):
    def get_state(
        self,
    ) -> (
        RuntimeControlStateRecord
        | None
    ):
        ...

    def initialize_state(
        self,
        record: RuntimeControlStateRecord,
    ) -> RuntimeControlStateRecord:
        ...

    def apply_update(
        self,
        state: RuntimeControlStateRecord,
        change: RuntimeControlChangeRecord,
        *,
        expected_version: int,
    ) -> RuntimeControlStateRecord:
        ...

    def list_changes(
        self,
    ) -> list[
        RuntimeControlChangeRecord
    ]:
        ...


class InMemoryRuntimeControlStore:
    def __init__(self):
        self._state = None
        self._changes = {}

    def get_state(
        self,
    ):
        return self._state

    def initialize_state(
        self,
        record,
    ):
        if self._state is None:
            self._state = record

        return self._state

    def apply_update(
        self,
        state,
        change,
        *,
        expected_version,
    ):
        current = self._state

        if (
            current is None
            or current.version
            != expected_version
        ):
            raise ValueError(
                "Runtime control state "
                "changed concurrently."
            )

        if (
            state.version
            != expected_version + 1
            or change.version
            != state.version
        ):
            raise ValueError(
                "Runtime control version "
                "transition is invalid."
            )

        if (
            change.change_id
            in self._changes
        ):
            raise ValueError(
                "Runtime control change_id "
                "already exists."
            )

        self._changes[
            change.change_id
        ] = change

        self._state = state

        return state

    def list_changes(
        self,
    ):
        return sorted(
            self._changes.values(),
            key=lambda record: (
                record.version,
                record.changed_at,
                record.change_id,
            ),
        )


class SQLiteRuntimeControlStore:
    def __init__(
        self,
        database_path: str | Path,
    ):
        self.database_path = Path(
            database_path
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(self):
        return sqlite3.connect(
            self.database_path
        )

    def _initialize_database(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS runtime_control_state (
                control_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS runtime_control_changes (
                change_id TEXT PRIMARY KEY,
                control_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                changed_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_runtime_control_changes_version
            ON runtime_control_changes (
                version
            )
            """,
        ]

        with self._connect() as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def get_state(
        self,
    ):
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM runtime_control_state
                WHERE control_id = ?
                """,
                (
                    "ATHENASEC_RUNTIME",
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            RuntimeControlStateRecord
            .model_validate_json(
                row[0]
            )
        )

    def initialize_state(
        self,
        record,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE
                INTO runtime_control_state (
                    control_id,
                    version,
                    updated_at,
                    payload
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    record.control_id,
                    record.version,
                    record.updated_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

        stored = self.get_state()

        if stored is None:
            raise RuntimeError(
                "Runtime control state "
                "could not be initialized."
            )

        return stored

    def apply_update(
        self,
        state,
        change,
        *,
        expected_version,
    ):
        if (
            state.version
            != expected_version + 1
            or change.version
            != state.version
        ):
            raise ValueError(
                "Runtime control version "
                "transition is invalid."
            )

        try:
            with self._connect() as connection:
                connection.execute(
                    "BEGIN IMMEDIATE"
                )

                row = connection.execute(
                    """
                    SELECT version
                    FROM runtime_control_state
                    WHERE control_id = ?
                    """,
                    (
                        state.control_id,
                    ),
                ).fetchone()

                if (
                    row is None
                    or row[0]
                    != expected_version
                ):
                    raise ValueError(
                        "Runtime control state "
                        "changed concurrently."
                    )

                connection.execute(
                    """
                    INSERT INTO runtime_control_changes (
                        change_id,
                        control_id,
                        version,
                        changed_at,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        change.change_id,
                        change.control_id,
                        change.version,
                        change.changed_at.isoformat(),
                        change.model_dump_json(),
                    ),
                )

                cursor = connection.execute(
                    """
                    UPDATE runtime_control_state
                    SET
                        version = ?,
                        updated_at = ?,
                        payload = ?
                    WHERE
                        control_id = ?
                        AND version = ?
                    """,
                    (
                        state.version,
                        state.updated_at.isoformat(),
                        state.model_dump_json(),
                        state.control_id,
                        expected_version,
                    ),
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        "Runtime control state "
                        "changed concurrently."
                    )

        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Runtime control change_id "
                "already exists."
            ) from exc

        return state

    def list_changes(
        self,
    ):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM runtime_control_changes
                ORDER BY
                    version ASC,
                    changed_at ASC,
                    change_id ASC
                """
            ).fetchall()

        return [
            RuntimeControlChangeRecord
            .model_validate_json(
                row[0]
            )
            for row in rows
        ]


class PostgresRuntimeControlStore:
    def __init__(
        self,
        database_url: str,
        *,
        connect=None,
    ):
        self.database_url = database_url

        if connect is None:
            connect = psycopg.connect

        self._connect = connect

        self._initialize_database()

    def _initialize_database(self):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS runtime_control_state (
                control_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS runtime_control_changes (
                change_id TEXT PRIMARY KEY,
                control_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                changed_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_runtime_control_changes_version
            ON runtime_control_changes (
                version
            )
            """,
        ]

        with self._connect(
            self.database_url
        ) as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def get_state(
        self,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM runtime_control_state
                WHERE control_id = %s
                """,
                (
                    "ATHENASEC_RUNTIME",
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            RuntimeControlStateRecord
            .model_validate_json(
                row[0]
            )
        )

    def initialize_state(
        self,
        record,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO runtime_control_state (
                    control_id,
                    version,
                    updated_at,
                    payload
                )
                VALUES (%s, %s, %s, %s)
                ON CONFLICT(control_id)
                DO NOTHING
                """,
                (
                    record.control_id,
                    record.version,
                    record.updated_at,
                    record.model_dump_json(),
                ),
            )

        stored = self.get_state()

        if stored is None:
            raise RuntimeError(
                "Runtime control state "
                "could not be initialized."
            )

        return stored

    def apply_update(
        self,
        state,
        change,
        *,
        expected_version,
    ):
        if (
            state.version
            != expected_version + 1
            or change.version
            != state.version
        ):
            raise ValueError(
                "Runtime control version "
                "transition is invalid."
            )

        try:
            with self._connect(
                self.database_url
            ) as connection:
                row = connection.execute(
                    """
                    SELECT version
                    FROM runtime_control_state
                    WHERE control_id = %s
                    FOR UPDATE
                    """,
                    (
                        state.control_id,
                    ),
                ).fetchone()

                if (
                    row is None
                    or row[0]
                    != expected_version
                ):
                    raise ValueError(
                        "Runtime control state "
                        "changed concurrently."
                    )

                connection.execute(
                    """
                    INSERT INTO runtime_control_changes (
                        change_id,
                        control_id,
                        version,
                        changed_at,
                        payload
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        change.change_id,
                        change.control_id,
                        change.version,
                        change.changed_at,
                        change.model_dump_json(),
                    ),
                )

                cursor = connection.execute(
                    """
                    UPDATE runtime_control_state
                    SET
                        version = %s,
                        updated_at = %s,
                        payload = %s
                    WHERE
                        control_id = %s
                        AND version = %s
                    """,
                    (
                        state.version,
                        state.updated_at,
                        state.model_dump_json(),
                        state.control_id,
                        expected_version,
                    ),
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        "Runtime control state "
                        "changed concurrently."
                    )

        except psycopg.errors.UniqueViolation as exc:
            raise ValueError(
                "Runtime control change_id "
                "already exists."
            ) from exc

        return state

    def list_changes(
        self,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM runtime_control_changes
                ORDER BY
                    version ASC,
                    changed_at ASC,
                    change_id ASC
                """
            ).fetchall()

        return [
            RuntimeControlChangeRecord
            .model_validate_json(
                row[0]
            )
            for row in rows
        ]