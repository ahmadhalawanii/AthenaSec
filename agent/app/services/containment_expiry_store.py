import sqlite3
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import (
    ContainmentExpiryRecord,
)


class ContainmentExpiryStore(
    Protocol
):
    def save_expiry(
        self,
        record: ContainmentExpiryRecord,
    ) -> ContainmentExpiryRecord:
        ...

    def get_expiry(
        self,
        expiry_id: str,
    ) -> (
        ContainmentExpiryRecord
        | None
    ):
        ...

    def list_due_expiries(
        self,
        *,
        now,
        limit: int = 100,
    ) -> list[
        ContainmentExpiryRecord
    ]:
        ...


class InMemoryContainmentExpiryStore:
    def __init__(self):
        self._records = {}

    def save_expiry(
        self,
        record,
    ):
        self._records[
            record.expiry_id
        ] = record

        return record

    def get_expiry(
        self,
        expiry_id,
    ):
        return self._records.get(
            expiry_id
        )

    def list_due_expiries(
        self,
        *,
        now,
        limit=100,
    ):
        if limit < 1:
            raise ValueError(
                "Containment expiry limit "
                "must be positive."
            )

        records = [
            record
            for record
            in self._records.values()
            if (
                record.status
                == "PENDING"
                and record.due_at
                <= now
            )
        ]

        records.sort(
            key=lambda record: (
                record.due_at,
                record.expiry_id,
            )
        )

        return records[
            :limit
        ]


class SQLiteContainmentExpiryStore:
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

    def _connect(
        self,
    ):
        return sqlite3.connect(
            self.database_path
        )

    def _initialize_database(
        self,
    ):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS
            containment_expiries (
                expiry_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                response_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                due_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_containment_expiries_due
            ON containment_expiries (
                status,
                due_at
            )
            """,
        ]

        with self._connect() as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def save_expiry(
        self,
        record,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO containment_expiries (
                    expiry_id,
                    incident_id,
                    proposed_action_id,
                    response_action_id,
                    status,
                    due_at,
                    payload
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(expiry_id)
                DO UPDATE SET
                    incident_id = excluded.incident_id,
                    proposed_action_id = excluded.proposed_action_id,
                    response_action_id = excluded.response_action_id,
                    status = excluded.status,
                    due_at = excluded.due_at,
                    payload = excluded.payload
                """,
                (
                    record.expiry_id,
                    record.incident_id,
                    record.proposed_action_id,
                    record.response_action_id,
                    record.status,
                    record.due_at.isoformat(),
                    record.model_dump_json(),
                ),
            )

        return record

    def get_expiry(
        self,
        expiry_id,
    ):
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM containment_expiries
                WHERE expiry_id = ?
                """,
                (
                    expiry_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            ContainmentExpiryRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_due_expiries(
        self,
        *,
        now,
        limit=100,
    ):
        if limit < 1:
            raise ValueError(
                "Containment expiry limit "
                "must be positive."
            )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM containment_expiries
                WHERE
                    status = 'PENDING'
                    AND due_at <= ?
                ORDER BY
                    due_at ASC,
                    expiry_id ASC
                LIMIT ?
                """,
                (
                    now.isoformat(),
                    limit,
                ),
            ).fetchall()

        return [
            (
                ContainmentExpiryRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]


class PostgresContainmentExpiryStore:
    def __init__(
        self,
        database_url: str,
        *,
        connect=None,
    ):
        self.database_url = database_url

        self._connect = (
            connect
            if connect is not None
            else psycopg.connect
        )

        self._initialize_database()

    def _initialize_database(
        self,
    ):
        statements = [
            """
            CREATE TABLE IF NOT EXISTS
            containment_expiries (
                expiry_id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                proposed_action_id TEXT NOT NULL,
                response_action_id TEXT NOT NULL,
                status TEXT NOT NULL,
                due_at TIMESTAMPTZ NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_containment_expiries_due
            ON containment_expiries (
                status,
                due_at
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

    def save_expiry(
        self,
        record,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO containment_expiries (
                    expiry_id,
                    incident_id,
                    proposed_action_id,
                    response_action_id,
                    status,
                    due_at,
                    payload
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                ON CONFLICT(expiry_id)
                DO UPDATE SET
                    incident_id = EXCLUDED.incident_id,
                    proposed_action_id = EXCLUDED.proposed_action_id,
                    response_action_id = EXCLUDED.response_action_id,
                    status = EXCLUDED.status,
                    due_at = EXCLUDED.due_at,
                    payload = EXCLUDED.payload
                """,
                (
                    record.expiry_id,
                    record.incident_id,
                    record.proposed_action_id,
                    record.response_action_id,
                    record.status,
                    record.due_at,
                    record.model_dump_json(),
                ),
            )

        return record

    def get_expiry(
        self,
        expiry_id,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM containment_expiries
                WHERE expiry_id = %s
                """,
                (
                    expiry_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            ContainmentExpiryRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_due_expiries(
        self,
        *,
        now,
        limit=100,
    ):
        if limit < 1:
            raise ValueError(
                "Containment expiry limit "
                "must be positive."
            )

        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM containment_expiries
                WHERE
                    status = 'PENDING'
                    AND due_at <= %s
                ORDER BY
                    due_at ASC,
                    expiry_id ASC
                LIMIT %s
                """,
                (
                    now,
                    limit,
                ),
            ).fetchall()

        return [
            (
                ContainmentExpiryRecord
                .model_validate_json(
                    row[0]
                )
            )
            for row in rows
        ]