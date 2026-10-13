import sqlite3
import psycopg
from datetime import (
    datetime,
    timezone,
)
from pathlib import Path
from typing import Protocol

from app.schemas import (
    AuditRecord,
    IncidentAuditRecord,
)
from psycopg.errors import UniqueViolation

class AuditStore(Protocol):
    def save(
        self,
        record: AuditRecord,
    ) -> AuditRecord:
        ...

    def get(
        self,
        audit_id: str,
    ) -> AuditRecord | None:
        ...

    def list_by_alert_id(
        self,
        alert_id: str,
    ) -> list[AuditRecord]:
        ...

    def save_incident_event(
        self,
        record: IncidentAuditRecord,
    ) -> IncidentAuditRecord:
        ...

    def get_incident_event(
        self,
        audit_id: str,
    ) -> IncidentAuditRecord | None:
        ...

    def list_by_incident_id(
        self,
        incident_id: str,
    ) -> list[IncidentAuditRecord]:
        ...


class InMemoryAuditStore:
    def __init__(self):
        self._records: dict[
            str,
            AuditRecord,
        ] = {}
        self._incident_records: dict[
            str,
            IncidentAuditRecord,
        ] = {}

    def save_incident_event(
        self,
        record: IncidentAuditRecord,
    ) -> IncidentAuditRecord:
        if (
            record.audit_id
            in self._incident_records
        ):
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            )

        self._incident_records[
            record.audit_id
        ] = record

        return record

    def get_incident_event(
        self,
        audit_id: str,
    ) -> IncidentAuditRecord | None:
        return self._incident_records.get(
            audit_id
        )

    def list_by_incident_id(
        self,
        incident_id: str,
    ) -> list[IncidentAuditRecord]:
        records = [
            record
            for record
            in self._incident_records.values()
            if (
                record.incident_id
                == incident_id
            )
        ]

        return sorted(
            records,
            key=lambda record: (
                record.timestamp,
                record.audit_id,
            ),
        )

    def save(
        self,
        record: AuditRecord,
    ) -> AuditRecord:
        if (
            record.audit_id
            in self._records
        ):
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            )

        self._records[
            record.audit_id
        ] = record

        return record

    def get(
        self,
        audit_id: str,
    ) -> AuditRecord | None:
        return self._records.get(
            audit_id
        )

    def list_by_alert_id(
        self,
        alert_id: str,
    ) -> list[AuditRecord]:
        records = [
            record
            for record in self._records.values()
            if record.alert_id == alert_id
        ]

        return sorted(
            records,
            key=lambda record: (
                record.timestamp
            ),
        )


class SQLiteAuditStore:
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
    ) -> sqlite3.Connection:
        return sqlite3.connect(
            self.database_path
        )

    def _get_column_names(
        self,
        connection: sqlite3.Connection,
    ) -> set[str]:
        rows = connection.execute(
            """
            PRAGMA table_info(audit_records)
            """
        ).fetchall()

        return {
            row[1]
            for row in rows
        }

    def _migrate_legacy_table(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        columns = self._get_column_names(
            connection
        )

        if (
            "timestamp"
            not in columns
        ):
            connection.execute(
                """
                ALTER TABLE audit_records
                ADD COLUMN timestamp TEXT
                """
            )

            fallback_timestamp = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

            connection.execute(
                """
                UPDATE audit_records
                SET timestamp = ?
                WHERE timestamp IS NULL
                """,
                (
                    fallback_timestamp,
                ),
            )

    def _initialize_database(
        self,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    audit_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_audit_events (
                    audit_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_audit_events_incident_id
                ON incident_audit_events(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_audit_events_timestamp
                ON incident_audit_events(timestamp)
                """
            )

            self._migrate_legacy_table(
                connection
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_records_alert_id
                ON audit_records(alert_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_records_timestamp
                ON audit_records(timestamp)
                """
            )

    def save_incident_event(
        self,
        record: IncidentAuditRecord,
    ) -> IncidentAuditRecord:
        payload = (
            record.model_dump_json()
        )

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO incident_audit_events (
                        audit_id,
                        incident_id,
                        event_type,
                        entity_type,
                        entity_id,
                        timestamp,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.audit_id,
                        record.incident_id,
                        record.event_type,
                        record.entity_type,
                        record.entity_id,
                        record.timestamp.isoformat(),
                        payload,
                    ),
                )

        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            ) from exc

        return record

    def get_incident_event(
        self,
        audit_id: str,
    ) -> IncidentAuditRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_audit_events
                WHERE audit_id = ?
                """,
                (
                    audit_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentAuditRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_by_incident_id(
        self,
        incident_id: str,
    ) -> list[IncidentAuditRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_audit_events
                WHERE incident_id = ?
                ORDER BY timestamp ASC, audit_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentAuditRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def save(
        self,
        record: AuditRecord,
    ) -> AuditRecord:
        payload = record.model_dump_json()

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO audit_records (
                        audit_id,
                        alert_id,
                        timestamp,
                        payload
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        record.audit_id,
                        record.alert_id,
                        record.timestamp.isoformat(),
                        payload,
                    ),
                )

        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            ) from exc

        return record

    def get(
        self,
        audit_id: str,
    ) -> AuditRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM audit_records
                WHERE audit_id = ?
                """,
                (
                    audit_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return AuditRecord.model_validate_json(
            row[0]
        )

    def list_by_alert_id(
        self,
        alert_id: str,
    ) -> list[AuditRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM audit_records
                WHERE alert_id = ?
                ORDER BY timestamp ASC
                """,
                (
                    alert_id,
                ),
            ).fetchall()

        return [
            AuditRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

class PostgresAuditStore:
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

    def _initialize_database(
        self,
    ) -> None:
        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    audit_id TEXT PRIMARY KEY,
                    alert_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_audit_events (
                    audit_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_audit_events_incident_id
                ON incident_audit_events(incident_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_incident_audit_events_timestamp
                ON incident_audit_events(timestamp)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_records_alert_id
                ON audit_records(alert_id)
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_audit_records_timestamp
                ON audit_records(timestamp)
                """
            )

    def save_incident_event(
        self,
        record: IncidentAuditRecord,
    ) -> IncidentAuditRecord:
        payload = (
            record.model_dump_json()
        )

        try:
            with self._connect(
                self.database_url
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO incident_audit_events (
                        audit_id,
                        incident_id,
                        event_type,
                        entity_type,
                        entity_id,
                        timestamp,
                        payload
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record.audit_id,
                        record.incident_id,
                        record.event_type,
                        record.entity_type,
                        record.entity_id,
                        record.timestamp,
                        payload,
                    ),
                )

        except UniqueViolation as exc:
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            ) from exc

        return record

    def get_incident_event(
        self,
        audit_id: str,
    ) -> IncidentAuditRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM incident_audit_events
                WHERE audit_id = %s
                """,
                (
                    audit_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            IncidentAuditRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_by_incident_id(
        self,
        incident_id: str,
    ) -> list[IncidentAuditRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM incident_audit_events
                WHERE incident_id = %s
                ORDER BY timestamp ASC, audit_id ASC
                """,
                (
                    incident_id,
                ),
            ).fetchall()

        return [
            IncidentAuditRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]

    def save(
        self,
        record: AuditRecord,
    ) -> AuditRecord:
        payload = record.model_dump_json()

        try:
            with self._connect(
                self.database_url
            ) as connection:
                connection.execute(
                    """
                    INSERT INTO audit_records (
                        audit_id,
                        alert_id,
                        timestamp,
                        payload
                    )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        record.audit_id,
                        record.alert_id,
                        record.timestamp.isoformat(),
                        payload,
                    ),
                )

        except UniqueViolation as exc:
            raise ValueError(
                "Audit record with audit_id "
                f"{record.audit_id} "
                "already exists."
            ) from exc

        return record

    def get(
        self,
        audit_id: str,
    ) -> AuditRecord | None:
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM audit_records
                WHERE audit_id = %s
                """,
                (
                    audit_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return (
            AuditRecord
            .model_validate_json(
                row[0]
            )
        )

    def list_by_alert_id(
        self,
        alert_id: str,
    ) -> list[AuditRecord]:
        with self._connect(
            self.database_url
        ) as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM audit_records
                WHERE alert_id = %s
                ORDER BY timestamp ASC
                """,
                (
                    alert_id,
                ),
            ).fetchall()

        return [
            AuditRecord.model_validate_json(
                row[0]
            )
            for row in rows
        ]