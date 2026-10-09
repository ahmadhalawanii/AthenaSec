import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Protocol

import psycopg

from app.schemas import (
    ContainmentExpiryRecord,
)


def _validate_claim(
    *,
    now,
    worker_id,
    lease_seconds,
    limit,
):
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ValueError(
            "Claim time must be timezone-aware."
        )

    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("Worker ID is required.")

    if (
        type(lease_seconds) is not int
        or not 1 <= lease_seconds <= 3600
    ):
        raise ValueError(
            "Lease must be 1-3600 seconds."
        )

    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Claim limit must be 1-100.")

    return now.astimezone(timezone.utc)


def _claimed_record(
    record,
    *,
    now,
    worker_id,
    lease_seconds,
):
    if (
        record.status != "PENDING"
        or record.due_at.tzinfo is None
        or record.due_at.astimezone(timezone.utc) > now
    ):
        raise RuntimeError(
            "Expiry is not eligible for claiming."
        )

    return record.model_copy(
        update={
            "status": "CLAIMED",
            "attempt_count": record.attempt_count + 1,
            "lease_owner": worker_id,
            "lease_expires_at": (
                now + timedelta(seconds=lease_seconds)
            ),
            "updated_at": now,
        }
    )


def _validate_finish(
    *,
    now,
    worker_id,
    attempt_count,
    status,
    error,
):
    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ValueError(
            "Finish time must be timezone-aware."
        )

    if not isinstance(worker_id, str) or not worker_id.strip():
        raise ValueError("Worker ID is required.")

    if type(attempt_count) is not int or attempt_count < 1:
        raise ValueError("Attempt count must be positive.")

    if status not in {"COMPLETED", "FAILED"}:
        raise ValueError("Unsupported terminal expiry status.")

    if status == "FAILED" and (
        not isinstance(error, str)
        or not error.strip()
    ):
        raise ValueError(
            "Failed expiry requires a safe error reason."
        )

    if status == "COMPLETED" and error is not None:
        raise ValueError(
            "Completed expiry cannot contain an error."
        )

    return now.astimezone(timezone.utc)


def _finish_record(
    record,
    *,
    now,
    worker_id,
    attempt_count,
    status,
    error,
):
    if (
        record.status != "CLAIMED"
        or record.lease_owner != worker_id
        or record.attempt_count != attempt_count
        or record.lease_expires_at is None
        or record.lease_expires_at.tzinfo is None
        or record.lease_expires_at <= now
    ):
        return None

    return record.model_copy(
        update={
            "status": status,
            "lease_owner": None,
            "lease_expires_at": None,
            "completed_at": (
                now if status == "COMPLETED" else None
            ),
            "last_error": error,
            "updated_at": now,
        }
    )


class ContainmentExpiryStore(
    Protocol
):
    def finish_claimed_expiry(
        self,
        *,
        expiry_id: str,
        worker_id: str,
        attempt_count: int,
        status: str,
        now: datetime,
        error: str | None = None,
    ) -> ContainmentExpiryRecord | None:
        ...

    def claim_due_expiries(
        self,
        *,
        now: datetime,
        worker_id: str,
        lease_seconds: int = 120,
        limit: int = 25,
    ) -> list[ContainmentExpiryRecord]:
        ...

    def create_expiry_if_absent(
        self,
        record: ContainmentExpiryRecord,
    ) -> ContainmentExpiryRecord:
        ...

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
        self._claim_lock = RLock()

    def finish_claimed_expiry(
        self,
        *,
        expiry_id,
        worker_id,
        attempt_count,
        status,
        now,
        error=None,
    ):
        now = _validate_finish(
            now=now,
            worker_id=worker_id,
            attempt_count=attempt_count,
            status=status,
            error=error,
        )

        with self._claim_lock:
            current = self._records.get(expiry_id)

            if current is None:
                return None

            updated = _finish_record(
                current,
                now=now,
                worker_id=worker_id,
                attempt_count=attempt_count,
                status=status,
                error=error,
            )

            if updated is not None:
                self._records[expiry_id] = updated

            return updated

    def claim_due_expiries(
        self,
        *,
        now,
        worker_id,
        lease_seconds=120,
        limit=25,
    ):
        now = _validate_claim(
            now=now,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            limit=limit,
        )

        with self._claim_lock:
            eligible = sorted(
                (
                    record
                    for record in self._records.values()
                    if (
                        record.status == "PENDING"
                        and record.due_at <= now
                    )
                ),
                key=lambda record: (
                    record.due_at,
                    record.expiry_id,
                ),
            )[:limit]

            claimed = [
                _claimed_record(
                    record,
                    now=now,
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )
                for record in eligible
            ]

            for record in claimed:
                self._records[record.expiry_id] = record

            return claimed

    def create_expiry_if_absent(
        self,
        record,
    ):
        return self._records.setdefault(
            record.expiry_id,
            record,
        )

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

    def finish_claimed_expiry(
        self,
        *,
        expiry_id,
        worker_id,
        attempt_count,
        status,
        now,
        error=None,
    ):
        now = _validate_finish(
            now=now,
            worker_id=worker_id,
            attempt_count=attempt_count,
            status=status,
            error=error,
        )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT payload FROM containment_expiries
                WHERE expiry_id = ?
                """,
                (expiry_id,),
            ).fetchone()

            if row is None:
                connection.commit()
                return None

            current = (
                ContainmentExpiryRecord.model_validate_json(
                    row[0]
                )
            )

            updated = _finish_record(
                current,
                now=now,
                worker_id=worker_id,
                attempt_count=attempt_count,
                status=status,
                error=error,
            )

            if updated is None:
                connection.commit()
                return None

            cursor = connection.execute(
                """
                UPDATE containment_expiries
                SET status = ?,
                    payload = ?
                WHERE expiry_id = ?
                  AND status = 'CLAIMED'
                """,
                (
                    status,
                    updated.model_dump_json(),
                    expiry_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Expiry completion update failed."
                )

            connection.commit()
            return updated

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def claim_due_expiries(
        self,
        *,
        now,
        worker_id,
        lease_seconds=120,
        limit=25,
    ):
        now = _validate_claim(
            now=now,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            limit=limit,
        )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            rows = connection.execute(
                """
                SELECT expiry_id, payload
                FROM containment_expiries
                WHERE status = 'PENDING'
                  AND due_at <= ?
                ORDER BY due_at ASC, expiry_id ASC
                LIMIT ?
                """,
                (now.isoformat(), limit),
            ).fetchall()

            claimed = []

            for expiry_id, payload in rows:
                original = (
                    ContainmentExpiryRecord.model_validate_json(
                        payload
                    )
                )

                record = _claimed_record(
                    original,
                    now=now,
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )

                cursor = connection.execute(
                    """
                    UPDATE containment_expiries
                    SET status = 'CLAIMED',
                        payload = ?
                    WHERE expiry_id = ?
                      AND status = 'PENDING'
                    """,
                    (
                        record.model_dump_json(),
                        expiry_id,
                    ),
                )

                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "Expiry claim update failed."
                    )

                claimed.append(record)

            connection.commit()
            return claimed

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def create_expiry_if_absent(
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
                DO NOTHING
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

        persisted = self.get_expiry(
            record.expiry_id
        )

        if persisted is None:
            raise RuntimeError(
                "Expiry creation did not persist."
            )

        return persisted

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

    def finish_claimed_expiry(
        self,
        *,
        expiry_id,
        worker_id,
        attempt_count,
        status,
        now,
        error=None,
    ):
        now = _validate_finish(
            now=now,
            worker_id=worker_id,
            attempt_count=attempt_count,
            status=status,
            error=error,
        )

        with self._connect(self.database_url) as connection:
            row = connection.execute(
                """
                SELECT payload FROM containment_expiries
                WHERE expiry_id = %s
                FOR UPDATE
                """,
                (expiry_id,),
            ).fetchone()

            if row is None:
                return None

            current = (
                ContainmentExpiryRecord.model_validate_json(
                    row[0]
                )
            )

            updated = _finish_record(
                current,
                now=now,
                worker_id=worker_id,
                attempt_count=attempt_count,
                status=status,
                error=error,
            )

            if updated is None:
                return None

            cursor = connection.execute(
                """
                UPDATE containment_expiries
                SET status = %s,
                    payload = %s
                WHERE expiry_id = %s
                  AND status = 'CLAIMED'
                """,
                (
                    status,
                    updated.model_dump_json(),
                    expiry_id,
                ),
            )

            if cursor.rowcount != 1:
                raise RuntimeError(
                    "Expiry completion update failed."
                )

            return updated

    def claim_due_expiries(
        self,
        *,
        now,
        worker_id,
        lease_seconds=120,
        limit=25,
    ):
        now = _validate_claim(
            now=now,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            limit=limit,
        )

        claimed = []

        with self._connect(self.database_url) as connection:
            rows = connection.execute(
                """
                SELECT expiry_id, payload
                FROM containment_expiries
                WHERE status = 'PENDING'
                  AND due_at <= %s
                ORDER BY due_at ASC, expiry_id ASC
                LIMIT %s
                FOR UPDATE SKIP LOCKED
                """,
                (now, limit),
            ).fetchall()

            for expiry_id, payload in rows:
                original = (
                    ContainmentExpiryRecord.model_validate_json(
                        payload
                    )
                )

                record = _claimed_record(
                    original,
                    now=now,
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )

                cursor = connection.execute(
                    """
                    UPDATE containment_expiries
                    SET status = 'CLAIMED',
                        payload = %s
                    WHERE expiry_id = %s
                      AND status = 'PENDING'
                    """,
                    (
                        record.model_dump_json(),
                        expiry_id,
                    ),
                )

                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "Expiry claim update failed."
                    )

                claimed.append(record)

        return claimed

    def create_expiry_if_absent(
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
                    %s, %s, %s, %s, %s, %s, %s
                )
                ON CONFLICT(expiry_id)
                DO NOTHING
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

        persisted = self.get_expiry(
            record.expiry_id
        )

        if persisted is None:
            raise RuntimeError(
                "Expiry creation did not persist."
            )

        return persisted

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
