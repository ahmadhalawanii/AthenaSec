import json
import sqlite3
from pathlib import Path

import psycopg

from app.services.target_protection import (
    TargetProtectionSnapshot,
)


CONTROL_ID = (
    "ATHENASEC_TARGET_PROTECTION"
)


def _snapshot_payload(
    snapshot,
):
    return json.dumps(
        {
            "version": snapshot.version,
            "protected_ips": list(
                snapshot.protected_ips
            ),
            "allowlisted_ips": list(
                snapshot.allowlisted_ips
            ),
            "protected_accounts": list(
                snapshot.protected_accounts
            ),
            "allowlisted_accounts": list(
                snapshot.allowlisted_accounts
            ),
            "protected_endpoints": list(
                snapshot.protected_endpoints
            ),
            "allowlisted_endpoints": list(
                snapshot.allowlisted_endpoints
            ),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _snapshot_from_payload(
    payload,
):
    value = json.loads(
        payload
    )

    return TargetProtectionSnapshot(
        version=int(
            value["version"]
        ),
        protected_ips=tuple(
            value["protected_ips"]
        ),
        allowlisted_ips=tuple(
            value["allowlisted_ips"]
        ),
        protected_accounts=tuple(
            value["protected_accounts"]
        ),
        allowlisted_accounts=tuple(
            value["allowlisted_accounts"]
        ),
        protected_endpoints=tuple(
            value["protected_endpoints"]
        ),
        allowlisted_endpoints=tuple(
            value["allowlisted_endpoints"]
        ),
    )


class InMemoryTargetProtectionStore:
    def __init__(self):
        self._snapshot = None
        self._changes = []

    def get_snapshot(
        self,
    ):
        return self._snapshot

    def initialize_snapshot(
        self,
        snapshot,
    ):
        if self._snapshot is None:
            self._snapshot = snapshot

        return self._snapshot

    def apply_update(
        self,
        snapshot,
        *,
        expected_version,
        change_id,
        changed_at,
        changed_by,
        reason,
    ):
        current = self._snapshot

        if (
            current is None
            or current.version
            != expected_version
        ):
            raise ValueError(
                "Target protection state "
                "changed concurrently."
            )

        if (
            snapshot.version
            != expected_version + 1
        ):
            raise ValueError(
                "Target protection version "
                "transition is invalid."
            )

        if any(
            change[
                "change_id"
            ] == change_id
            for change
            in self._changes
        ):
            raise ValueError(
                "Target protection change_id "
                "already exists."
            )

        self._changes.append(
            {
                "change_id": change_id,
                "version": (
                    snapshot.version
                ),
                "changed_at": changed_at,
                "changed_by": changed_by,
                "reason": reason,
                "payload": (
                    _snapshot_payload(
                        snapshot
                    )
                ),
            }
        )

        self._snapshot = snapshot

        return snapshot

    def list_changes(
        self,
    ):
        return list(
            self._changes
        )


class SQLiteTargetProtectionStore:
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
            target_protection_state (
                control_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS
            target_protection_changes (
                change_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_target_protection_changes_version
            ON target_protection_changes (
                version
            )
            """,
        ]

        with self._connect() as connection:
            for statement in statements:
                connection.execute(
                    statement
                )

    def get_snapshot(
        self,
    ):
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM target_protection_state
                WHERE control_id = ?
                """,
                (
                    CONTROL_ID,
                ),
            ).fetchone()

        if row is None:
            return None

        return _snapshot_from_payload(
            row[0]
        )

    def initialize_snapshot(
        self,
        snapshot,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE
                INTO target_protection_state (
                    control_id,
                    version,
                    payload
                )
                VALUES (?, ?, ?)
                """,
                (
                    CONTROL_ID,
                    snapshot.version,
                    _snapshot_payload(
                        snapshot
                    ),
                ),
            )

        stored = self.get_snapshot()

        if stored is None:
            raise RuntimeError(
                "Target protection state "
                "could not be initialized."
            )

        return stored

    def apply_update(
        self,
        snapshot,
        *,
        expected_version,
        change_id,
        changed_at,
        changed_by,
        reason,
    ):
        if (
            snapshot.version
            != expected_version + 1
        ):
            raise ValueError(
                "Target protection version "
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
                    FROM target_protection_state
                    WHERE control_id = ?
                    """,
                    (
                        CONTROL_ID,
                    ),
                ).fetchone()

                if (
                    row is None
                    or row[0]
                    != expected_version
                ):
                    raise ValueError(
                        "Target protection state "
                        "changed concurrently."
                    )

                connection.execute(
                    """
                    INSERT INTO
                    target_protection_changes (
                        change_id,
                        version,
                        changed_at,
                        changed_by,
                        reason,
                        payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        change_id,
                        snapshot.version,
                        changed_at.isoformat(),
                        changed_by,
                        reason,
                        _snapshot_payload(
                            snapshot
                        ),
                    ),
                )

                cursor = connection.execute(
                    """
                    UPDATE target_protection_state
                    SET
                        version = ?,
                        payload = ?
                    WHERE
                        control_id = ?
                        AND version = ?
                    """,
                    (
                        snapshot.version,
                        _snapshot_payload(
                            snapshot
                        ),
                        CONTROL_ID,
                        expected_version,
                    ),
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        "Target protection state "
                        "changed concurrently."
                    )

        except sqlite3.IntegrityError as exc:
            raise ValueError(
                "Target protection change_id "
                "already exists."
            ) from exc

        return snapshot

    def list_changes(
        self,
    ):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    change_id,
                    version,
                    changed_at,
                    changed_by,
                    reason,
                    payload
                FROM target_protection_changes
                ORDER BY
                    version ASC,
                    changed_at ASC,
                    change_id ASC
                """
            ).fetchall()

        return [
            {
                "change_id": row[0],
                "version": row[1],
                "changed_at": row[2],
                "changed_by": row[3],
                "reason": row[4],
                "payload": row[5],
            }
            for row in rows
        ]


class PostgresTargetProtectionStore:
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
            target_protection_state (
                control_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS
            target_protection_changes (
                change_id TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                changed_at TIMESTAMPTZ NOT NULL,
                changed_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX IF NOT EXISTS
            idx_target_protection_changes_version
            ON target_protection_changes (
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

    def get_snapshot(
        self,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM target_protection_state
                WHERE control_id = %s
                """,
                (
                    CONTROL_ID,
                ),
            ).fetchone()

        if row is None:
            return None

        return _snapshot_from_payload(
            row[0]
        )

    def initialize_snapshot(
        self,
        snapshot,
    ):
        with self._connect(
            self.database_url
        ) as connection:
            connection.execute(
                """
                INSERT INTO target_protection_state (
                    control_id,
                    version,
                    payload
                )
                VALUES (%s, %s, %s)
                ON CONFLICT(control_id)
                DO NOTHING
                """,
                (
                    CONTROL_ID,
                    snapshot.version,
                    _snapshot_payload(
                        snapshot
                    ),
                ),
            )

        stored = self.get_snapshot()

        if stored is None:
            raise RuntimeError(
                "Target protection state "
                "could not be initialized."
            )

        return stored

    def apply_update(
        self,
        snapshot,
        *,
        expected_version,
        change_id,
        changed_at,
        changed_by,
        reason,
    ):
        if (
            snapshot.version
            != expected_version + 1
        ):
            raise ValueError(
                "Target protection version "
                "transition is invalid."
            )

        try:
            with self._connect(
                self.database_url
            ) as connection:
                row = connection.execute(
                    """
                    SELECT version
                    FROM target_protection_state
                    WHERE control_id = %s
                    FOR UPDATE
                    """,
                    (
                        CONTROL_ID,
                    ),
                ).fetchone()

                if (
                    row is None
                    or row[0]
                    != expected_version
                ):
                    raise ValueError(
                        "Target protection state "
                        "changed concurrently."
                    )

                connection.execute(
                    """
                    INSERT INTO
                    target_protection_changes (
                        change_id,
                        version,
                        changed_at,
                        changed_by,
                        reason,
                        payload
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        change_id,
                        snapshot.version,
                        changed_at,
                        changed_by,
                        reason,
                        _snapshot_payload(
                            snapshot
                        ),
                    ),
                )

                cursor = connection.execute(
                    """
                    UPDATE target_protection_state
                    SET
                        version = %s,
                        payload = %s
                    WHERE
                        control_id = %s
                        AND version = %s
                    """,
                    (
                        snapshot.version,
                        _snapshot_payload(
                            snapshot
                        ),
                        CONTROL_ID,
                        expected_version,
                    ),
                )

                if cursor.rowcount != 1:
                    raise ValueError(
                        "Target protection state "
                        "changed concurrently."
                    )

        except psycopg.errors.UniqueViolation as exc:
            raise ValueError(
                "Target protection change_id "
                "already exists."
            ) from exc

        return snapshot