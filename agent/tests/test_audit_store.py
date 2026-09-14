from app.schemas import AuditRecord
from app.services.audit_store import (
    InMemoryAuditStore,
    PostgresAuditStore,
)

def test_audit_store_saves_record():
    store = InMemoryAuditStore()

    record = AuditRecord(
        audit_id="AUD-001",
        alert_id="ALT-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={
            "source": "wazuh",
        },
    )

    store.save(
        record
    )

    saved = store.get(
        "AUD-001"
    )

    assert saved is not None

    assert saved.audit_id == "AUD-001"

    assert (
        saved.alert_id
        == "ALT-001"
    )

    assert (
        saved.event_type
        == "investigation_created"
    )


def test_audit_store_lists_records_for_alert():
    store = InMemoryAuditStore()

    first = AuditRecord(
        audit_id="AUD-001",
        alert_id="ALT-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={},
    )

    second = AuditRecord(
        audit_id="AUD-002",
        alert_id="ALT-001",
        event_type="policy_evaluated",
        message="Policy was evaluated.",
        details={},
    )

    third = AuditRecord(
        audit_id="AUD-003",
        alert_id="ALT-OTHER",
        event_type="case_created",
        message="Case was created.",
        details={},
    )

    store.save(
        first
    )

    store.save(
        second
    )

    store.save(
        third
    )

    records = store.list_by_alert_id(
        "ALT-001"
    )

    assert len(
        records
    ) == 2

    assert [
        record.audit_id
        for record in records
    ] == [
        "AUD-001",
        "AUD-002",
    ]

from app.services.audit_store import (
    SQLiteAuditStore,
)


def test_sqlite_audit_store_persists_records(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-audit.db"
    )

    first_store = SQLiteAuditStore(
        database_path
    )

    record = AuditRecord(
        audit_id="AUD-SQL-001",
        alert_id="ALT-SQL-001",
        event_type="case_created",
        message="Case was created.",
        details={
            "case_id": "CASE-001",
        },
    )

    first_store.save(
        record
    )

    second_store = SQLiteAuditStore(
        database_path
    )

    loaded = second_store.get(
        "AUD-SQL-001"
    )

    assert loaded is not None

    assert (
        loaded.audit_id
        == "AUD-SQL-001"
    )

    assert (
        loaded.alert_id
        == "ALT-SQL-001"
    )

    records = (
        second_store.list_by_alert_id(
            "ALT-SQL-001"
        )
    )

    assert len(
        records
    ) == 1

    assert (
        records[0].event_type
        == "case_created"
    )


def test_audit_record_has_timestamp():
    store = InMemoryAuditStore()

    record = AuditRecord(
        audit_id="AUD-TIME-001",
        alert_id="ALT-TIME-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={},
    )

    store.save(
        record
    )

    saved = store.get(
        "AUD-TIME-001"
    )

    assert saved is not None

    assert saved.timestamp is not None


def test_in_memory_audit_store_rejects_duplicate_audit_id():
    store = InMemoryAuditStore()

    first = AuditRecord(
        audit_id="AUD-DUP-001",
        alert_id="ALT-001",
        event_type="investigation_created",
        message="First event.",
        details={},
    )

    second = AuditRecord(
        audit_id="AUD-DUP-001",
        alert_id="ALT-001",
        event_type="policy_evaluated",
        message="Second event.",
        details={},
    )

    store.save(
        first
    )

    try:
        store.save(
            second
        )

        assert False, (
            "Expected duplicate audit_id "
            "to be rejected."
        )

    except ValueError as exc:
        assert (
            "audit_id"
            in str(exc)
        )


def test_sqlite_audit_store_rejects_duplicate_audit_id(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-audit-append-only.db"
    )

    store = SQLiteAuditStore(
        database_path
    )

    first = AuditRecord(
        audit_id="AUD-DUP-SQL-001",
        alert_id="ALT-001",
        event_type="investigation_created",
        message="First event.",
        details={},
    )

    second = AuditRecord(
        audit_id="AUD-DUP-SQL-001",
        alert_id="ALT-001",
        event_type="policy_evaluated",
        message="Second event.",
        details={},
    )

    store.save(
        first
    )

    try:
        store.save(
            second
        )

        assert False, (
            "Expected duplicate audit_id "
            "to be rejected."
        )

    except ValueError as exc:
        assert (
            "audit_id"
            in str(exc)
        )

def test_sqlite_audit_store_migrates_legacy_table(
    tmp_path,
):
    import sqlite3

    database_path = (
        tmp_path
        / "athenasec-legacy-audit.db"
    )

    connection = sqlite3.connect(
        database_path
    )

    connection.execute(
        """
        CREATE TABLE audit_records (
            audit_id TEXT PRIMARY KEY,
            alert_id TEXT NOT NULL,
            payload TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()

    store = SQLiteAuditStore(
        database_path
    )

    record = AuditRecord(
        audit_id="AUD-MIGRATE-001",
        alert_id="ALT-MIGRATE-001",
        event_type="investigation_created",
        message=(
            "Investigation was created."
        ),
        details={},
    )

    store.save(
        record
    )

    loaded = store.get(
        "AUD-MIGRATE-001"
    )

    assert loaded is not None

    assert loaded.timestamp is not None

def test_postgres_audit_store_initializes_table():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connect.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "CREATE TABLE IF NOT EXISTS audit_records"
        in executed_sql
    )

    assert (
        "idx_audit_records_alert_id"
        in executed_sql
    )

    assert (
        "idx_audit_records_timestamp"
        in executed_sql
    )

def test_postgres_audit_store_saves_record():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    record = AuditRecord(
        audit_id="AUD-PG-001",
        alert_id="ALT-PG-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={
            "source": "wazuh",
        },
    )

    result = store.save(
        record
    )

    assert result == record

    assert (
        connection.execute.call_count
        == 1
    )

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "INSERT INTO audit_records"
        in sql
    )

    assert parameters[0] == (
        "AUD-PG-001"
    )

    assert parameters[1] == (
        "ALT-PG-001"
    )

    assert parameters[2] == (
        record.timestamp.isoformat()
    )

    assert parameters[3] == (
        record.model_dump_json()
    )

def test_postgres_audit_store_gets_record():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    record = AuditRecord(
        audit_id="AUD-PG-001",
        alert_id="ALT-PG-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={
            "source": "wazuh",
        },
    )

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        record.model_dump_json(),
    )

    stored = store.get(
        "AUD-PG-001"
    )

    assert stored == record

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "SELECT payload"
        in sql
    )

    assert (
        "FROM audit_records"
        in sql
    )

    assert (
        "WHERE audit_id = %s"
        in sql
    )

    assert parameters == (
        "AUD-PG-001",
    )

def test_postgres_audit_store_lists_records_for_alert():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    first = AuditRecord(
        audit_id="AUD-PG-001",
        alert_id="ALT-PG-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={},
    )

    second = AuditRecord(
        audit_id="AUD-PG-002",
        alert_id="ALT-PG-001",
        event_type="policy_evaluated",
        message="Policy was evaluated.",
        details={},
    )

    (
        connection
        .execute
        .return_value
        .fetchall
        .return_value
    ) = [
        (
            first.model_dump_json(),
        ),
        (
            second.model_dump_json(),
        ),
    ]

    records = store.list_by_alert_id(
        "ALT-PG-001"
    )

    assert records == [
        first,
        second,
    ]

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "SELECT payload"
        in sql
    )

    assert (
        "FROM audit_records"
        in sql
    )

    assert (
        "WHERE alert_id = %s"
        in sql
    )

    assert (
        "ORDER BY timestamp ASC"
        in sql
    )

    assert parameters == (
        "ALT-PG-001",
    )

def test_postgres_audit_store_rejects_duplicate_audit_id():
    from unittest.mock import MagicMock

    from psycopg.errors import UniqueViolation

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    connection.execute.side_effect = (
        UniqueViolation(
            "duplicate key"
        )
    )

    record = AuditRecord(
        audit_id="AUD-DUP-PG-001",
        alert_id="ALT-PG-001",
        event_type="investigation_created",
        message="Investigation was created.",
        details={},
    )

    try:
        store.save(
            record
        )

        assert False, (
            "Expected duplicate audit_id "
            "to be rejected."
        )

    except ValueError as exc:
        assert (
            "audit_id"
            in str(exc)
        )

def test_postgres_audit_store_uses_psycopg_by_default(
    monkeypatch,
):
    from unittest.mock import MagicMock

    import psycopg

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    monkeypatch.setattr(
        psycopg,
        "connect",
        connect,
    )

    PostgresAuditStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    connect.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )