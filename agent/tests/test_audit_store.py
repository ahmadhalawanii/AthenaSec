from app.schemas import AuditRecord
from app.services.audit_store import (
    InMemoryAuditStore,
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