from datetime import (
    datetime,
    timezone,
)
from unittest.mock import MagicMock

import pytest

from app.schemas import (
    IncidentAuditRecord,
    IncidentCaseRecord,
)
from app.services.audit_store import (
    InMemoryAuditStore,
    PostgresAuditStore,
    SQLiteAuditStore,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.persistence_config import (
    build_incident_response_store_from_env,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    16,
    0,
    tzinfo=timezone.utc,
)


def make_case() -> IncidentCaseRecord:
    return IncidentCaseRecord(
        case_id="CASE-INC-001",
        incident_id="INC-001",
        investigation_id="INV-001",
        policy_decision_id="PDEC-001",
        status="open",
        reason="Policy did not permit automatic response.",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_audit(
    audit_id: str = "AUD-INC-001",
) -> IncidentAuditRecord:
    return IncidentAuditRecord(
        audit_id=audit_id,
        incident_id="INC-001",
        event_type="policy_decision_recorded",
        entity_type="policy_decision",
        entity_id="PDEC-001",
        message="Policy decision was persisted.",
        details={
            "outcome": "NOT_ALLOWED",
        },
        timestamp=BASE_TIME,
    )


def test_in_memory_response_store_persists_incident_case():
    store = InMemoryIncidentResponseStore()

    case = make_case()

    assert (
        store.save_incident_case(case)
        == case
    )

    assert (
        store.get_incident_case(
            "CASE-INC-001"
        )
        == case
    )


def test_in_memory_response_store_lists_cases_for_incident():
    store = InMemoryIncidentResponseStore()

    case = make_case()

    store.save_incident_case(
        case
    )

    assert (
        store.list_incident_cases(
            "INC-001"
        )
        == [case]
    )

    assert (
        store.list_incident_cases(
            "INC-OTHER"
        )
        == []
    )


def test_sqlite_response_store_persists_incident_case(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-case-test.db"
    )

    first = SQLiteIncidentResponseStore(
        database_path
    )

    first.save_incident_case(
        make_case()
    )

    second = SQLiteIncidentResponseStore(
        database_path
    )

    assert (
        second.get_incident_case(
            "CASE-INC-001"
        )
        == make_case()
    )

    assert (
        second.list_incident_cases(
            "INC-001"
        )
        == [
            make_case(),
        ]
    )


def test_postgres_response_store_initializes_incident_cases():
    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresIncidentResponseStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
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
        "CREATE TABLE IF NOT EXISTS incident_cases"
        in executed_sql
    )


def test_postgres_response_store_saves_incident_case():
    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresIncidentResponseStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    case = make_case()

    store.save_incident_case(
        case
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
        "INSERT INTO incident_cases"
        in sql
    )

    assert (
        "ON CONFLICT (case_id)"
        in sql
    )

    assert (
        parameters[0]
        == "CASE-INC-001"
    )

    assert (
        parameters[1]
        == "INC-001"
    )


def test_in_memory_audit_store_persists_incident_event():
    store = InMemoryAuditStore()

    record = make_audit()

    assert (
        store.save_incident_event(record)
        == record
    )

    assert (
        store.get_incident_event(
            "AUD-INC-001"
        )
        == record
    )


def test_incident_audit_is_append_only():
    store = InMemoryAuditStore()

    store.save_incident_event(
        make_audit()
    )

    with pytest.raises(
        ValueError,
        match="audit_id",
    ):
        store.save_incident_event(
            make_audit()
        )


def test_in_memory_audit_store_lists_incident_timeline():
    store = InMemoryAuditStore()

    first = make_audit(
        "AUD-INC-001"
    )

    second = make_audit(
        "AUD-INC-002"
    ).model_copy(
        update={
            "event_type": (
                "response_action_recorded"
            ),
            "entity_type": (
                "response_action"
            ),
            "entity_id": "ACT-001",
            "timestamp": datetime(
                2026,
                10,
                7,
                16,
                1,
                tzinfo=timezone.utc,
            ),
        }
    )

    store.save_incident_event(
        second
    )

    store.save_incident_event(
        first
    )

    records = (
        store.list_by_incident_id(
            "INC-001"
        )
    )

    assert [
        record.audit_id
        for record in records
    ] == [
        "AUD-INC-001",
        "AUD-INC-002",
    ]


def test_sqlite_audit_store_persists_incident_event(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-incident-audit.db"
    )

    first = SQLiteAuditStore(
        database_path
    )

    first.save_incident_event(
        make_audit()
    )

    second = SQLiteAuditStore(
        database_path
    )

    assert (
        second.get_incident_event(
            "AUD-INC-001"
        )
        == make_audit()
    )

    assert (
        second.list_by_incident_id(
            "INC-001"
        )
        == [
            make_audit(),
        ]
    )


def test_postgres_audit_store_initializes_incident_audit_table():
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

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "CREATE TABLE IF NOT EXISTS incident_audit_events"
        in executed_sql
    )

    assert (
        "idx_incident_audit_events_incident_id"
        in executed_sql
    )


def test_postgres_audit_store_saves_incident_event():
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

    record = make_audit()

    store.save_incident_event(
        record
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
        "INSERT INTO incident_audit_events"
        in sql
    )

    assert parameters[0] == (
        "AUD-INC-001"
    )

    assert parameters[1] == (
        "INC-001"
    )


def test_response_store_builder_uses_sqlite(
    monkeypatch,
):
    response_store_class = MagicMock()

    monkeypatch.setenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        "sqlite",
    )

    monkeypatch.setenv(
        "ATHENASEC_DB_PATH",
        "data/athenasec-test.db",
    )

    result = (
        build_incident_response_store_from_env(
            sqlite_response_store_class=(
                response_store_class
            ),
        )
    )

    response_store_class.assert_called_once_with(
        "data/athenasec-test.db"
    )

    assert (
        result
        is response_store_class.return_value
    )


def test_response_store_builder_uses_postgres(
    monkeypatch,
):
    response_store_class = MagicMock()

    monkeypatch.delenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        raising=False,
    )

    monkeypatch.setenv(
        "ATHENASEC_DATABASE_URL",
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
    )

    result = (
        build_incident_response_store_from_env(
            postgres_response_store_class=(
                response_store_class
            ),
        )
    )

    response_store_class.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    assert (
        result
        is response_store_class.return_value
    )