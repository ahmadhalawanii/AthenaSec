from datetime import (
    datetime,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    IncidentRecord,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)


def make_incident() -> IncidentRecord:
    timestamp = datetime(
        2026,
        10,
        7,
        16,
        0,
        tzinfo=timezone.utc,
    )

    return IncidentRecord(
        incident_id="INC-001",
        title="SSH brute-force activity",
        status="open",
        created_at=timestamp,
        updated_at=timestamp,
    )


def test_in_memory_store_saves_and_gets_incident():
    store = InMemoryInvestigationStore()

    incident = make_incident()

    saved = store.save_incident(
        incident
    )

    assert saved == incident

    stored = store.get_incident(
        "INC-001"
    )

    assert stored == incident


def test_sqlite_store_persists_incident_across_instances(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-incident-test.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    incident = make_incident()

    first_store.save_incident(
        incident
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    stored = second_store.get_incident(
        "INC-001"
    )

    assert stored == incident


def test_postgres_store_initializes_incidents_table():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresInvestigationStore(
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
        "CREATE TABLE IF NOT EXISTS incidents"
        in executed_sql
    )


def test_postgres_store_saves_incident():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    incident = make_incident()

    saved = store.save_incident(
        incident
    )

    assert saved == incident

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
        "INSERT INTO incidents"
        in sql
    )

    assert (
        "ON CONFLICT (incident_id)"
        in sql
    )

    assert (
        parameters[0]
        == "INC-001"
    )


def test_postgres_store_gets_incident():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    incident = make_incident()

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        incident.model_dump_json(),
    )

    stored = store.get_incident(
        "INC-001"
    )

    assert stored == incident

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
        "FROM incidents"
        in sql
    )

    assert (
        "WHERE incident_id = %s"
        in sql
    )

    assert parameters == (
        "INC-001",
    )