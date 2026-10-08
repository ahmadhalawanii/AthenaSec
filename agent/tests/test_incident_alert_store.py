from datetime import (
    datetime,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    IncidentAlertRecord,
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


def make_incident_alert(
    alert_id: str = "ALT-WAZUH-001",
    minute: int = 1,
) -> IncidentAlertRecord:
    return IncidentAlertRecord(
        incident_id="INC-001",
        alert_id=alert_id,
        source="wazuh",
        event_text="Repeated SSH authentication failures.",
        metadata={
            "agent_id": "001",
            "source_ip": "203.0.113.10",
            "rule_id": "5712",
        },
        observed_at=datetime(
            2026,
            10,
            7,
            16,
            minute,
            tzinfo=timezone.utc,
        ),
    )


def test_in_memory_store_saves_and_gets_incident_alert():
    store = InMemoryInvestigationStore()

    alert = make_incident_alert()

    saved = store.save_incident_alert(
        alert
    )

    assert saved == alert

    stored = store.get_incident_alert(
        "ALT-WAZUH-001"
    )

    assert stored == alert


def test_in_memory_store_lists_alerts_for_incident():
    store = InMemoryInvestigationStore()

    later = make_incident_alert(
        alert_id="ALT-WAZUH-002",
        minute=2,
    )

    earlier = make_incident_alert(
        alert_id="ALT-WAZUH-001",
        minute=1,
    )

    store.save_incident_alert(
        later
    )

    store.save_incident_alert(
        earlier
    )

    alerts = store.list_incident_alerts(
        "INC-001"
    )

    assert [
        alert.alert_id
        for alert in alerts
    ] == [
        "ALT-WAZUH-001",
        "ALT-WAZUH-002",
    ]


def test_sqlite_store_persists_incident_alerts(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-incident-alert-test.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    first_store.save_incident(
        make_incident()
    )

    first_store.save_incident_alert(
        make_incident_alert()
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    stored = (
        second_store
        .get_incident_alert(
            "ALT-WAZUH-001"
        )
    )

    assert stored is not None

    assert (
        stored.incident_id
        == "INC-001"
    )

    assert (
        stored.source
        == "wazuh"
    )

    alerts = (
        second_store
        .list_incident_alerts(
            "INC-001"
        )
    )

    assert len(alerts) == 1

    assert (
        alerts[0].alert_id
        == "ALT-WAZUH-001"
    )


def test_postgres_store_initializes_incident_alerts_table():
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
        "CREATE TABLE IF NOT EXISTS incident_alerts"
        in executed_sql
    )

    assert (
        "incident_id TEXT NOT NULL"
        in executed_sql
    )

    assert (
        "alert_id TEXT PRIMARY KEY"
        in executed_sql
    )


def test_postgres_store_saves_incident_alert():
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

    alert = make_incident_alert()

    saved = store.save_incident_alert(
        alert
    )

    assert saved == alert

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
        "INSERT INTO incident_alerts"
        in sql
    )

    assert (
        "ON CONFLICT (alert_id)"
        in sql
    )

    assert (
        parameters[0]
        == "ALT-WAZUH-001"
    )

    assert (
        parameters[1]
        == "INC-001"
    )


def test_postgres_store_lists_incident_alerts():
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

    alert = make_incident_alert()

    (
        connection
        .execute
        .return_value
        .fetchall
        .return_value
    ) = [
        (
            alert.model_dump_json(),
        ),
    ]

    alerts = store.list_incident_alerts(
        "INC-001"
    )

    assert alerts == [
        alert,
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
        "FROM incident_alerts"
        in sql
    )

    assert (
        "WHERE incident_id = %s"
        in sql
    )

    assert (
        "ORDER BY observed_at ASC"
        in sql
    )

    assert parameters == (
        "INC-001",
    )