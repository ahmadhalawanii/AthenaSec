from datetime import (
    datetime,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    IncidentAlertRecord,
    IncidentInvestigationRecord,
    IncidentRecord,
    InvestigationEvidenceRecord,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)

def normalize_sql(sql: str) -> str:
    return " ".join(
        sql.split()
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


def make_alert() -> IncidentAlertRecord:
    return IncidentAlertRecord(
        incident_id="INC-001",
        alert_id="ALT-WAZUH-001",
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
            1,
            tzinfo=timezone.utc,
        ),
    )


def make_investigation(
    investigation_id: str = "INV-001",
    minute: int = 2,
) -> IncidentInvestigationRecord:
    timestamp = datetime(
        2026,
        10,
        7,
        16,
        minute,
        tzinfo=timezone.utc,
    )

    return IncidentInvestigationRecord(
        investigation_id=investigation_id,
        incident_id="INC-001",
        primary_alert_id="ALT-WAZUH-001",
        status="investigating",
        started_at=timestamp,
        updated_at=timestamp,
    )


def make_evidence(
    investigation_id: str = "INV-001",
    evidence_id: str = "E001",
    minute: int = 3,
) -> InvestigationEvidenceRecord:
    return InvestigationEvidenceRecord(
        investigation_id=investigation_id,
        evidence_id=evidence_id,
        source="wazuh",
        content="No successful SSH authentication was observed.",
        captured_at=datetime(
            2026,
            10,
            7,
            16,
            minute,
            tzinfo=timezone.utc,
        ),
    )


def test_in_memory_store_saves_and_gets_incident_investigation():
    store = InMemoryInvestigationStore()

    investigation = make_investigation()

    saved = store.save_incident_investigation(
        investigation
    )

    assert saved == investigation

    stored = store.get_incident_investigation(
        "INV-001"
    )

    assert stored == investigation


def test_in_memory_store_lists_incident_investigations_in_order():
    store = InMemoryInvestigationStore()

    later = make_investigation(
        investigation_id="INV-002",
        minute=4,
    )

    earlier = make_investigation(
        investigation_id="INV-001",
        minute=2,
    )

    store.save_incident_investigation(
        later
    )

    store.save_incident_investigation(
        earlier
    )

    investigations = (
        store.list_incident_investigations(
            "INC-001"
        )
    )

    assert [
        investigation.investigation_id
        for investigation in investigations
    ] == [
        "INV-001",
        "INV-002",
    ]


def test_evidence_ids_are_scoped_to_investigation():
    store = InMemoryInvestigationStore()

    first = make_evidence(
        investigation_id="INV-001",
        evidence_id="E001",
    )

    second = make_evidence(
        investigation_id="INV-002",
        evidence_id="E001",
    )

    store.save_investigation_evidence(
        first
    )

    store.save_investigation_evidence(
        second
    )

    assert (
        store.get_investigation_evidence(
            "INV-001",
            "E001",
        )
        == first
    )

    assert (
        store.get_investigation_evidence(
            "INV-002",
            "E001",
        )
        == second
    )


def test_sqlite_store_persists_investigation_and_evidence(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-investigation-test.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    first_store.save_incident(
        make_incident()
    )

    first_store.save_incident_alert(
        make_alert()
    )

    first_store.save_incident_investigation(
        make_investigation()
    )

    first_store.save_investigation_evidence(
        make_evidence()
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    investigation = (
        second_store
        .get_incident_investigation(
            "INV-001"
        )
    )

    assert investigation is not None

    assert (
        investigation.incident_id
        == "INC-001"
    )

    evidence = (
        second_store
        .list_investigation_evidence(
            "INV-001"
        )
    )

    assert len(evidence) == 1

    assert (
        evidence[0].evidence_id
        == "E001"
    )


def test_postgres_store_initializes_new_investigation_tables():
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
        "CREATE TABLE IF NOT EXISTS incident_investigations"
        in executed_sql
    )

    assert (
        "CREATE TABLE IF NOT EXISTS investigation_evidence"
        in executed_sql
    )

    normalized_sql = normalize_sql(
        executed_sql
    )

    assert (
        "PRIMARY KEY ( investigation_id, evidence_id )"
        in normalized_sql
    )


def test_postgres_store_saves_incident_investigation():
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

    investigation = make_investigation()

    saved = store.save_incident_investigation(
        investigation
    )

    assert saved == investigation

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
        "INSERT INTO incident_investigations"
        in sql
    )

    assert (
        "ON CONFLICT (investigation_id)"
        in sql
    )

    assert (
        parameters[0]
        == "INV-001"
    )

    assert (
        parameters[1]
        == "INC-001"
    )

    assert (
        parameters[2]
        == "ALT-WAZUH-001"
    )


def test_postgres_store_saves_investigation_evidence():
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

    evidence = make_evidence()

    saved = store.save_investigation_evidence(
        evidence
    )

    assert saved == evidence

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
        "INSERT INTO investigation_evidence"
        in sql
    )

    normalized_sql = normalize_sql(
        sql
    )

    assert (
        "ON CONFLICT ( investigation_id, evidence_id )"
        in normalized_sql
    )

    assert (
        parameters[0]
        == "INV-001"
    )

    assert (
        parameters[1]
        == "E001"
    )


def test_postgres_store_lists_investigation_evidence():
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

    evidence = make_evidence()

    (
        connection
        .execute
        .return_value
        .fetchall
        .return_value
    ) = [
        (
            evidence.model_dump_json(),
        ),
    ]

    stored = store.list_investigation_evidence(
        "INV-001"
    )

    assert stored == [
        evidence,
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
        "FROM investigation_evidence"
        in sql
    )

    assert (
        "WHERE investigation_id = %s"
        in sql
    )

    assert (
        "ORDER BY captured_at ASC"
        in sql
    )

    assert parameters == (
        "INV-001",
    )