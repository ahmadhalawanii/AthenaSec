from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from app.schemas import (
    AttackPrediction,
    IncidentAlertRecord,
    IncidentInvestigationRecord,
    IncidentRecord,
    RiskAssessment,
)
from app.services.investigations.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)
from tests.test_investigation_store import make_investigation

BASE = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)


def seed(store):
    """Three alerts across two incidents, plus an orphan investigation."""

    specs = [
        # alert, incident, classification, status, minutes ago, risk
        ("ALT-1", "INC-A", "brute_force", "complete", 30, 80),
        ("ALT-2", "INC-A", "privilege_escalation", "complete", 20, 60),
        ("ALT-3", "INC-B", "benign", "failed", 10, 10),
    ]

    for alert_id, incident_id, classification, status, ago, score in specs:
        observed_at = BASE - timedelta(minutes=ago)
        base = make_investigation()
        analysis = base.analysis.model_copy(
            update={"classification": classification}
        )
        investigation = base.model_copy(
            update={
                "alert_id": alert_id,
                "incident_id": incident_id,
                "investigation_id": f"INV-{alert_id}",
                "status": status,
                "analysis": analysis,
                "risk_assessment": RiskAssessment(
                    score=score, band="high", factors=[]
                ),
                "ml_prediction": AttackPrediction(
                    classification=classification,
                    confidence=0.9,
                    model_version="test",
                ),
            }
        )
        store.save_incident(
            IncidentRecord(
                incident_id=incident_id,
                title=incident_id,
                status="open",
                created_at=observed_at,
                updated_at=observed_at,
            )
        )
        store.save_incident_alert(
            IncidentAlertRecord(
                incident_id=incident_id,
                alert_id=alert_id,
                source="manual",
                event_text="event",
                observed_at=observed_at,
            )
        )
        store.save(investigation)
        store.save_incident_investigation(
            IncidentInvestigationRecord(
                investigation_id=f"INV-{alert_id}",
                incident_id=incident_id,
                primary_alert_id=alert_id,
                status="complete" if status == "complete" else "failed",
                started_at=observed_at,
                updated_at=observed_at,
            )
        )

    # An investigation record whose summary was never stored.
    store.save_incident_investigation(
        IncidentInvestigationRecord(
            investigation_id="INV-ORPHAN",
            incident_id="INC-B",
            primary_alert_id="ALT-MISSING",
            status="open",
            started_at=BASE - timedelta(minutes=5),
            updated_at=BASE,
        )
    )
    return store


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return seed(InMemoryInvestigationStore())

    return seed(SQLiteInvestigationStore(tmp_path / "list.db"))


def test_list_alerts_newest_first_with_fields(store):
    entries = store.list_alerts()

    assert [entry.alert_id for entry in entries] == [
        "ALT-3",
        "ALT-2",
        "ALT-1",
    ]
    first = entries[0]
    assert first.observed_at == BASE - timedelta(minutes=10)
    assert first.classification == "benign"
    assert first.ml_prediction.classification == "benign"
    assert first.risk_assessment.score == 10
    assert first.status == "failed"
    assert first.incident_id == "INC-B"


def test_list_alerts_filters(store):
    assert [e.alert_id for e in store.list_alerts(status="complete")] == [
        "ALT-2",
        "ALT-1",
    ]
    assert [
        e.alert_id
        for e in store.list_alerts(classification="brute_force")
    ] == ["ALT-1"]
    assert [
        e.alert_id
        for e in store.list_alerts(since=BASE - timedelta(minutes=25))
    ] == ["ALT-3", "ALT-2"]
    assert store.list_alerts(status="complete", classification="benign") == []


def test_list_alerts_since_accepts_naive_datetime(store):
    naive = (BASE - timedelta(minutes=15)).replace(tzinfo=None)

    assert [e.alert_id for e in store.list_alerts(since=naive)] == ["ALT-3"]


def test_list_alerts_empty_store():
    assert InMemoryInvestigationStore().list_alerts() == []


def test_list_investigations_newest_first_with_summary(store):
    entries = store.list_investigations()

    assert [e.investigation_id for e in entries] == [
        "INV-ORPHAN",
        "INV-ALT-3",
        "INV-ALT-2",
        "INV-ALT-1",
    ]  # orphan started 5 minutes ago, ALT-3 10 minutes ago
    by_id = {e.investigation_id: e for e in entries}
    assert by_id["INV-ALT-1"].classification == "brute_force"
    assert by_id["INV-ALT-1"].risk_score == 80
    assert by_id["INV-ALT-1"].risk_band == "high"
    assert by_id["INV-ALT-1"].policy_outcome == "create_case"
    assert by_id["INV-ALT-1"].primary_alert_id == "ALT-1"


def test_list_investigations_without_summary_has_null_fields(store):
    orphan = next(
        e
        for e in store.list_investigations()
        if e.investigation_id == "INV-ORPHAN"
    )

    assert orphan.classification is None
    assert orphan.risk_score is None
    assert orphan.risk_band is None
    assert orphan.policy_outcome is None


def test_list_investigations_filters(store):
    assert {
        e.investigation_id
        for e in store.list_investigations(incident_id="INC-A")
    } == {"INV-ALT-1", "INV-ALT-2"}
    assert [
        e.investigation_id
        for e in store.list_investigations(status="open")
    ] == ["INV-ORPHAN"]
    assert (
        store.list_investigations(incident_id="INC-A", status="open") == []
    )


def make_postgres_store():
    connection = MagicMock()
    connection.__enter__.return_value = connection
    store = PostgresInvestigationStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=MagicMock(return_value=connection),
    )
    connection.execute.reset_mock()
    return store, connection


def test_postgres_list_alerts_joins_observed_at_and_filters():
    store, connection = make_postgres_store()
    first = make_investigation()
    second = first.model_copy(
        update={"alert_id": "ALT-STORE-002", "status": "failed"}
    )
    third = first.model_copy(update={"alert_id": "ALT-STORE-003"})
    connection.execute.return_value.fetchall.return_value = [
        (first.model_dump_json(), BASE - timedelta(minutes=5)),
        (second.model_dump_json(), BASE),
        # Alert that never reached incident_alerts.
        (third.model_dump_json(), None),
    ]

    entries = store.list_alerts()
    sql = connection.execute.call_args.args[0]

    assert "LEFT JOIN incident_alerts" in sql
    assert [e.alert_id for e in entries] == [
        "ALT-STORE-002",
        "ALT-STORE-001",
        "ALT-STORE-003",
    ]
    assert [e.alert_id for e in store.list_alerts(status="failed")] == [
        "ALT-STORE-002"
    ]
    assert [
        e.alert_id
        for e in store.list_alerts(since=BASE - timedelta(minutes=1))
    ] == ["ALT-STORE-002"]


def test_postgres_list_investigations_joins_summary():
    store, connection = make_postgres_store()
    summary = make_investigation()
    record = IncidentInvestigationRecord(
        investigation_id="INV-1",
        incident_id="INC-1",
        primary_alert_id=summary.alert_id,
        status="complete",
        started_at=BASE,
        updated_at=BASE,
    )
    orphan = record.model_copy(
        update={
            "investigation_id": "INV-0",
            "primary_alert_id": "GONE",
            "incident_id": "INC-2",
            "started_at": BASE - timedelta(minutes=1),
        }
    )
    connection.execute.return_value.fetchall.return_value = [
        (record.model_dump_json(), summary.model_dump_json()),
        (orphan.model_dump_json(), None),
    ]

    entries = store.list_investigations()
    sql = connection.execute.call_args.args[0]

    assert "LEFT JOIN investigations" in sql
    assert [e.investigation_id for e in entries] == ["INV-1", "INV-0"]
    assert entries[0].classification == "brute_force"
    assert entries[0].risk_score == 75
    assert entries[1].risk_score is None
    assert [
        e.investigation_id
        for e in store.list_investigations(incident_id="INC-2")
    ] == ["INV-0"]
