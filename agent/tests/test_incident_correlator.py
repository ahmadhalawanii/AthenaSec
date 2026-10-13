from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.schemas import (
    AttackPrediction,
    IncidentCorrelationProfile,
    IncidentRecord,
    SecurityAlertInput,
)
from app.services.incident_correlator import (
    correlate_or_create_incident,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
)


BASE_TIME = datetime(
    2026,
    10,
    8,
    8,
    0,
    tzinfo=timezone.utc,
)


def make_alert(
    *,
    alert_id: str = "ALT-001",
    minute: int = 0,
    source_ip: str | None = "203.0.113.10",
    target_user: str | None = "root",
    agent_id: str | None = "007",
    mitre_ids: list[str] | None = None,
) -> SecurityAlertInput:
    observed_at = (
        BASE_TIME
        + timedelta(minutes=minute)
    )

    return SecurityAlertInput(
        alert_id=alert_id,
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
        metadata={
            "timestamp": (
                observed_at.isoformat()
            ),
            "source_ip": source_ip,
            "target_user": target_user,
            "agent_id": agent_id,
            "mitre_ids": (
                mitre_ids
                if mitre_ids is not None
                else [
                    "T1110.001",
                ]
            ),
        },
    )


def make_prediction(
    classification: str = "brute_force",
) -> AttackPrediction:
    return AttackPrediction(
        classification=classification,
        confidence=0.95,
        model_version="test-model",
    )


def make_incident(
    *,
    incident_id: str,
    status: str = "open",
    minute: int = 0,
) -> IncidentRecord:
    timestamp = (
        BASE_TIME
        + timedelta(minutes=minute)
    )

    return IncidentRecord(
        incident_id=incident_id,
        title="Brute force activity",
        status=status,
        created_at=timestamp,
        updated_at=timestamp,
    )


def make_profile(
    *,
    incident_id: str,
    source_ips: list[str] | None = None,
    target_users: list[str] | None = None,
    agent_ids: list[str] | None = None,
    mitre_ids: list[str] | None = None,
    first_minute: int = 0,
    last_minute: int = 0,
) -> IncidentCorrelationProfile:
    return IncidentCorrelationProfile(
        incident_id=incident_id,
        classification="brute_force",
        source_ips=(
            source_ips
            if source_ips is not None
            else [
                "203.0.113.10",
            ]
        ),
        target_users=(
            target_users
            if target_users is not None
            else [
                "root",
            ]
        ),
        agent_ids=(
            agent_ids
            if agent_ids is not None
            else [
                "007",
            ]
        ),
        mitre_ids=(
            mitre_ids
            if mitre_ids is not None
            else [
                "T1110.001",
            ]
        ),
        first_seen=(
            BASE_TIME
            + timedelta(
                minutes=first_minute
            )
        ),
        last_seen=(
            BASE_TIME
            + timedelta(
                minutes=last_minute
            )
        ),
    )


def test_first_alert_creates_new_incident():
    store = InMemoryInvestigationStore()

    alert = make_alert()

    decision = correlate_or_create_incident(
        alert=alert,
        prediction=make_prediction(),
        store=store,
    )

    assert (
        decision.created_new_incident
        is True
    )

    assert (
        decision.duplicate_alert
        is False
    )

    assert (
        decision.incident.incident_id
        .startswith("INC-")
    )

    assert (
        decision.alert.incident_id
        == decision.incident.incident_id
    )

    assert (
        decision.profile.incident_id
        == decision.incident.incident_id
    )

    assert (
        store.get_incident(
            decision.incident.incident_id
        )
        == decision.incident
    )

    assert (
        store.get_incident_alert(
            "ALT-001"
        )
        == decision.alert
    )


def test_matching_alert_is_attached_to_existing_incident():
    store = InMemoryInvestigationStore()

    first = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-001",
            minute=0,
        ),
        prediction=make_prediction(),
        store=store,
    )

    second = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-002",
            minute=5,
        ),
        prediction=make_prediction(),
        store=store,
    )

    assert (
        second.created_new_incident
        is False
    )

    assert (
        second.duplicate_alert
        is False
    )

    assert (
        second.incident.incident_id
        == first.incident.incident_id
    )

    assert (
        second.correlation_score
        >= 5
    )

    alerts = store.list_incident_alerts(
        first.incident.incident_id
    )

    assert [
        alert.alert_id
        for alert in alerts
    ] == [
        "ALT-001",
        "ALT-002",
    ]


def test_best_scoring_candidate_wins():
    store = InMemoryInvestigationStore()

    weak_incident = make_incident(
        incident_id="INC-WEAK",
        minute=4,
    )

    strong_incident = make_incident(
        incident_id="INC-STRONG",
        minute=0,
    )

    store.save_incident(
        weak_incident
    )

    store.save_incident(
        strong_incident
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-WEAK",
            source_ips=[
                "203.0.113.10",
            ],
            target_users=[
                "different-user",
            ],
            agent_ids=[
                "999",
            ],
            mitre_ids=[],
            last_minute=4,
        )
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-STRONG",
            source_ips=[
                "203.0.113.10",
            ],
            target_users=[
                "root",
            ],
            agent_ids=[
                "007",
            ],
            mitre_ids=[
                "T1110.001",
            ],
            last_minute=0,
        )
    )

    decision = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-NEW",
            minute=5,
        ),
        prediction=make_prediction(),
        store=store,
    )

    assert (
        decision.incident.incident_id
        == "INC-STRONG"
    )

    assert (
        decision.correlation_score
        == 12
    )


def test_resolved_incident_is_not_reopened_by_correlation():
    store = InMemoryInvestigationStore()

    store.save_incident(
        make_incident(
            incident_id="INC-RESOLVED",
            status="resolved",
        )
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-RESOLVED",
        )
    )

    decision = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-NEW",
            minute=5,
        ),
        prediction=make_prediction(),
        store=store,
    )

    assert (
        decision.created_new_incident
        is True
    )

    assert (
        decision.incident.incident_id
        != "INC-RESOLVED"
    )


def test_duplicate_alert_is_idempotent():
    store = InMemoryInvestigationStore()

    first = correlate_or_create_incident(
        alert=make_alert(),
        prediction=make_prediction(),
        store=store,
    )

    second = correlate_or_create_incident(
        alert=make_alert(),
        prediction=make_prediction(),
        store=store,
    )

    assert (
        second.duplicate_alert
        is True
    )

    assert (
        second.created_new_incident
        is False
    )

    assert (
        second.incident.incident_id
        == first.incident.incident_id
    )

    alerts = store.list_incident_alerts(
        first.incident.incident_id
    )

    assert len(alerts) == 1


def test_out_of_order_alert_preserves_latest_incident_time():
    store = InMemoryInvestigationStore()

    first = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-LATER",
            minute=10,
        ),
        prediction=make_prediction(),
        store=store,
    )

    second = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-EARLIER",
            minute=5,
        ),
        prediction=make_prediction(),
        store=store,
    )

    assert (
        second.incident.incident_id
        == first.incident.incident_id
    )

    assert (
        second.incident.updated_at
        == BASE_TIME
        + timedelta(minutes=10)
    )

    assert (
        second.profile.first_seen
        == BASE_TIME
        + timedelta(minutes=5)
    )

    assert (
        second.profile.last_seen
        == BASE_TIME
        + timedelta(minutes=10)
    )


def test_sqlite_correlator_survives_store_restart(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-correlator.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    first = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-001",
            minute=0,
        ),
        prediction=make_prediction(),
        store=first_store,
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    second = correlate_or_create_incident(
        alert=make_alert(
            alert_id="ALT-002",
            minute=5,
        ),
        prediction=make_prediction(),
        store=second_store,
    )

    assert (
        second.incident.incident_id
        == first.incident.incident_id
    )

    persisted_profile = (
        second_store
        .get_correlation_profile(
            first.incident.incident_id
        )
    )

    assert persisted_profile is not None

    assert (
        persisted_profile.last_seen
        == BASE_TIME
        + timedelta(minutes=5)
    )

    alerts = (
        second_store
        .list_incident_alerts(
            first.incident.incident_id
        )
    )

    assert len(alerts) == 2