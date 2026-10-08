from datetime import (
    datetime,
    timedelta,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    IncidentCorrelationProfile,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
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

WINDOW = timedelta(
    minutes=15,
)

def normalize_sql(
    sql: str,
) -> str:
    return " ".join(
        sql.split()
    )

def make_profile(
    *,
    incident_id: str = "INC-001",
    classification: str = "brute_force",
    first_seen: datetime = BASE_TIME,
    last_seen: datetime = BASE_TIME,
) -> IncidentCorrelationProfile:
    return IncidentCorrelationProfile(
        incident_id=incident_id,
        classification=classification,
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
        first_seen=first_seen,
        last_seen=last_seen,
    )


def test_in_memory_store_saves_and_gets_correlation_profile():
    store = InMemoryInvestigationStore()

    profile = make_profile()

    saved = store.save_correlation_profile(
        profile
    )

    assert saved == profile

    stored = store.get_correlation_profile(
        "INC-001"
    )

    assert stored == profile


def test_in_memory_store_filters_correlation_candidates():
    store = InMemoryInvestigationStore()

    recent = make_profile(
        incident_id="INC-RECENT",
        last_seen=(
            BASE_TIME
            + timedelta(minutes=4)
        ),
    )

    old = make_profile(
        incident_id="INC-OLD",
        first_seen=(
            BASE_TIME
            - timedelta(hours=2)
        ),
        last_seen=(
            BASE_TIME
            - timedelta(hours=1)
        ),
    )

    different_class = make_profile(
        incident_id="INC-PRIV",
        classification="privilege_misuse",
    )

    store.save_correlation_profile(
        old
    )

    store.save_correlation_profile(
        different_class
    )

    store.save_correlation_profile(
        recent
    )

    candidates = (
        store.list_correlation_candidates(
            classification="brute_force",
            observed_at=(
                BASE_TIME
                + timedelta(minutes=5)
            ),
            window=WINDOW,
        )
    )

    assert [
        candidate.incident_id
        for candidate in candidates
    ] == [
        "INC-RECENT",
    ]


def test_candidate_lookup_supports_out_of_order_alerts():
    store = InMemoryInvestigationStore()

    profile = make_profile(
        incident_id="INC-001",
        first_seen=(
            BASE_TIME
            + timedelta(minutes=5)
        ),
        last_seen=(
            BASE_TIME
            + timedelta(minutes=10)
        ),
    )

    store.save_correlation_profile(
        profile
    )

    candidates = (
        store.list_correlation_candidates(
            classification="brute_force",
            observed_at=(
                BASE_TIME
                - timedelta(minutes=5)
            ),
            window=WINDOW,
        )
    )

    assert candidates == [
        profile,
    ]


def test_sqlite_store_persists_correlation_profile(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-correlation.db"
    )

    first = SQLiteInvestigationStore(
        database_path
    )

    first.save_correlation_profile(
        make_profile()
    )

    second = SQLiteInvestigationStore(
        database_path
    )

    stored = (
        second.get_correlation_profile(
            "INC-001"
        )
    )

    assert stored == make_profile()


def test_sqlite_store_filters_correlation_candidates(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-correlation-candidates.db"
    )

    store = SQLiteInvestigationStore(
        database_path
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-001",
            last_seen=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
        )
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-002",
            first_seen=(
                BASE_TIME
                + timedelta(minutes=2)
            ),
            last_seen=(
                BASE_TIME
                + timedelta(minutes=3)
            ),
        )
    )

    store.save_correlation_profile(
        make_profile(
            incident_id="INC-OLD",
            first_seen=(
                BASE_TIME
                - timedelta(hours=2)
            ),
            last_seen=(
                BASE_TIME
                - timedelta(hours=1)
            ),
        )
    )

    candidates = (
        store.list_correlation_candidates(
            classification="brute_force",
            observed_at=(
                BASE_TIME
                + timedelta(minutes=4)
            ),
            window=WINDOW,
        )
    )

    assert [
        candidate.incident_id
        for candidate in candidates
    ] == [
        "INC-002",
        "INC-001",
    ]


def test_postgres_store_initializes_correlation_profile_table():
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

    normalized_sql = normalize_sql(
        executed_sql
    )

    assert (
        "CREATE TABLE IF NOT EXISTS "
        "incident_correlation_profiles"
        in normalized_sql
    )

    assert (
        "idx_incident_correlation_profiles_lookup"
        in executed_sql
    )


def test_postgres_store_saves_correlation_profile():
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

    profile = make_profile()

    saved = store.save_correlation_profile(
        profile
    )

    assert saved == profile

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
        "INSERT INTO incident_correlation_profiles"
        in sql
    )

    assert (
        "ON CONFLICT (incident_id)"
        in sql
    )

    assert parameters[0] == "INC-001"

    assert (
        parameters[1]
        == "brute_force"
    )


def test_postgres_store_queries_only_plausible_candidates():
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

    profile = make_profile()

    (
        connection
        .execute
        .return_value
        .fetchall
        .return_value
    ) = [
        (
            profile.model_dump_json(),
        ),
    ]

    observed_at = (
        BASE_TIME
        + timedelta(minutes=5)
    )

    candidates = (
        store.list_correlation_candidates(
            classification="brute_force",
            observed_at=observed_at,
            window=WINDOW,
        )
    )

    assert candidates == [
        profile,
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
        "FROM incident_correlation_profiles"
        in sql
    )

    assert (
        "classification = %s"
        in sql
    )

    assert (
        "first_seen <= %s"
        in sql
    )

    assert (
        "last_seen >= %s"
        in sql
    )

    assert (
        "ORDER BY last_seen DESC"
        in sql
    )

    assert parameters == (
        "brute_force",
        observed_at + WINDOW,
        observed_at - WINDOW,
    )