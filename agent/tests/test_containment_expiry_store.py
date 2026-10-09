from datetime import (
    datetime,
    timedelta,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    ContainmentExpiryRecord,
)
from app.services.containment_expiry_store import (
    InMemoryContainmentExpiryStore,
    PostgresContainmentExpiryStore,
    SQLiteContainmentExpiryStore,
)


FIXED_TIME = datetime(
    2026,
    10,
    9,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_expiry(
    *,
    expiry_id="EXPIRY-001",
    due_at=None,
    status="PENDING",
):
    if due_at is None:
        due_at = (
            FIXED_TIME
            + timedelta(minutes=30)
        )

    return ContainmentExpiryRecord(
        expiry_id=expiry_id,
        incident_id="INC-EXPIRY-001",
        proposed_action_id=(
            "PACT-EXPIRY-001"
        ),
        response_action_id=(
            "ACT-EXPIRY-001"
        ),
        rollback_action_type=(
            "unblock_ip"
        ),
        target="203.0.113.10",
        rollback_parameters={},
        due_at=due_at,
        status=status,
        attempt_count=0,
        lease_owner=None,
        lease_expires_at=None,
        last_error=None,
        created_at=FIXED_TIME,
        updated_at=FIXED_TIME,
        completed_at=None,
    )


def test_in_memory_store_round_trip_and_due_filter():
    store = (
        InMemoryContainmentExpiryStore()
    )

    due = make_expiry()

    future = make_expiry(
        expiry_id="EXPIRY-002",
        due_at=(
            FIXED_TIME
            + timedelta(hours=2)
        ),
    )

    claimed = make_expiry(
        expiry_id="EXPIRY-003",
        due_at=(
            FIXED_TIME
            + timedelta(minutes=10)
        ),
        status="CLAIMED",
    )

    store.save_expiry(due)
    store.save_expiry(future)
    store.save_expiry(claimed)

    assert (
        store.get_expiry(
            "EXPIRY-001"
        )
        == due
    )

    records = store.list_due_expiries(
        now=(
            FIXED_TIME
            + timedelta(minutes=31)
        )
    )

    assert records == [
        due,
    ]


def test_sqlite_expiry_survives_restart(
    tmp_path,
):
    database_path = (
        tmp_path
        / "containment-expiry.db"
    )

    store = (
        SQLiteContainmentExpiryStore(
            database_path
        )
    )

    record = make_expiry()

    assert (
        store.save_expiry(
            record
        )
        == record
    )

    restarted = (
        SQLiteContainmentExpiryStore(
            database_path
        )
    )

    assert (
        restarted.get_expiry(
            record.expiry_id
        )
        == record
    )


def test_sqlite_lists_only_due_pending_records(
    tmp_path,
):
    database_path = (
        tmp_path
        / "containment-due.db"
    )

    store = (
        SQLiteContainmentExpiryStore(
            database_path
        )
    )

    due_one = make_expiry(
        expiry_id="EXPIRY-001",
        due_at=(
            FIXED_TIME
            + timedelta(minutes=5)
        ),
    )

    due_two = make_expiry(
        expiry_id="EXPIRY-002",
        due_at=(
            FIXED_TIME
            + timedelta(minutes=10)
        ),
    )

    future = make_expiry(
        expiry_id="EXPIRY-003",
        due_at=(
            FIXED_TIME
            + timedelta(hours=1)
        ),
    )

    completed = make_expiry(
        expiry_id="EXPIRY-004",
        due_at=(
            FIXED_TIME
            + timedelta(minutes=1)
        ),
        status="COMPLETED",
    )

    for record in (
        due_one,
        due_two,
        future,
        completed,
    ):
        store.save_expiry(
            record
        )

    records = store.list_due_expiries(
        now=(
            FIXED_TIME
            + timedelta(minutes=30)
        )
    )

    assert records == [
        due_one,
        due_two,
    ]


def test_postgres_store_initializes_expiry_table():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresContainmentExpiryStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    executed_sql = " ".join(
        " ".join(
            call.args[0].split()
        )
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "CREATE TABLE IF NOT EXISTS "
        "containment_expiries"
        in executed_sql
    )

    assert (
        "idx_containment_expiries_due"
        in executed_sql
    )


def test_postgres_store_saves_and_queries_due_records():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = (
        PostgresContainmentExpiryStore(
            (
                "postgresql://"
                "athenasec:test@localhost/"
                "athenasec"
            ),
            connect=connect,
        )
    )

    connection.execute.reset_mock()

    record = make_expiry()

    assert (
        store.save_expiry(
            record
        )
        == record
    )

    save_sql = (
        connection.execute
        .call_args.args[0]
    )

    assert (
        "INSERT INTO containment_expiries"
        in save_sql
    )

    connection.execute.reset_mock()

    query_result = MagicMock()

    query_result.fetchall.return_value = [
        (
            record.model_dump_json(),
        ),
    ]

    connection.execute.return_value = (
        query_result
    )

    records = store.list_due_expiries(
        now=(
            FIXED_TIME
            + timedelta(minutes=31)
        ),
        limit=25,
    )

    assert records == [
        record,
    ]

    query_sql = (
        connection.execute
        .call_args.args[0]
    )

    assert (
        "status = 'PENDING'"
        in query_sql
    )

    assert (
        "due_at <= %s"
        in query_sql
    )

    assert (
        "LIMIT %s"
        in query_sql
    )