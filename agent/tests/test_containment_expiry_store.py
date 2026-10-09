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

def test_create_if_absent_preserves_claimed_expiry(tmp_path):
    store = SQLiteContainmentExpiryStore(
        tmp_path / "expiry-race.db"
    )

    original = make_expiry()

    claimed = original.model_copy(
        update={
            "status": "CLAIMED",
            "lease_owner": "worker-001",
            "lease_expires_at": (
                FIXED_TIME + timedelta(minutes=35)
            ),
        }
    )

    store.save_expiry(claimed)

    result = store.create_expiry_if_absent(original)

    assert result == claimed
    assert store.get_expiry(original.expiry_id) == claimed


def test_postgres_create_if_absent_uses_conflict_do_nothing():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    store = PostgresContainmentExpiryStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=MagicMock(return_value=connection),
    )

    connection.execute.reset_mock()
    record = make_expiry()

    store.get_expiry = lambda expiry_id: record

    result = store.create_expiry_if_absent(record)

    assert result == record

    sql = connection.execute.call_args.args[0]

    assert "ON CONFLICT(expiry_id)" in sql
    assert "DO NOTHING" in sql
    assert "DO UPDATE" not in sql

def test_in_memory_claim_only_due_pending_records():
    store = InMemoryContainmentExpiryStore()

    due = make_expiry()
    future = make_expiry(
        expiry_id="EXPIRY-FUTURE",
        due_at=FIXED_TIME + timedelta(hours=2),
    )

    store.save_expiry(due)
    store.save_expiry(future)

    now = FIXED_TIME + timedelta(minutes=31)

    first = store.claim_due_expiries(
        now=now,
        worker_id="worker-001",
        lease_seconds=120,
        limit=10,
    )

    assert len(first) == 1
    assert first[0].expiry_id == due.expiry_id
    assert first[0].status == "CLAIMED"
    assert first[0].attempt_count == 1
    assert first[0].lease_owner == "worker-001"
    assert first[0].lease_expires_at == (
        now + timedelta(seconds=120)
    )

    second = store.claim_due_expiries(
        now=now,
        worker_id="worker-002",
    )

    assert second == []
    assert store.get_expiry(future.expiry_id) == future


def test_sqlite_two_workers_cannot_claim_same_expiry(tmp_path):
    database_path = tmp_path / "worker-claims.db"

    first_store = SQLiteContainmentExpiryStore(
        database_path
    )
    second_store = SQLiteContainmentExpiryStore(
        database_path
    )

    due = make_expiry()
    first_store.save_expiry(due)

    now = FIXED_TIME + timedelta(minutes=31)

    first = first_store.claim_due_expiries(
        now=now,
        worker_id="worker-A",
    )

    second = second_store.claim_due_expiries(
        now=now,
        worker_id="worker-B",
    )

    assert len(first) == 1
    assert second == []
    assert first[0].status == "CLAIMED"
    assert first[0].attempt_count == 1

    assert (
        second_store.get_expiry(due.expiry_id)
        == first[0]
    )


def test_postgres_claim_uses_skip_locked_and_update():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    store = PostgresContainmentExpiryStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=MagicMock(return_value=connection),
    )

    due = make_expiry()

    query_cursor = MagicMock()
    query_cursor.fetchall.return_value = [
        (due.expiry_id, due.model_dump_json()),
    ]

    update_cursor = MagicMock()
    update_cursor.rowcount = 1

    connection.execute.reset_mock()
    connection.execute.side_effect = [
        query_cursor,
        update_cursor,
    ]

    claimed = store.claim_due_expiries(
        now=FIXED_TIME + timedelta(minutes=31),
        worker_id="postgres-worker",
        lease_seconds=120,
    )

    assert len(claimed) == 1
    assert claimed[0].status == "CLAIMED"
    assert claimed[0].lease_owner == "postgres-worker"

    sql = [
        " ".join(call.args[0].split())
        for call in connection.execute.call_args_list
    ]

    assert "FOR UPDATE SKIP LOCKED" in sql[0]
    assert "UPDATE containment_expiries" in sql[1]
    assert "status = 'CLAIMED'" in sql[1]

def test_in_memory_finish_claimed_expiry():
    store = InMemoryContainmentExpiryStore()
    store.save_expiry(make_expiry())

    now = FIXED_TIME + timedelta(minutes=31)

    claimed = store.claim_due_expiries(
        now=now,
        worker_id="worker-A",
    )[0]

    finished_at = now + timedelta(seconds=20)

    completed = store.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=claimed.attempt_count,
        status="COMPLETED",
        now=finished_at,
    )

    assert completed.status == "COMPLETED"
    assert completed.completed_at == finished_at
    assert completed.lease_owner is None
    assert completed.lease_expires_at is None
    assert completed.attempt_count == 1

    assert store.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=1,
        status="COMPLETED",
        now=finished_at,
    ) is None

    assert store.get_expiry(
        claimed.expiry_id
    ) == completed


def test_finish_claim_rejects_wrong_worker_and_expired_lease():
    store = InMemoryContainmentExpiryStore()
    store.save_expiry(make_expiry())

    now = FIXED_TIME + timedelta(minutes=31)

    claimed = store.claim_due_expiries(
        now=now,
        worker_id="worker-A",
        lease_seconds=120,
    )[0]

    assert store.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-B",
        attempt_count=1,
        status="COMPLETED",
        now=now + timedelta(seconds=10),
    ) is None

    assert store.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=1,
        status="FAILED",
        error="Unblock verification was uncertain.",
        now=now + timedelta(seconds=121),
    ) is None

    assert store.get_expiry(
        claimed.expiry_id
    ) == claimed


def test_sqlite_finish_claim_persists_across_restart(tmp_path):
    database = tmp_path / "expiry-completion.db"

    first = SQLiteContainmentExpiryStore(database)
    first.save_expiry(make_expiry())

    now = FIXED_TIME + timedelta(minutes=31)

    claimed = first.claim_due_expiries(
        now=now,
        worker_id="worker-A",
    )[0]

    restarted = SQLiteContainmentExpiryStore(database)

    failed = restarted.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=1,
        status="FAILED",
        error="Independent verifier unavailable.",
        now=now + timedelta(seconds=10),
    )

    assert failed.status == "FAILED"
    assert failed.last_error == (
        "Independent verifier unavailable."
    )
    assert failed.completed_at is None

    assert first.get_expiry(claimed.expiry_id) == failed

    assert first.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=1,
        status="COMPLETED",
        now=now + timedelta(seconds=20),
    ) is None


def test_postgres_finish_claim_uses_locked_transition():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    store = PostgresContainmentExpiryStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=MagicMock(return_value=connection),
    )

    now = FIXED_TIME + timedelta(minutes=31)

    claimed = make_expiry().model_copy(
        update={
            "status": "CLAIMED",
            "attempt_count": 1,
            "lease_owner": "worker-A",
            "lease_expires_at": now + timedelta(seconds=120),
            "updated_at": now,
        }
    )

    select_cursor = MagicMock()
    select_cursor.fetchone.return_value = (
        claimed.model_dump_json(),
    )

    update_cursor = MagicMock()
    update_cursor.rowcount = 1

    connection.execute.reset_mock()
    connection.execute.side_effect = [
        select_cursor,
        update_cursor,
    ]

    result = store.finish_claimed_expiry(
        expiry_id=claimed.expiry_id,
        worker_id="worker-A",
        attempt_count=1,
        status="COMPLETED",
        now=now + timedelta(seconds=10),
    )

    assert result.status == "COMPLETED"

    statements = [
        " ".join(call.args[0].split())
        for call in connection.execute.call_args_list
    ]

    assert "FOR UPDATE" in statements[0]
    assert "UPDATE containment_expiries" in statements[1]
    assert "status = 'CLAIMED'" in statements[1]
