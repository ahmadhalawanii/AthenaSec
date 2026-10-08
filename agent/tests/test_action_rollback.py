from datetime import (
    datetime,
    timezone,
)
from unittest.mock import (
    MagicMock,
)

import pytest

from app.schemas import (
    ActionRollbackRecord,
    ActionVerificationRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.action_rollback import (
    rollback_structured_action,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    23,
    0,
    tzinfo=timezone.utc,
)


def make_action(
    *,
    reversible=True,
):
    return ProposedActionRecord(
        proposed_action_id=(
            "PACT-ROLLBACK-001"
        ),
        incident_id=(
            "INC-ROLLBACK-001"
        ),
        investigation_id=(
            "INV-ROLLBACK-001"
        ),
        action_type="block_ip",
        target_type="ip",
        target="203.0.113.10",
        parameters={
            "duration_minutes": 30,
        },
        reversible=reversible,
        rollback_action_type=(
            "unblock_ip"
            if reversible
            else None
        ),
        rollback_parameters={},
        reason=(
            "Temporary containment."
        ),
        proposed_at=FIXED_TIME,
    )


def make_response_action(
    *,
    proposed_action_id=(
        "PACT-ROLLBACK-001"
    ),
):
    return ResponseActionRecord(
        response_action_id=(
            "ACT-ROLLBACK-001"
        ),
        incident_id=(
            "INC-ROLLBACK-001"
        ),
        proposed_action_id=(
            proposed_action_id
        ),
        approval_id=None,
        executor="cortex",
        status="completed",
        created_at=FIXED_TIME,
    )


def make_verification(
    *,
    status="FAILED",
    proposed_action_id=(
        "PACT-ROLLBACK-001"
    ),
    response_action_id=(
        "ACT-ROLLBACK-001"
    ),
):
    return ActionVerificationRecord(
        verification_id=(
            "VERIFY-ROLLBACK-001"
        ),
        response_action_id=(
            response_action_id
        ),
        proposed_action_id=(
            proposed_action_id
        ),
        status=status,
        message=(
            "Post-action verification "
            "result."
        ),
        details={},
        verified_at=FIXED_TIME,
    )


class FakeRollbackExecutor:
    def __init__(self):
        self.calls = []

    def rollback(
        self,
        proposed_action,
    ):
        self.calls.append(
            proposed_action
        )

        return StructuredExecutorResult(
            message=(
                "Cortex removed the "
                "temporary IP block."
            ),
            details={
                "responder_id": (
                    "UnblockIp_1_0"
                ),
            },
        )


class FailingRollbackExecutor:
    def __init__(self):
        self.calls = []

    def rollback(
        self,
        proposed_action,
    ):
        self.calls.append(
            proposed_action
        )

        raise RuntimeError(
            "Cortex rollback failed."
        )


@pytest.mark.parametrize(
    "verification_status",
    [
        "PARTIAL",
        "FAILED",
        "UNVERIFIED",
    ],
)
def test_unsuccessful_verification_rolls_back(
    verification_status,
):
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeRollbackExecutor()
    )

    action = make_action()

    record = (
        rollback_structured_action(
            store=store,
            proposed_action=action,
            response_action=(
                make_response_action()
            ),
            verification=(
                make_verification(
                    status=(
                        verification_status
                    )
                )
            ),
            rollback_executor=executor,
            now=FIXED_TIME,
        )
    )

    assert executor.calls == [
        action,
    ]

    assert (
        record.status
        == "completed"
    )

    assert (
        record.rollback_action_type
        == "unblock_ip"
    )

    assert (
        record.target
        == "203.0.113.10"
    )

    assert (
        store.get_action_rollback(
            record.rollback_id
        )
        == record
    )


def test_successful_verification_is_not_rolled_back():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeRollbackExecutor()
    )

    with pytest.raises(
        ValueError,
        match="SUCCESS",
    ):
        rollback_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            verification=(
                make_verification(
                    status="SUCCESS"
                )
            ),
            rollback_executor=executor,
            now=FIXED_TIME,
        )

    assert executor.calls == []


def test_non_reversible_action_cannot_roll_back():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeRollbackExecutor()
    )

    with pytest.raises(
        ValueError,
        match="reversible",
    ):
        rollback_structured_action(
            store=store,
            proposed_action=(
                make_action(
                    reversible=False
                )
            ),
            response_action=(
                make_response_action()
            ),
            verification=(
                make_verification()
            ),
            rollback_executor=executor,
            now=FIXED_TIME,
        )

    assert executor.calls == []


def test_rollback_identity_mismatch_fails_closed():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeRollbackExecutor()
    )

    with pytest.raises(
        ValueError,
        match="proposed action",
    ):
        rollback_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action(
                    proposed_action_id=(
                        "PACT-OTHER"
                    )
                )
            ),
            verification=(
                make_verification()
            ),
            rollback_executor=executor,
            now=FIXED_TIME,
        )

    assert executor.calls == []


def test_failed_rollback_is_persisted():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FailingRollbackExecutor()
    )

    record = (
        rollback_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            verification=(
                make_verification()
            ),
            rollback_executor=executor,
            now=FIXED_TIME,
        )
    )

    assert (
        record.status
        == "failed"
    )

    assert (
        "failed"
        in record.message.lower()
    )

    assert (
        record.details["error"]
        == "Cortex rollback failed."
    )

    assert (
        store.get_action_rollback(
            record.rollback_id
        )
        == record
    )


def make_rollback_record():
    return ActionRollbackRecord(
        rollback_id=(
            "ROLLBACK-001"
        ),
        response_action_id=(
            "ACT-ROLLBACK-001"
        ),
        proposed_action_id=(
            "PACT-ROLLBACK-001"
        ),
        verification_id=(
            "VERIFY-ROLLBACK-001"
        ),
        rollback_action_type=(
            "unblock_ip"
        ),
        target="203.0.113.10",
        status="completed",
        message=(
            "Temporary block removed."
        ),
        details={},
        recorded_at=FIXED_TIME,
    )


def test_sqlite_store_persists_rollback(
    tmp_path,
):
    database_path = (
        tmp_path
        / "rollback.db"
    )

    store = (
        SQLiteIncidentResponseStore(
            database_path
        )
    )

    record = (
        make_rollback_record()
    )

    assert (
        store.save_action_rollback(
            record
        )
        == record
    )

    restarted = (
        SQLiteIncidentResponseStore(
            database_path
        )
    )

    assert (
        restarted.get_action_rollback(
            "ROLLBACK-001"
        )
        == record
    )


def test_postgres_store_supports_rollback():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = (
        PostgresIncidentResponseStore(
            (
                "postgresql://"
                "athenasec:test@localhost/"
                "athenasec"
            ),
            connect=connect,
        )
    )

    initialized_sql = " ".join(
        call.args[0]
        for call
        in connection
        .execute
        .call_args_list
    )

    assert (
        "CREATE TABLE IF NOT EXISTS "
        "action_rollbacks"
        in initialized_sql
    )

    connection.execute.reset_mock()

    record = (
        make_rollback_record()
    )

    assert (
        store.save_action_rollback(
            record
        )
        == record
    )

    sql = (
        connection.execute
        .call_args.args[0]
    )

    parameters = (
        connection.execute
        .call_args.args[1]
    )

    assert (
        "INSERT INTO action_rollbacks"
        in sql
    )

    assert (
        parameters[0]
        == "ROLLBACK-001"
    )

    assert (
        parameters[1]
        == "ACT-ROLLBACK-001"
    )

    assert (
        parameters[2]
        == "PACT-ROLLBACK-001"
    )

    assert (
        parameters[3]
        == "VERIFY-ROLLBACK-001"
    )

    assert (
        parameters[4]
        == "completed"
    )

def test_repeated_completed_rollback_does_not_execute_twice():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeRollbackExecutor()
    )

    action = make_action()

    response_action = (
        make_response_action()
    )

    verification = (
        make_verification()
    )

    first = rollback_structured_action(
        store=store,
        proposed_action=action,
        response_action=response_action,
        verification=verification,
        rollback_executor=executor,
        now=FIXED_TIME,
    )

    second = rollback_structured_action(
        store=store,
        proposed_action=action,
        response_action=response_action,
        verification=verification,
        rollback_executor=executor,
        now=FIXED_TIME,
    )

    assert first == second

    assert executor.calls == [
        action,
    ]


def test_repeated_failed_rollback_is_not_retried_automatically():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FailingRollbackExecutor()
    )

    action = make_action()

    response_action = (
        make_response_action()
    )

    verification = (
        make_verification()
    )

    first = rollback_structured_action(
        store=store,
        proposed_action=action,
        response_action=response_action,
        verification=verification,
        rollback_executor=executor,
        now=FIXED_TIME,
    )

    second = rollback_structured_action(
        store=store,
        proposed_action=action,
        response_action=response_action,
        verification=verification,
        rollback_executor=executor,
        now=FIXED_TIME,
    )

    assert first == second

    assert first.status == "failed"

    assert executor.calls == [
        action,
    ]
