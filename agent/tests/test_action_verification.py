from datetime import (
    datetime,
    timezone,
)
from unittest.mock import (
    MagicMock,
)

import pytest

from app.schemas import (
    ActionExecutionResultRecord,
    ActionVerificationRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
    verify_structured_action,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    22,
    0,
    tzinfo=timezone.utc,
)


def make_action(
    *,
    proposed_action_id=(
        "PACT-VERIFY-001"
    ),
):
    return ProposedActionRecord(
        proposed_action_id=(
            proposed_action_id
        ),
        incident_id="INC-VERIFY-001",
        investigation_id=(
            "INV-VERIFY-001"
        ),
        action_type="block_ip",
        target_type="ip",
        target="203.0.113.10",
        parameters={
            "duration_minutes": 30,
        },
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={},
        reason=(
            "Contain malicious source."
        ),
        proposed_at=FIXED_TIME,
    )


def make_response_action(
    *,
    status="completed",
    proposed_action_id=(
        "PACT-VERIFY-001"
    ),
):
    return ResponseActionRecord(
        response_action_id=(
            "ACT-VERIFY-001"
        ),
        incident_id="INC-VERIFY-001",
        proposed_action_id=(
            proposed_action_id
        ),
        approval_id=None,
        executor="cortex",
        status=status,
        created_at=FIXED_TIME,
    )


def make_action_result(
    *,
    status="completed",
    response_action_id=(
        "ACT-VERIFY-001"
    ),
):
    return ActionExecutionResultRecord(
        action_result_id=(
            "ARES-VERIFY-001"
        ),
        response_action_id=(
            response_action_id
        ),
        status=status,
        message=(
            "Cortex responder completed."
        ),
        details={
            "job_id": "JOB-001",
        },
        recorded_at=FIXED_TIME,
    )


class FakeVerifier:
    def __init__(
        self,
        *,
        status="SUCCESS",
    ):
        self.status = status
        self.calls = []

    def verify(
        self,
        proposed_action,
        action_result,
    ):
        self.calls.append(
            (
                proposed_action,
                action_result,
            )
        )

        return (
            StructuredVerificationObservation(
                status=self.status,
                message=(
                    "Post-action state "
                    "was checked."
                ),
                details={
                    "observed": True,
                },
            )
        )


class FailingVerifier:
    def verify(
        self,
        proposed_action,
        action_result,
    ):
        raise RuntimeError(
            "Verification provider "
            "is unavailable."
        )


@pytest.mark.parametrize(
    "status",
    [
        "SUCCESS",
        "PARTIAL",
        "FAILED",
    ],
)
def test_verification_result_is_persisted(
    status,
):
    store = (
        InMemoryIncidentResponseStore()
    )

    action = make_action()

    response_action = (
        make_response_action()
    )

    action_result = (
        make_action_result()
    )

    verifier = FakeVerifier(
        status=status
    )

    record = (
        verify_structured_action(
            store=store,
            proposed_action=action,
            response_action=(
                response_action
            ),
            action_result=(
                action_result
            ),
            verifier=verifier,
            now=FIXED_TIME,
        )
    )

    assert record.status == status

    assert verifier.calls == [
        (
            action,
            action_result,
        ),
    ]

    assert (
        store.get_action_verification(
            record.verification_id
        )
        == record
    )


def test_verifier_failure_becomes_unverified():
    store = (
        InMemoryIncidentResponseStore()
    )

    record = (
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            action_result=(
                make_action_result()
            ),
            verifier=FailingVerifier(),
            now=FIXED_TIME,
        )
    )

    assert (
        record.status
        == "UNVERIFIED"
    )

    assert (
        "unavailable"
        in record.message.lower()
    )

    assert (
        record.details["error"]
        == (
            "Verification provider "
            "is unavailable."
        )
    )


def test_verification_id_is_deterministic():
    store = (
        InMemoryIncidentResponseStore()
    )

    verifier = FakeVerifier()

    first = (
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            action_result=(
                make_action_result()
            ),
            verifier=verifier,
            now=FIXED_TIME,
        )
    )

    second = (
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            action_result=(
                make_action_result()
            ),
            verifier=verifier,
            now=FIXED_TIME,
        )
    )

    assert (
        first.verification_id
        == second.verification_id
    )


def test_proposed_action_identity_mismatch_is_rejected():
    store = (
        InMemoryIncidentResponseStore()
    )

    with pytest.raises(
        ValueError,
        match="proposed action",
    ):
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action(
                    proposed_action_id=(
                        "PACT-OTHER"
                    )
                )
            ),
            response_action=(
                make_response_action()
            ),
            action_result=(
                make_action_result()
            ),
            verifier=FakeVerifier(),
            now=FIXED_TIME,
        )


def test_action_result_identity_mismatch_is_rejected():
    store = (
        InMemoryIncidentResponseStore()
    )

    with pytest.raises(
        ValueError,
        match="action result",
    ):
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action()
            ),
            action_result=(
                make_action_result(
                    response_action_id=(
                        "ACT-OTHER"
                    )
                )
            ),
            verifier=FakeVerifier(),
            now=FIXED_TIME,
        )


def test_non_completed_execution_cannot_be_verified():
    store = (
        InMemoryIncidentResponseStore()
    )

    with pytest.raises(
        ValueError,
        match="completed",
    ):
        verify_structured_action(
            store=store,
            proposed_action=(
                make_action()
            ),
            response_action=(
                make_response_action(
                    status="failed"
                )
            ),
            action_result=(
                make_action_result(
                    status="failed"
                )
            ),
            verifier=FakeVerifier(),
            now=FIXED_TIME,
        )


def make_verification_record():
    return ActionVerificationRecord(
        verification_id=(
            "VERIFY-001"
        ),
        response_action_id=(
            "ACT-VERIFY-001"
        ),
        proposed_action_id=(
            "PACT-VERIFY-001"
        ),
        status="SUCCESS",
        message=(
            "Action effect verified."
        ),
        details={
            "observed": True,
        },
        verified_at=FIXED_TIME,
    )


def test_sqlite_store_persists_verification(
    tmp_path,
):
    database_path = (
        tmp_path
        / "verification.db"
    )

    store = (
        SQLiteIncidentResponseStore(
            database_path
        )
    )

    record = (
        make_verification_record()
    )

    assert (
        store.save_action_verification(
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
        restarted
        .get_action_verification(
            "VERIFY-001"
        )
        == record
    )


def test_postgres_store_supports_verification():
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
        "action_verifications"
        in initialized_sql
    )

    connection.execute.reset_mock()

    record = (
        make_verification_record()
    )

    assert (
        store.save_action_verification(
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
        "INSERT INTO action_verifications"
        in sql
    )

    assert (
        parameters[0]
        == "VERIFY-001"
    )

    assert (
        parameters[1]
        == "ACT-VERIFY-001"
    )

    assert (
        parameters[2]
        == "PACT-VERIFY-001"
    )

    assert (
        parameters[3]
        == "SUCCESS"
    )