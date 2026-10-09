from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.schemas import (
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
)
from app.services.containment_expiry_store import (
    InMemoryContainmentExpiryStore,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
)
from app.services.structured_response_runtime import (
    process_structured_response_action,
)


BASE_TIME = datetime(
    2026,
    10,
    9,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_action(
    *,
    temporary=True,
):
    if temporary:
        return ProposedActionRecord(
            proposed_action_id=(
                "PACT-EXPIRY-RUNTIME-001"
            ),
            incident_id=(
                "INC-EXPIRY-RUNTIME-001"
            ),
            investigation_id=(
                "INV-EXPIRY-RUNTIME-001"
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
                "Temporary containment."
            ),
            proposed_at=BASE_TIME,
        )

    return ProposedActionRecord(
        proposed_action_id=(
            "PACT-EXPIRY-RUNTIME-002"
        ),
        incident_id=(
            "INC-EXPIRY-RUNTIME-001"
        ),
        investigation_id=(
            "INV-EXPIRY-RUNTIME-001"
        ),
        action_type=(
            "capture_telemetry"
        ),
        target_type="endpoint",
        target="agent-001",
        parameters={},
        reversible=False,
        rollback_action_type=None,
        rollback_parameters={},
        reason=(
            "Collect endpoint telemetry."
        ),
        proposed_at=BASE_TIME,
    )


def make_policy(
    action,
):
    return IncidentPolicyDecisionRecord(
        decision_id=(
            "PDEC-"
            + action.proposed_action_id
        ),
        incident_id=action.incident_id,
        proposed_action_id=(
            action.proposed_action_id
        ),
        policy_id="POL-EXPIRY-TEST",
        outcome="AUTO_ALLOWED",
        reason="Runtime policy.",
        decided_at=BASE_TIME,
    )


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        proposed_action,
    ):
        self.calls.append(
            proposed_action
        )

        return StructuredExecutorResult(
            message="Cortex executed.",
            details={
                "job_id": "JOB-001",
            },
        )


class FakeVerifier:
    def __init__(
        self,
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

        return StructuredVerificationObservation(
            status=self.status,
            message=(
                "Post-action state checked."
            ),
            details={},
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
                "Temporary containment "
                "was removed."
            ),
            details={},
        )


class FailingExpiryStore(
    InMemoryContainmentExpiryStore
):
    def create_expiry_if_absent(
        self,
        record,
    ):
        raise RuntimeError(
            "Expiry persistence unavailable."
        )


def test_verified_temporary_action_creates_durable_expiry():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    expiry_store = (
        InMemoryContainmentExpiryStore()
    )

    action = make_action()

    executor = FakeExecutor()
    verifier = FakeVerifier()
    rollback = FakeRollbackExecutor()

    result = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            containment_expiry_store=(
                expiry_store
            ),
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "verified"

    assert result.expiry is not None

    assert result.expiry.status == "PENDING"

    assert (
        result.expiry.due_at
        == BASE_TIME
        + timedelta(minutes=30)
    )

    assert (
        result.expiry
        .rollback_action_type
        == "unblock_ip"
    )

    assert (
        result.expiry.target
        == "203.0.113.10"
    )

    assert (
        expiry_store.get_expiry(
            result.expiry.expiry_id
        )
        == result.expiry
    )

    assert rollback.calls == []


def test_failed_verification_does_not_create_expiry():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    expiry_store = (
        InMemoryContainmentExpiryStore()
    )

    action = make_action()

    executor = FakeExecutor()

    verifier = FakeVerifier(
        status="FAILED"
    )

    rollback = FakeRollbackExecutor()

    result = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            containment_expiry_store=(
                expiry_store
            ),
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "rolled_back"

    assert result.expiry is None

    assert (
        expiry_store.list_due_expiries(
            now=(
                BASE_TIME
                + timedelta(hours=1)
            )
        )
        == []
    )


def test_missing_expiry_store_blocks_before_cortex():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    action = make_action()

    executor = FakeExecutor()

    result = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=FakeVerifier(),
            rollback_executor=(
                FakeRollbackExecutor()
            ),
            containment_expiry_store=None,
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    cases = (
        incident_store
        .list_incident_cases(
            action.incident_id
        )
    )

    assert len(cases) == 1

    assert (
        "expiry"
        in cases[0].reason.lower()
    )


def test_expiry_persistence_failure_immediately_rolls_back():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    expiry_store = (
        FailingExpiryStore()
    )

    action = make_action()

    executor = FakeExecutor()
    verifier = FakeVerifier()
    rollback = FakeRollbackExecutor()

    result = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            containment_expiry_store=(
                expiry_store
            ),
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "rolled_back"

    assert result.verification is not None

    assert (
        result.verification.status
        == "SUCCESS"
    )

    assert result.expiry is None

    assert rollback.calls == [
        action,
    ]

    assert result.rollback is not None

    assert (
        result.rollback.status
        == "completed"
    )

    cases = (
        incident_store
        .list_incident_cases(
            action.incident_id
        )
    )

    assert len(cases) == 1

    assert (
        "expiry"
        in cases[0].reason.lower()
    )


def test_existing_expiry_lifecycle_is_not_reset():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    expiry_store = (
        InMemoryContainmentExpiryStore()
    )

    action = make_action()

    executor = FakeExecutor()
    verifier = FakeVerifier()
    rollback = FakeRollbackExecutor()

    first = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            containment_expiry_store=(
                expiry_store
            ),
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert first.expiry is not None

    claimed = (
        first.expiry.model_copy(
            update={
                "status": "CLAIMED",
                "lease_owner": "worker-001",
                "lease_expires_at": (
                    BASE_TIME
                    + timedelta(minutes=35)
                ),
                "updated_at": (
                    BASE_TIME
                    + timedelta(minutes=31)
                ),
            }
        )
    )

    expiry_store.save_expiry(
        claimed
    )

    second = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            containment_expiry_store=(
                expiry_store
            ),
            autonomous_response_enabled=True,
            now=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
        )
    )

    assert second.outcome == "verified"

    assert second.expiry == claimed

    assert (
        second.expiry.status
        == "CLAIMED"
    )

    assert len(executor.calls) == 1


def test_non_temporary_action_does_not_require_expiry_store():
    incident_store = (
        InMemoryIncidentResponseStore()
    )

    action = make_action(
        temporary=False
    )

    executor = FakeExecutor()

    result = (
        process_structured_response_action(
            store=incident_store,
            proposed_action=action,
            policy_decision=(
                make_policy(action)
            ),
            executor=executor,
            verifier=FakeVerifier(),
            rollback_executor=None,
            containment_expiry_store=None,
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "verified"

    assert result.expiry is None

    assert executor.calls == [
        action,
    ]
