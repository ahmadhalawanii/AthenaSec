from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.schemas import (
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.action_approval import (
    create_approval_request,
    decide_approval_request,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.containment_expiry_store import (
    InMemoryContainmentExpiryStore,
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


def _process_test_runtime(
    **kwargs,
):
    kwargs.setdefault(
        "containment_expiry_store",
        InMemoryContainmentExpiryStore(),
    )

    return (
        process_structured_response_action(
            **kwargs
        )
    )


def make_action():
    return ProposedActionRecord(
        proposed_action_id="PACT-RUNTIME-001",
        incident_id="INC-RUNTIME-001",
        investigation_id="INV-RUNTIME-001",
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
        proposed_at=BASE_TIME,
    )


def make_policy(
    outcome="AUTO_ALLOWED",
):
    return IncidentPolicyDecisionRecord(
        decision_id="PDEC-RUNTIME-001",
        incident_id="INC-RUNTIME-001",
        proposed_action_id=(
            "PACT-RUNTIME-001"
        ),
        policy_id=(
            "POL-RUNTIME-TEST"
        ),
        outcome=outcome,
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
            details={
                "verified": (
                    self.status
                    == "SUCCESS"
                ),
            },
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
            message="Rollback completed.",
            details={},
        )


def test_auto_allowed_action_executes_and_verifies():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = FakeExecutor()
    verifier = FakeVerifier()
    rollback = (
        FakeRollbackExecutor()
    )

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=make_action(),
            policy_decision=make_policy(),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "verified"

    assert len(executor.calls) == 1
    assert len(verifier.calls) == 1
    assert rollback.calls == []

    assert (
        result.verification.status
        == "SUCCESS"
    )

    assert (
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
        == []
    )


def test_failed_verification_rolls_back_and_creates_case():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = FakeExecutor()

    verifier = FakeVerifier(
        status="FAILED"
    )

    rollback = (
        FakeRollbackExecutor()
    )

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=make_action(),
            policy_decision=make_policy(),
            executor=executor,
            verifier=verifier,
            rollback_executor=rollback,
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert (
        result.outcome
        == "rolled_back"
    )

    assert len(executor.calls) == 1
    assert len(rollback.calls) == 1

    assert result.rollback is not None

    assert (
        result.rollback.status
        == "completed"
    )

    cases = (
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
    )

    assert len(cases) == 1


def test_missing_verifier_blocks_before_cortex():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = FakeExecutor()

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=make_action(),
            policy_decision=make_policy(),
            executor=executor,
            verifier=None,
            rollback_executor=(
                FakeRollbackExecutor()
            ),
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    assert len(
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
    ) == 1


def test_missing_rollback_path_blocks_reversible_action_before_cortex():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = FakeExecutor()

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=make_action(),
            policy_decision=make_policy(),
            executor=executor,
            verifier=FakeVerifier(),
            rollback_executor=None,
            autonomous_response_enabled=True,
            now=BASE_TIME,
        )
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    assert len(
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
    ) == 1


def test_expired_approved_action_cannot_execute():
    store = (
        InMemoryIncidentResponseStore()
    )

    action = make_action()

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    pending = (
        create_approval_request(
            proposed_action=action,
            policy_decision=policy,
            requested_at=BASE_TIME,
            expires_at=(
                BASE_TIME
                + timedelta(minutes=30)
            ),
        )
    )

    approved = (
        decide_approval_request(
            approval=pending,
            proposed_action=action,
            decision="APPROVED",
            decided_by="analyst-001",
            reason="Approved.",
            decided_at=(
                BASE_TIME
                + timedelta(minutes=5)
            ),
        )
    )

    store.save_approval_request(
        approved
    )

    executor = FakeExecutor()

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=action,
            policy_decision=policy,
            approval_id=(
                approved.approval_id
            ),
            executor=executor,
            verifier=FakeVerifier(),
            rollback_executor=(
                FakeRollbackExecutor()
            ),
            autonomous_response_enabled=True,
            now=(
                BASE_TIME
                + timedelta(minutes=31)
            ),
        )
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    assert len(
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
    ) == 1


def test_repeated_runtime_call_does_not_execute_cortex_twice():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = FakeExecutor()
    verifier = FakeVerifier()
    rollback = (
        FakeRollbackExecutor()
    )

    for _ in range(2):
        result = (
            _process_test_runtime(
                store=store,
                proposed_action=(
                    make_action()
                ),
                policy_decision=(
                    make_policy()
                ),
                executor=executor,
                verifier=verifier,
                rollback_executor=rollback,
                autonomous_response_enabled=True,
                now=BASE_TIME,
            )
        )

        assert (
            result.outcome
            == "verified"
        )

    assert len(executor.calls) == 1

def test_shadow_mode_skips_cortex_without_runtime_components():
    store = (
        InMemoryIncidentResponseStore()
    )

    result = (
        _process_test_runtime(
            store=store,
            proposed_action=make_action(),
            policy_decision=make_policy(),
            executor=None,
            verifier=None,
            rollback_executor=None,
            autonomous_response_enabled=True,
            response_mode="SHADOW",
            now=BASE_TIME,
        )
    )

    assert result.outcome == "shadowed"

    assert result.execution is None

    assert result.verification is None

    assert result.rollback is None

    assert result.incident_case is None

    assert (
        store.list_incident_cases(
            "INC-RUNTIME-001"
        )
        == []
    )
