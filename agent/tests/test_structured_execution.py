from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from app.schemas import (
    ActionRiskAssessmentRecord,
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.action_approval import (
    create_approval_request,
    decide_approval_request,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
    execute_structured_action,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    20,
    0,
    tzinfo=timezone.utc,
)


class FakeSuccessfulExecutor:
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
            message=(
                "Cortex responder "
                "completed successfully."
            ),
            details={
                "job_id": "CORTEX-JOB-001",
            },
        )


class FakeFailingExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        proposed_action,
    ):
        self.calls.append(
            proposed_action
        )

        raise RuntimeError(
            "Cortex responder failed."
        )


def make_action(
    *,
    target: str = "203.0.113.10",
    duration_minutes: int = 30,
):
    return ProposedActionRecord(
        proposed_action_id="PACT-M6-001",
        incident_id="INC-M6-001",
        investigation_id="INV-M6-001",
        action_type="block_ip",
        target_type="ip",
        target=target,
        parameters={
            "duration_minutes": (
                duration_minutes
            ),
        },
        reversible=True,
        rollback_action_type=(
            "unblock_ip"
        ),
        rollback_parameters={
            "target": target,
        },
        reason=(
            "Contain the verified "
            "malicious source."
        ),
        proposed_at=FIXED_TIME,
    )


def make_policy(
    *,
    outcome: str = "AUTO_ALLOWED",
    proposed_action_id: str = (
        "PACT-M6-001"
    ),
):
    policy_id = (
        "POL-ACTION-AUTO"
        if outcome == "AUTO_ALLOWED"
        else (
            "POL-ACTION-HUMAN-APPROVAL"
            if (
                outcome
                == "APPROVAL_REQUIRED"
            )
            else (
                "POL-ACTION-"
                "PROTECTED-TARGET"
            )
        )
    )

    return IncidentPolicyDecisionRecord(
        decision_id="PDEC-M6-001",
        incident_id="INC-M6-001",
        proposed_action_id=(
            proposed_action_id
        ),
        policy_id=policy_id,
        outcome=outcome,
        reason=(
            "Deterministic action "
            "policy result."
        ),
        decided_at=FIXED_TIME,
    )


def make_approved_request(
    *,
    store,
    action,
    policy,
):
    pending = (
        create_approval_request(
            proposed_action=action,
            policy_decision=policy,
            requested_at=FIXED_TIME,
            expires_at=(
                FIXED_TIME
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
            reason=(
                "Approved exact "
                "containment action."
            ),
            decided_at=(
                FIXED_TIME
                + timedelta(minutes=5)
            ),
        )
    )

    store.save_approval_request(
        approved
    )

    return approved


def test_auto_allowed_action_executes_and_persists():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    action = make_action()

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=(
            make_policy()
        ),
        executor=executor,
        autonomous_response_enabled=True,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "executed"
    )

    assert executor.calls == [
        action,
    ]

    assert (
        result.response_action
        is not None
    )

    assert (
        result.response_action.status
        == "completed"
    )

    assert (
        result.response_action
        .approval_id
        is None
    )

    assert (
        result.action_result
        is not None
    )

    assert (
        result.action_result.status
        == "completed"
    )

    assert (
        store.get_response_action(
            result.response_action
            .response_action_id
        )
        == result.response_action
    )

    assert (
        store.get_action_result(
            result.action_result
            .action_result_id
        )
        == result.action_result
    )


def test_pending_approval_does_not_execute():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    action = make_action()

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    pending = (
        create_approval_request(
            proposed_action=action,
            policy_decision=policy,
            requested_at=FIXED_TIME,
            expires_at=(
                FIXED_TIME
                + timedelta(minutes=30)
            ),
        )
    )

    store.save_approval_request(
        pending
    )

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=policy,
        approval_id=(
            pending.approval_id
        ),
        executor=executor,
        autonomous_response_enabled=True,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "awaiting_approval"
    )

    assert executor.calls == []

    assert (
        result.response_action
        is None
    )


def test_exact_approved_action_executes():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    action = make_action()

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    approval = (
        make_approved_request(
            store=store,
            action=action,
            policy=policy,
        )
    )

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=policy,
        approval_id=(
            approval.approval_id
        ),
        executor=executor,
        autonomous_response_enabled=True,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "executed"
    )

    assert executor.calls == [
        action,
    ]

    assert (
        result.response_action
        .approval_id
        == approval.approval_id
    )


def test_modified_action_cannot_use_existing_approval():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    original = make_action()

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    approval = (
        make_approved_request(
            store=store,
            action=original,
            policy=policy,
        )
    )

    modified = make_action(
        duration_minutes=600,
    )

    with pytest.raises(
        ValueError,
        match="fingerprint",
    ):
        execute_structured_action(
            store=store,
            proposed_action=modified,
            policy_decision=policy,
            approval_id=(
                approval.approval_id
            ),
            executor=executor,
            autonomous_response_enabled=True,
            now=FIXED_TIME,
        )

    assert executor.calls == []


def test_not_allowed_action_never_executes():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    result = execute_structured_action(
        store=store,
        proposed_action=make_action(),
        policy_decision=(
            make_policy(
                outcome="NOT_ALLOWED"
            )
        ),
        executor=executor,
        autonomous_response_enabled=True,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "blocked"
    )

    assert executor.calls == []

    assert (
        result.response_action
        is None
    )


def test_kill_switch_blocks_execution_and_creates_case():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    result = execute_structured_action(
        store=store,
        proposed_action=make_action(),
        policy_decision=(
            make_policy()
        ),
        executor=executor,
        autonomous_response_enabled=False,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "blocked"
    )

    assert executor.calls == []

    assert (
        result.response_action
        is not None
    )

    assert (
        result.response_action.status
        == "blocked"
    )

    cases = (
        store.list_incident_cases(
            "INC-M6-001"
        )
    )

    assert len(cases) == 1


def test_executor_failure_persists_failure_and_case():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeFailingExecutor()
    )

    action = make_action()

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=(
            make_policy()
        ),
        executor=executor,
        autonomous_response_enabled=True,
        now=FIXED_TIME,
    )

    assert (
        result.outcome
        == "failed"
    )

    assert executor.calls == [
        action,
    ]

    assert (
        result.response_action
        is not None
    )

    assert (
        result.response_action.status
        == "failed"
    )

    assert (
        result.action_result
        is not None
    )

    assert (
        result.action_result.status
        == "failed"
    )

    cases = (
        store.list_incident_cases(
            "INC-M6-001"
        )
    )

    assert len(cases) == 1


def test_policy_action_identity_mismatch_fails_closed():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    with pytest.raises(
        ValueError,
        match="proposed action",
    ):
        execute_structured_action(
            store=store,
            proposed_action=make_action(),
            policy_decision=(
                make_policy(
                    proposed_action_id=(
                        "PACT-OTHER"
                    )
                )
            ),
            executor=executor,
            autonomous_response_enabled=True,
            now=FIXED_TIME,
        )

    assert executor.calls == []


class MutableProtectionRegistry:
    def __init__(
        self,
        *,
        protected=False,
        allowlisted=False,
        fail=False,
    ):
        self.protected = protected
        self.allowlisted = allowlisted
        self.fail = fail
        self.calls = []

    def inspect(
        self,
        *,
        target_type,
        target,
    ):
        self.calls.append(
            (
                target_type,
                target,
            )
        )

        if self.fail:
            raise RuntimeError(
                "Protection registry unavailable."
            )

        from app.services.target_protection import (
            TargetProtectionObservation,
        )

        return TargetProtectionObservation(
            protected_target=(
                self.protected
            ),
            allowlisted_target=(
                self.allowlisted
            ),
        )


def test_execution_rechecks_target_protection_before_cortex():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    protection = (
        MutableProtectionRegistry(
            protected=True
        )
    )

    result = execute_structured_action(
        store=store,
        proposed_action=make_action(),
        policy_decision=make_policy(),
        executor=executor,
        autonomous_response_enabled=True,
        target_protection_registry=(
            protection
        ),
        now=FIXED_TIME,
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    assert protection.calls == [
        (
            "ip",
            "203.0.113.10",
        )
    ]

    assert (
        result.response_action
        is not None
    )

    assert (
        result.response_action.status
        == "blocked"
    )

    cases = (
        store.list_incident_cases(
            "INC-M6-001"
        )
    )

    assert len(cases) == 1

    assert (
        "protected"
        in cases[0].reason.lower()
    )


def test_execution_rechecks_allowlist_before_cortex():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    protection = (
        MutableProtectionRegistry(
            allowlisted=True
        )
    )

    result = execute_structured_action(
        store=store,
        proposed_action=make_action(),
        policy_decision=make_policy(),
        executor=executor,
        autonomous_response_enabled=True,
        target_protection_registry=(
            protection
        ),
        now=FIXED_TIME,
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    cases = (
        store.list_incident_cases(
            "INC-M6-001"
        )
    )

    assert len(cases) == 1

    assert (
        "allowlisted"
        in cases[0].reason.lower()
    )


def test_approved_action_is_blocked_if_target_becomes_protected():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    action = make_action(
        duration_minutes=480
    )

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    approval = (
        make_approved_request(
            store=store,
            action=action,
            policy=policy,
        )
    )

    protection = (
        MutableProtectionRegistry(
            protected=True
        )
    )

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=policy,
        approval_id=(
            approval.approval_id
        ),
        executor=executor,
        autonomous_response_enabled=True,
        target_protection_registry=(
            protection
        ),
        now=(
            FIXED_TIME
            + timedelta(minutes=10)
        ),
    )

    assert result.outcome == "blocked"

    assert executor.calls == []


def test_protection_lookup_failure_fails_closed():
    store = (
        InMemoryIncidentResponseStore()
    )

    executor = (
        FakeSuccessfulExecutor()
    )

    protection = (
        MutableProtectionRegistry(
            fail=True
        )
    )

    result = execute_structured_action(
        store=store,
        proposed_action=make_action(),
        policy_decision=make_policy(),
        executor=executor,
        autonomous_response_enabled=True,
        target_protection_registry=(
            protection
        ),
        now=FIXED_TIME,
    )

    assert result.outcome == "blocked"

    assert executor.calls == []

    cases = (
        store.list_incident_cases(
            "INC-M6-001"
        )
    )

    assert len(cases) == 1

    assert (
        "protection"
        in cases[0].reason.lower()
    )


def test_persisted_protection_change_invalidates_prior_approval():
    from app.services.target_protection import (
        PersistentTargetProtectionRegistry,
        TargetProtectionManager,
        initialize_target_protection_store_from_env,
    )
    from app.services.target_protection_store import (
        InMemoryTargetProtectionStore,
    )

    store = InMemoryIncidentResponseStore()

    protection_store = (
        InMemoryTargetProtectionStore()
    )

    initialize_target_protection_store_from_env(
        protection_store
    )

    registry = (
        PersistentTargetProtectionRegistry(
            protection_store
        )
    )

    manager = TargetProtectionManager(
        store=protection_store,
        clock=lambda: FIXED_TIME,
    )

    action = make_action(
        duration_minutes=480
    )

    policy = make_policy(
        outcome="APPROVAL_REQUIRED"
    )

    approval = make_approved_request(
        store=store,
        action=action,
        policy=policy,
    )

    before = registry.inspect(
        target_type=action.target_type,
        target=action.target,
    )

    assert before.protected_target is False

    manager.replace(
        protected_ips=[
            action.target,
        ],
        changed_by="analyst-002",
        reason=(
            "Target became protected "
            "after approval."
        ),
    )

    executor = FakeSuccessfulExecutor()

    result = execute_structured_action(
        store=store,
        proposed_action=action,
        policy_decision=policy,
        approval_id=approval.approval_id,
        executor=executor,
        autonomous_response_enabled=True,
        target_protection_registry=registry,
        now=(
            FIXED_TIME
            + timedelta(minutes=10)
        ),
    )

    assert result.outcome == "blocked"
    assert executor.calls == []

    cases = store.list_incident_cases(
        "INC-M6-001"
    )

    assert len(cases) == 1

    assert (
        "protected"
        in cases[0].reason.lower()
    )
