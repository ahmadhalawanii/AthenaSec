from datetime import datetime, timedelta, timezone

from app.schemas import (
    ActionExecutionResultRecord,
    ActionVerificationRecord,
    ContainmentExpiryRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
    _verification_id,
)
from app.services.audit_store import InMemoryAuditStore
from app.services.containment_expiry_store import (
    InMemoryContainmentExpiryStore,
    SQLiteContainmentExpiryStore,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
    _action_result_id,
)
from app.services.containment_expiry_worker import (
    process_due_containment_expiries,
    reconcile_expired_containment_claims,
)


BASE = datetime(
    2026, 10, 9, 12, 0,
    tzinfo=timezone.utc,
)
NOW = BASE + timedelta(minutes=31)


class FakeRollback:
    def __init__(self, fails=False):
        self.calls = []
        self.fails = fails

    def rollback(self, action):
        self.calls.append(action)

        if self.fails:
            raise RuntimeError("Cortex unavailable.")

        return StructuredExecutorResult(
            message="Unblock submitted.",
            details={},
        )


class FakeVerifier:
    def __init__(self, blocked=False):
        self.blocked = blocked
        self.calls = []

    def verify_unblocked(self, target):
        self.calls.append(target)

        return StructuredVerificationObservation(
            status=(
                "FAILED"
                if self.blocked
                else "SUCCESS"
            ),
            message="Independent state checked.",
            details={
                "target": target,
                "blocked": self.blocked,
            },
        )


def setup_records(expiry_store=None):
    response_store = InMemoryIncidentResponseStore()
    audit_store = InMemoryAuditStore()

    if expiry_store is None:
        expiry_store = InMemoryContainmentExpiryStore()

    action = ProposedActionRecord(
        proposed_action_id="PACT-WORKER-001",
        incident_id="INC-WORKER-001",
        investigation_id="INV-WORKER-001",
        action_type="block_ip",
        target_type="ip",
        target="203.0.113.10",
        parameters={"duration_minutes": 30},
        reversible=True,
        rollback_action_type="unblock_ip",
        rollback_parameters={},
        reason="Temporary containment.",
        proposed_at=BASE,
    )

    response = ResponseActionRecord(
        response_action_id="ACT-WORKER-001",
        incident_id=action.incident_id,
        proposed_action_id=action.proposed_action_id,
        approval_id=None,
        executor="cortex",
        status="completed",
        created_at=BASE,
    )

    action_result = ActionExecutionResultRecord(
        action_result_id=_action_result_id(
            response.response_action_id
        ),
        response_action_id=response.response_action_id,
        status="completed",
        message="Block completed.",
        details={},
        recorded_at=BASE,
    )

    verification = ActionVerificationRecord(
        verification_id=_verification_id(
            response_action_id=response.response_action_id,
            action_result_id=action_result.action_result_id,
        ),
        response_action_id=response.response_action_id,
        proposed_action_id=action.proposed_action_id,
        status="SUCCESS",
        message="Block independently verified.",
        details={"blocked": True},
        verified_at=BASE,
    )

    expiry = ContainmentExpiryRecord(
        expiry_id="EXPIRY-WORKER-001",
        incident_id=action.incident_id,
        proposed_action_id=action.proposed_action_id,
        response_action_id=response.response_action_id,
        rollback_action_type="unblock_ip",
        target=action.target,
        rollback_parameters={},
        due_at=BASE + timedelta(minutes=30),
        status="PENDING",
        attempt_count=0,
        created_at=BASE,
        updated_at=BASE,
    )

    response_store.save_proposed_action(action)
    response_store.save_response_action(response)
    response_store.save_action_result(action_result)
    response_store.save_action_verification(verification)
    expiry_store.save_expiry(expiry)

    return response_store, expiry_store, audit_store, expiry


def run_worker(
    response_store,
    expiry_store,
    audit_store,
    rollback,
    verifier,
    *,
    enabled=True,
):
    return process_due_containment_expiries(
        expiry_store=expiry_store,
        response_store=response_store,
        audit_store=audit_store,
        rollback_executor=rollback,
        verifier=verifier,
        worker_id="worker-001",
        autonomous_response_enabled=enabled,
        clock=lambda: NOW,
    )


def test_due_expiry_executes_verifies_and_completes():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert len(results) == 1
    assert results[0].status == "COMPLETED"
    assert results[0].completed_at == NOW

    assert len(rollback.calls) == 1
    assert verifier.calls == ["203.0.113.10"]

    assert expiries.get_expiry(
        expiry.expiry_id
    ) == results[0]

    assert response.list_incident_cases(
        expiry.incident_id
    ) == []

    events = audits.list_by_incident_id(
        expiry.incident_id
    )

    assert any(
        event.event_type == "containment_expiry_completed"
        for event in events
    )


def test_completed_expiry_is_not_executed_twice():
    response, expiries, audits, _ = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier()

    first = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    second = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert len(first) == 1
    assert second == []
    assert len(rollback.calls) == 1
    assert len(verifier.calls) == 1


def test_still_blocked_is_failed_and_creates_case():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier(blocked=True)

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert results[0].status == "FAILED"
    assert results[0].completed_at is None
    assert len(rollback.calls) == 1

    assert len(response.list_incident_cases(
        expiry.incident_id
    )) == 1

    events = audits.list_by_incident_id(
        expiry.incident_id
    )

    assert any(
        event.event_type == "containment_expiry_failed"
        for event in events
    )


def test_cortex_unblock_failure_is_not_completed():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback(fails=True)
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert results[0].status == "FAILED"
    assert verifier.calls == []
    assert len(response.list_incident_cases(
        expiry.incident_id
    )) == 1


def test_corrupt_source_blocks_cortex_execution():
    response, expiries, audits, expiry = setup_records()

    original = response.get_proposed_action(
        expiry.proposed_action_id
    )

    response.save_proposed_action(
        original.model_copy(
            update={"target": "198.51.100.25"}
        )
    )

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert results[0].status == "FAILED"
    assert rollback.calls == []
    assert verifier.calls == []


def test_global_kill_switch_prevents_cortex():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
        enabled=False,
    )

    assert results == []
    assert rollback.calls == []
    assert verifier.calls == []

    assert expiries.get_expiry(
        expiry.expiry_id
    ).status == "PENDING"


def test_sqlite_completed_expiry_survives_restart(tmp_path):
    database = tmp_path / "worker.db"

    store = SQLiteContainmentExpiryStore(database)

    response, expiries, audits, expiry = setup_records(
        store
    )

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    restarted = SQLiteContainmentExpiryStore(
        database
    )

    assert results[0].status == "COMPLETED"
    assert restarted.get_expiry(
        expiry.expiry_id
    ) == results[0]

    assert run_worker(
        response, restarted, audits,
        rollback, verifier,
    ) == []

    assert len(rollback.calls) == 1


def test_expired_lease_before_cortex_prevents_unblock():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier()

    moments = iter([
        NOW,
        NOW + timedelta(seconds=121),
        NOW + timedelta(seconds=121),
    ])

    results = process_due_containment_expiries(
        expiry_store=expiries,
        response_store=response,
        audit_store=audits,
        rollback_executor=rollback,
        verifier=verifier,
        worker_id="worker-001",
        autonomous_response_enabled=True,
        clock=lambda: next(moments),
        lease_seconds=120,
    )

    assert results == []
    assert rollback.calls == []
    assert verifier.calls == []

    assert expiries.get_expiry(
        expiry.expiry_id
    ).status == "CLAIMED"

    assert len(
        response.list_incident_cases(expiry.incident_id)
    ) == 1


def test_lost_lease_ownership_prevents_cortex_unblock():
    class LeaseStolenStore(InMemoryContainmentExpiryStore):
        def claim_due_expiries(self, **kwargs):
            records = super().claim_due_expiries(**kwargs)

            for record in records:
                self.save_expiry(
                    record.model_copy(
                        update={
                            "lease_owner": "worker-002",
                        }
                    )
                )

            return records

    expiries = LeaseStolenStore()

    response, expiries, audits, expiry = setup_records(
        expiries
    )

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert results == []
    assert rollback.calls == []
    assert verifier.calls == []

    claimed = expiries.get_expiry(expiry.expiry_id)

    assert claimed.status == "CLAIMED"
    assert claimed.lease_owner == "worker-002"

    assert len(
        response.list_incident_cases(expiry.incident_id)
    ) == 1

def test_newer_containment_prevents_old_unblock():
    response, expiries, audits, expiry = setup_records()

    newer = expiry.model_copy(
        update={
            "expiry_id": "EXPIRY-NEWER-002",
            "incident_id": "INC-NEWER-002",
            "proposed_action_id": "PACT-NEWER-002",
            "response_action_id": "ACT-NEWER-002",
            "created_at": BASE + timedelta(minutes=10),
            "updated_at": BASE + timedelta(minutes=10),
            "due_at": BASE + timedelta(minutes=60),
        }
    )

    expiries.save_expiry(newer)

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert len(results) == 1
    assert results[0].status == "FAILED"
    assert rollback.calls == []
    assert verifier.calls == []

    assert len(
        response.list_incident_cases(expiry.incident_id)
    ) == 1


def test_older_active_containment_prevents_newer_unblock():
    response, expiries, audits, expiry = setup_records()

    older = expiry.model_copy(
        update={
            "expiry_id": "EXPIRY-OLDER-002",
            "incident_id": "INC-OLDER-002",
            "proposed_action_id": "PACT-OLDER-002",
            "response_action_id": "ACT-OLDER-002",
            "created_at": BASE - timedelta(minutes=10),
            "updated_at": BASE - timedelta(minutes=10),
            "due_at": BASE + timedelta(minutes=90),
        }
    )

    expiries.save_expiry(older)

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert len(results) == 1
    assert results[0].status == "FAILED"
    assert rollback.calls == []
    assert verifier.calls == []

    assert len(
        response.list_incident_cases(expiry.incident_id)
    ) == 1


def test_unrelated_ip_containment_does_not_block_unblock():
    response, expiries, audits, expiry = setup_records()

    other = expiry.model_copy(
        update={
            "expiry_id": "EXPIRY-OTHER-IP",
            "incident_id": "INC-OTHER-IP",
            "proposed_action_id": "PACT-OTHER-IP",
            "response_action_id": "ACT-OTHER-IP",
            "target": "198.51.100.25",
            "due_at": BASE + timedelta(minutes=60),
        }
    )

    expiries.save_expiry(other)

    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = run_worker(
        response, expiries, audits,
        rollback, verifier,
    )

    assert len(results) == 1
    assert results[0].status == "COMPLETED"
    assert len(rollback.calls) == 1
    assert verifier.calls == ["203.0.113.10"]


def test_expired_claim_reconciliation_creates_case_once():
    response, expiries, audits, expiry = setup_records()

    claimed = expiries.claim_due_expiries(
        now=NOW,
        worker_id="crashed-worker",
        lease_seconds=30,
    )[0]

    later = NOW + timedelta(seconds=31)

    first = reconcile_expired_containment_claims(
        expiry_store=expiries,
        response_store=response,
        audit_store=audits,
        clock=lambda: later,
    )

    second = reconcile_expired_containment_claims(
        expiry_store=expiries,
        response_store=response,
        audit_store=audits,
        clock=lambda: later,
    )

    assert first == [claimed]
    assert second == [claimed]

    assert expiries.get_expiry(
        expiry.expiry_id
    ).status == "CLAIMED"

    assert len(response.list_incident_cases(
        expiry.incident_id
    )) == 1

    events = audits.list_by_incident_id(
        expiry.incident_id
    )

    assert len([
        event for event in events
        if event.event_type
        == "containment_expiry_reconciliation_required"
    ]) == 1


def test_active_claim_is_not_reconciled():
    response, expiries, audits, expiry = setup_records()

    expiries.claim_due_expiries(
        now=NOW,
        worker_id="active-worker",
        lease_seconds=120,
    )

    result = reconcile_expired_containment_claims(
        expiry_store=expiries,
        response_store=response,
        audit_store=audits,
        clock=lambda: NOW + timedelta(seconds=30),
    )

    assert result == []
    assert response.list_incident_cases(
        expiry.incident_id
    ) == []


def test_live_execution_switch_prevents_unblock():
    response, expiries, audits, expiry = setup_records()
    rollback = FakeRollback()
    verifier = FakeVerifier()

    results = process_due_containment_expiries(
        expiry_store=expiries,
        response_store=response,
        audit_store=audits,
        rollback_executor=rollback,
        verifier=verifier,
        worker_id="worker-001",
        autonomous_response_enabled=True,
        can_execute_now=lambda: False,
        clock=lambda: NOW,
    )

    assert len(results) == 1
    assert results[0].status == "FAILED"
    assert rollback.calls == []
    assert verifier.calls == []

    assert len(response.list_incident_cases(
        expiry.incident_id
    )) == 1


def test_sqlite_stale_claim_detected_after_restart(tmp_path):
    database = tmp_path / "stale-claims.db"

    store = SQLiteContainmentExpiryStore(database)

    response, _, audits, expiry = setup_records(
        store
    )

    store.claim_due_expiries(
        now=NOW,
        worker_id="crashed-worker",
        lease_seconds=30,
    )

    restarted = SQLiteContainmentExpiryStore(
        database
    )

    stale = reconcile_expired_containment_claims(
        expiry_store=restarted,
        response_store=response,
        audit_store=audits,
        clock=lambda: NOW + timedelta(seconds=31),
    )

    assert len(stale) == 1
    assert stale[0].expiry_id == expiry.expiry_id

    assert len(response.list_incident_cases(
        expiry.incident_id
    )) == 1

