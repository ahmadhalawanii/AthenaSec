"""Regression: only one decision may win for any PENDING approval."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4
import os

import pytest

from app.schemas import IncidentPolicyDecisionRecord, ProposedActionRecord
from app.services.action_approval import create_approval_request
from app.services.approval_resolution import resolve_approval_request
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
    SQLiteIncidentResponseStore,
    PostgresIncidentResponseStore,
)


def seed(store):
    now = datetime.now(timezone.utc)
    suffix = uuid4().hex
    action = ProposedActionRecord(
        proposed_action_id="PACT-" + suffix,
        incident_id="INC-" + suffix,
        investigation_id="INV-" + suffix,
        action_type="block_ip", target_type="ip", target="203.0.113.10",
        parameters={"duration_minutes": 480}, reversible=True,
        rollback_action_type="unblock_ip", rollback_parameters={},
        reason="Test pending action", proposed_at=now,
    )
    policy = IncidentPolicyDecisionRecord(
        decision_id="PDEC-" + suffix, incident_id=action.incident_id,
        proposed_action_id=action.proposed_action_id,
        policy_id="POL-ACTION-HUMAN-APPROVAL",
        outcome="APPROVAL_REQUIRED", reason="Human approval required",
        decided_at=now,
    )
    pending = create_approval_request(
        proposed_action=action, policy_decision=policy,
        requested_at=now, expires_at=now + timedelta(minutes=30),
    )
    store.save_proposed_action(action)
    store.save_policy_decision(policy)
    store.save_approval_request(pending)
    return pending


class SynchronizedReads:
    """Force two requests to fetch the SAME pending snapshot."""
    def __init__(self, store):
        self.store = store
        self.barrier = Barrier(2)

    def get_approval_request(self, approval_id):
        item = self.store.get_approval_request(approval_id)
        if item is not None and item.status == "PENDING":
            self.barrier.wait(timeout=8)
        return item

    def __getattr__(self, name):
        return getattr(self.store, name)


def compete(store):
    pending = seed(store)
    synchronized = SynchronizedReads(store)

    def decide(decision):
        try:
            result = resolve_approval_request(
                store=synchronized, approval_id=pending.approval_id,
                decision=decision, decided_by="test-" + decision,
                reason="Test concurrency",
            )
            return ("accepted", result.approval.status)
        except ValueError:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, ("APPROVED", "REJECTED")))

    assert sorted(value[0] for value in results) == ["accepted", "conflict"]
    final = store.get_approval_request(pending.approval_id)
    assert final.status in {"APPROVED", "REJECTED"}
    assert [value[1] for value in results if value[0] == "accepted"] == [final.status]
    cases = store.list_incident_cases(pending.incident_id)
    assert len(cases) == (1 if final.status == "REJECTED" else 0)


def test_parallel_competing_decisions_in_memory():
    compete(InMemoryIncidentResponseStore())


def test_parallel_competing_decisions_sqlite(tmp_path):
    compete(SQLiteIncidentResponseStore(tmp_path / "approvals.db"))


@pytest.mark.skipif(not os.getenv("ATHENASEC_TEST_PG_URL"), reason="ATHENASEC_TEST_PG_URL not configured")
def test_parallel_competing_decisions_real_postgres():
    compete(PostgresIncidentResponseStore(os.environ["ATHENASEC_TEST_PG_URL"]))


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_stale_pending_replay_cannot_reset_terminal_approval(tmp_path, backend):
    store = (InMemoryIncidentResponseStore() if backend == "memory" else
             SQLiteIncidentResponseStore(tmp_path / "replay.db"))
    pending = seed(store)
    result = resolve_approval_request(
        store=store, approval_id=pending.approval_id,
        decision="APPROVED", decided_by="test-analyst", reason="Authorized",
    )
    assert result.approval.status == "APPROVED"
    store.save_approval_request(pending)
    assert store.get_approval_request(pending.approval_id).status == "APPROVED"


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_terminal_approval_cannot_be_atomically_overwritten(tmp_path, backend):
    store = (InMemoryIncidentResponseStore() if backend == "memory" else
             SQLiteIncidentResponseStore(tmp_path / "replay.db"))
    pending = seed(store)
    result = resolve_approval_request(
        store=store, approval_id=pending.approval_id,
        decision="APPROVED", decided_by="test-analyst", reason="Authorized",
    )
    changed = result.approval.model_copy(update={"status": "REJECTED"})
    assert store.transition_pending_approval(changed) is False
    assert store.get_approval_request(pending.approval_id).status == "APPROVED"
