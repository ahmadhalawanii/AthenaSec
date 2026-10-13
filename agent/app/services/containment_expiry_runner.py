"""Explicitly deployed expiry daemon: python -m app.services.containment_expiry_runner.

No FastAPI startup side effect; deploy exactly one managed service instance
(or multiple instances backed by the same PostgreSQL advisory locks).
"""
import argparse
import os
import socket
import time
from datetime import datetime, timezone

from app.services.audit_store import AuditStore
from app.services.containment_expiry_worker import (
    process_due_containment_expiries,
    reconcile_expired_containment_claims,
)
from app.services.cortex_config import build_structured_cortex_runtime_from_env
from app.services.persistence_config import (
    build_containment_expiry_store_from_env,
    build_incident_response_store_from_env,
    build_persistence_stores_from_env,
    build_runtime_control_store_from_env,
)
from app.services.target_operation_coordinator import (
    PostgresTargetOperationCoordinator,
)


def execution_enabled(global_enabled, runtime_control_store):
    state = runtime_control_store.get_state()
    return bool(
        global_enabled
        and state is not None
        and state.operator_execution_enabled
        and state.response_mode != "SHADOW"
    )


def run_expiry_cycle(
    *, expiry_store, response_store, audit_store: AuditStore,
    runtime_control_store, rollback_executor, verifier,
    target_coordinator, global_enabled, worker_id,
    clock=lambda: datetime.now(timezone.utc),
):
    # Reconcile even if automatic Cortex execution has been disabled.
    stale = reconcile_expired_containment_claims(
        expiry_store=expiry_store,
        response_store=response_store,
        audit_store=audit_store,
        clock=clock,
    )
    # The persisted runtime controls are refreshed at every cycle and
    # immediately before external Cortex execution.
    check = lambda: execution_enabled(
        global_enabled, runtime_control_store
    )
    completed = process_due_containment_expiries(
        expiry_store=expiry_store,
        response_store=response_store,
        audit_store=audit_store,
        rollback_executor=rollback_executor,
        verifier=verifier,
        target_coordinator=target_coordinator,
        worker_id=worker_id,
        autonomous_response_enabled=check(),
        can_execute_now=check,
        clock=clock,
    )
    return {"stale": len(stale), "processed": len(completed)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if not 5 <= args.interval <= 3600:
        raise SystemExit("Polling interval must be 5-3600 seconds.")

    backend = os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower()
    if backend != "postgres":
        raise SystemExit(
            "Automatic expiry runner requires PostgreSQL for cross-process locks."
        )

    dsn = os.getenv("ATHENASEC_DATABASE_URL")
    if not dsn:
        raise SystemExit("ATHENASEC_DATABASE_URL is required.")

    expiry_store = build_containment_expiry_store_from_env()
    response_store = build_incident_response_store_from_env()
    _, audit_store = build_persistence_stores_from_env()
    control_store = build_runtime_control_store_from_env()
    cortex = build_structured_cortex_runtime_from_env()

    enabled = os.getenv("AUTONOMOUS_RESPONSE_ENABLED", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if enabled and cortex is None:
        raise SystemExit("Cortex structured execution/verification configuration is required.")

    coordinator = PostgresTargetOperationCoordinator(dsn)
    worker_id = f"athenasec-expiry:{socket.gethostname()}:{os.getpid()}"
    while True:
        run_expiry_cycle(
            expiry_store=expiry_store,
            response_store=response_store,
            audit_store=audit_store,
            runtime_control_store=control_store,
            rollback_executor=cortex.rollback_executor if cortex else None,
            verifier=cortex.verifier if cortex else None,
            target_coordinator=coordinator,
            global_enabled=enabled,
            worker_id=worker_id,
        )
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
