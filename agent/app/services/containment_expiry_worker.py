import ipaddress

from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import NAMESPACE_URL, uuid5

from app.schemas import (
    ContainmentExpiryRecord,
    IncidentAuditRecord,
    IncidentCaseRecord,
)
from app.services.action_rollback import (
    rollback_verified_structured_action,
)
from app.services.action_verification import (
    _verification_id,
)
from app.services.audit_store import AuditStore
from app.services.containment_expiry_store import (
    ContainmentExpiryStore,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)
from app.services.structured_execution import (
    _action_result_id,
)


def _utc_now():
    return datetime.now(timezone.utc)


def _identity(prefix, value):
    return prefix + str(
        uuid5(NAMESPACE_URL, value)
    ).upper()


def _validate_original_containment(
    *,
    expiry,
    store,
):
    action = store.get_proposed_action(
        expiry.proposed_action_id
    )

    response = store.get_response_action(
        expiry.response_action_id
    )

    if action is None or response is None:
        raise ValueError(
            "Original containment records missing."
        )

    if (
        action.incident_id != expiry.incident_id
        or action.proposed_action_id
        != response.proposed_action_id
        or response.incident_id != expiry.incident_id
        or action.action_type != "block_ip"
        or action.target_type != "ip"
        or action.target != expiry.target
        or action.rollback_action_type != "unblock_ip"
        or expiry.rollback_action_type != "unblock_ip"
        or action.rollback_parameters != {}
        or expiry.rollback_parameters != {}
        or not action.reversible
        or response.status != "completed"
        or response.executor != "cortex"
    ):
        raise ValueError(
            "Original containment identity invalid."
        )

    if expiry.target != expiry.target.strip():
        raise ValueError(
            "Containment expiry IP target invalid."
        )

    ipaddress.ip_address(expiry.target)

    duration = action.parameters.get(
        "duration_minutes"
    )

    if (
        type(duration) is not int
        or not 1 <= duration <= 1440
    ):
        raise ValueError(
            "Original containment duration invalid."
        )

    result = store.get_action_result(
        _action_result_id(
            response.response_action_id
        )
    )

    if (
        result is None
        or result.status != "completed"
        or result.response_action_id
        != response.response_action_id
    ):
        raise ValueError(
            "Original execution result invalid."
        )

    verification = store.get_action_verification(
        _verification_id(
            response_action_id=response.response_action_id,
            action_result_id=result.action_result_id,
        )
    )

    if (
        verification is None
        or verification.status != "SUCCESS"
        or verification.response_action_id
        != response.response_action_id
        or verification.proposed_action_id
        != action.proposed_action_id
        or expiry.due_at
        != verification.verified_at
        + timedelta(minutes=duration)
    ):
        raise ValueError(
            "Original block verification invalid."
        )

    return action, response, verification


def _create_failure_case(
    *,
    expiry,
    response_store,
    reason,
    now,
):
    original = response_store.get_proposed_action(
        expiry.proposed_action_id
    )

    case_id = _identity(
        "CASE-",
        "athenasec-expiry-failure:"
        + expiry.expiry_id,
    )

    existing = response_store.get_incident_case(
        case_id
    )

    if existing is not None:
        return existing

    record = IncidentCaseRecord(
        case_id=case_id,
        incident_id=expiry.incident_id,
        investigation_id=(
            original.investigation_id
            if original is not None
            else None
        ),
        policy_decision_id=None,
        status="open",
        reason=reason,
        created_at=now,
        updated_at=now,
    )

    return response_store.save_incident_case(
        record
    )


def _audit_terminal_state(
    *,
    audit_store,
    record,
    now,
):
    event_type = (
        "containment_expiry_completed"
        if record.status == "COMPLETED"
        else "containment_expiry_failed"
    )

    audit_id = _identity(
        "IAUDIT-",
        "athenasec-expiry:"
        + record.expiry_id
        + ":"
        + str(record.attempt_count)
        + ":"
        + record.status,
    )

    if audit_store.get_incident_event(
        audit_id
    ) is not None:
        return

    audit_store.save_incident_event(
        IncidentAuditRecord(
            audit_id=audit_id,
            incident_id=record.incident_id,
            event_type=event_type,
            entity_type="containment_expiry",
            entity_id=record.expiry_id,
            message=(
                "Temporary containment expiry "
                + record.status.lower()
                + "."
            ),
            details={
                "expiry_id": record.expiry_id,
                "response_action_id": (
                    record.response_action_id
                ),
                "rollback_action_type": (
                    record.rollback_action_type
                ),
                "attempt_count": (
                    record.attempt_count
                ),
                "status": record.status,
                "last_error": record.last_error,
            },
            timestamp=now,
        )
    )


def process_due_containment_expiries(
    *,
    expiry_store: ContainmentExpiryStore,
    response_store: IncidentResponseStore,
    audit_store: AuditStore,
    rollback_executor,
    verifier,
    worker_id: str,
    autonomous_response_enabled: bool,
    can_execute_now: Callable[[], bool] | None = None,
    clock: Callable[[], datetime] = _utc_now,
    lease_seconds: int = 120,
    limit: int = 25,
) -> list[ContainmentExpiryRecord]:
    if not autonomous_response_enabled:
        return []

    claimed = expiry_store.claim_due_expiries(
        now=clock(),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        limit=limit,
    )

    finished_records = []

    for expiry in claimed:
        stage = "source"
        reason = None

        try:
            action, response, verification = (
                _validate_original_containment(
                    expiry=expiry,
                    store=response_store,
                )
            )

            if rollback_executor is None:
                raise RuntimeError(
                    "Cortex rollback executor unavailable."
                )

            if verifier is None:
                raise RuntimeError(
                    "Cortex read-only verifier unavailable."
                )

            current_claim = expiry_store.get_expiry(
                expiry.expiry_id
            )

            lease_now = clock()

            if (
                current_claim is None
                or current_claim.status != "CLAIMED"
                or current_claim.lease_owner != worker_id
                or current_claim.attempt_count
                != expiry.attempt_count
                or current_claim.incident_id
                != expiry.incident_id
                or current_claim.response_action_id
                != expiry.response_action_id
                or current_claim.target != expiry.target
                or current_claim.lease_expires_at is None
                or current_claim.lease_expires_at.tzinfo is None
                or lease_now.tzinfo is None
                or lease_now.utcoffset() is None
                or current_claim.lease_expires_at <= lease_now
            ):
                raise RuntimeError(
                    "Containment expiry lease is no "
                    "longer valid before Cortex execution."
                )

            stage = "overlap"

            if expiry_store.has_other_unresolved_containment(
                expiry_id=expiry.expiry_id,
                target=expiry.target,
            ):
                raise RuntimeError(
                    "Another unresolved containment "
                    "exists for the same IP."
                )

            stage = "source"

            if (
                can_execute_now is not None
                and can_execute_now() is not True
            ):
                raise RuntimeError(
                    "Autonomous execution is currently disabled."
                )

            stage = "rollback"

            rollback = rollback_verified_structured_action(
                store=response_store,
                proposed_action=action,
                response_action=response,
                verification=verification,
                rollback_executor=rollback_executor,
                now=clock(),
            )

            if rollback.status != "completed":
                raise RuntimeError(
                    "Cortex unblock was unsuccessful."
                )

            stage = "verification"

            observation = verifier.verify_unblocked(
                expiry.target
            )

            if (
                observation.status != "SUCCESS"
                or observation.details.get("target")
                != expiry.target
                or observation.details.get("blocked")
                is not False
            ):
                raise RuntimeError(
                    "Independent unblock verification failed."
                )

            status = "COMPLETED"

        except Exception:
            status = "FAILED"

            reasons = {
                "overlap": (
                    "Automatic unblock was withheld "
                    "because another unresolved "
                    "containment exists for the IP."
                ),
                "source": (
                    "Original containment validation "
                    "or required runtime capability failed."
                ),
                "rollback": (
                    "Cortex automatic unblock "
                    "did not complete."
                ),
                "verification": (
                    "Read-only verification did not "
                    "confirm block removal."
                ),
            }

            reason = reasons[stage]

        finish_time = clock()

        terminal = expiry_store.finish_claimed_expiry(
            expiry_id=expiry.expiry_id,
            worker_id=worker_id,
            attempt_count=expiry.attempt_count,
            status=status,
            error=reason,
            now=finish_time,
        )

        if terminal is None:
            _create_failure_case(
                expiry=expiry,
                response_store=response_store,
                reason=(
                    "Containment expiry worker lost its "
                    "valid lease before recording the "
                    "terminal result. Reconciliation "
                    "is required."
                ),
                now=finish_time,
            )

            # Do not claim that the unblock completed.
            # Leave the claimed record for reconciliation.
            continue

        if terminal.status == "FAILED":
            _create_failure_case(
                expiry=terminal,
                response_store=response_store,
                reason=(
                    "Automatic containment expiry failed: "
                    + (terminal.last_error or "unknown")
                ),
                now=finish_time,
            )

        _audit_terminal_state(
            audit_store=audit_store,
            record=terminal,
            now=finish_time,
        )

        finished_records.append(terminal)

    return finished_records


def reconcile_expired_containment_claims(
    *,
    expiry_store: ContainmentExpiryStore,
    response_store: IncidentResponseStore,
    audit_store: AuditStore,
    clock: Callable[[], datetime] = _utc_now,
    limit: int = 100,
) -> list[ContainmentExpiryRecord]:
    now = clock()

    stale = expiry_store.list_expired_claimed_expiries(
        now=now,
        limit=limit,
    )

    for expiry in stale:
        _create_failure_case(
            expiry=expiry,
            response_store=response_store,
            reason=(
                "Containment expiry worker lease expired "
                "without a durable terminal outcome. "
                "Reconciliation is required before "
                "any additional unblock attempt."
            ),
            now=now,
        )

        audit_id = _identity(
            "IAUDIT-",
            (
                "athenasec-expiry-stale:"
                + expiry.expiry_id
                + ":"
                + str(expiry.attempt_count)
            ),
        )

        if audit_store.get_incident_event(audit_id) is not None:
            continue

        audit_store.save_incident_event(
            IncidentAuditRecord(
                audit_id=audit_id,
                incident_id=expiry.incident_id,
                event_type=(
                    "containment_expiry_reconciliation_required"
                ),
                entity_type="containment_expiry",
                entity_id=expiry.expiry_id,
                message=(
                    "Containment expiry lease expired "
                    "with an uncertain execution outcome."
                ),
                details={
                    "expiry_id": expiry.expiry_id,
                    "attempt_count": expiry.attempt_count,
                    "lease_owner": expiry.lease_owner,
                    "status": expiry.status,
                    "automatic_retry": False,
                },
                timestamp=now,
            )
        )

    return stale

