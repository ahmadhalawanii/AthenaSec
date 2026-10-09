from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from typing import Literal
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionRollbackRecord,
    ActionVerificationRecord,
    ContainmentExpiryRecord,
    IncidentCaseRecord,
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)
from app.services.action_rollback import (
    StructuredRollbackExecutor,
    rollback_structured_action,
    rollback_verified_structured_action,
)
from app.services.action_verification import (
    StructuredActionVerifier,
    verify_structured_action,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredActionExecutor,
    StructuredExecutionOutcome,
    execute_structured_action,
)
from app.services.response_mode import (
    ResponseMode,
    evaluate_response_mode,
)
from app.services.target_protection import (
    TargetProtectionRegistry,
)
from app.services.containment_expiry import (
    ensure_containment_expiry,
    requires_containment_expiry,
)
from app.services.containment_expiry_store import (
    ContainmentExpiryStore,
)


StructuredRuntimeStatus = Literal[
    "awaiting_approval",
    "shadowed",
    "blocked",
    "failed",
    "verified",
    "rolled_back",
]


@dataclass(
    frozen=True,
)
class StructuredRuntimeOutcome:
    outcome: StructuredRuntimeStatus

    execution: (
        StructuredExecutionOutcome | None
    ) = None

    verification: (
        ActionVerificationRecord | None
    ) = None

    rollback: (
        ActionRollbackRecord | None
    ) = None

    expiry: (
        ContainmentExpiryRecord | None
    ) = None

    incident_case: (
        IncidentCaseRecord | None
    ) = None


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _case_id(
    *,
    proposed_action_id: str,
    policy_decision_id: str,
    reason_code: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-runtime-case:"
            f"{proposed_action_id}:"
            f"{policy_decision_id}:"
            f"{reason_code}"
        ),
    )

    return (
        "CASE-"
        f"{str(value).upper()}"
    )


def _create_case(
    *,
    store: IncidentResponseStore,
    proposed_action: ProposedActionRecord,
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    reason_code: str,
    reason: str,
    now: datetime,
) -> IncidentCaseRecord:
    case = IncidentCaseRecord(
        case_id=_case_id(
            proposed_action_id=(
                proposed_action
                .proposed_action_id
            ),
            policy_decision_id=(
                policy_decision
                .decision_id
            ),
            reason_code=reason_code,
        ),
        incident_id=(
            proposed_action.incident_id
        ),
        investigation_id=(
            proposed_action
            .investigation_id
        ),
        policy_decision_id=(
            policy_decision.decision_id
        ),
        status="open",
        reason=reason,
        created_at=now,
        updated_at=now,
    )

    store.save_incident_case(
        case
    )

    return case


def process_structured_response_action(
    *,
    store: IncidentResponseStore,
    proposed_action: ProposedActionRecord,
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    executor: (
        StructuredActionExecutor | None
    ),
    verifier: (
        StructuredActionVerifier | None
    ),
    rollback_executor: (
        StructuredRollbackExecutor | None
    ),
    autonomous_response_enabled: bool,
    target_protection_registry: (
        TargetProtectionRegistry | None
    ) = None,
    containment_expiry_store: (
        ContainmentExpiryStore | None
    ) = None,
    response_mode: ResponseMode = "SUPERVISED",
    approval_id: str | None = None,
    now: datetime | None = None,
) -> StructuredRuntimeOutcome:
    if (
        policy_decision
        .proposed_action_id
        != proposed_action
        .proposed_action_id
        or policy_decision.incident_id
        != proposed_action.incident_id
    ):
        raise ValueError(
            "Policy decision does not "
            "match the proposed action."
        )

    if now is None:
        now = _utc_now()

    if (
        policy_decision.outcome
        == "NOT_ALLOWED"
    ):
        return StructuredRuntimeOutcome(
            outcome="blocked"
        )

    if (
        policy_decision.outcome
        == "APPROVAL_REQUIRED"
        and approval_id is None
    ):
        return StructuredRuntimeOutcome(
            outcome="awaiting_approval"
        )

    mode_decision = (
        evaluate_response_mode(
            response_mode
        )
    )

    if (
        not mode_decision
        .cortex_execution_allowed
    ):
        return StructuredRuntimeOutcome(
            outcome="shadowed"
        )

    if executor is None:
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "executor-unavailable"
            ),
            reason=(
                "Structured response was "
                "authorized but no Cortex "
                "executor was available."
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    if verifier is None:
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "verifier-unavailable"
            ),
            reason=(
                "Structured response was "
                "not executed because no "
                "post-action verifier was "
                "available."
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    if (
        proposed_action.reversible
        and rollback_executor is None
    ):
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "rollback-unavailable"
            ),
            reason=(
                "Structured response was "
                "not executed because its "
                "required rollback path "
                "was unavailable."
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    try:
        expiry_required = (
            requires_containment_expiry(
                proposed_action
            )
        )

    except ValueError:
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "containment-expiry-contract-invalid"
            ),
            reason=(
                "Structured response was "
                "not executed because its "
                "temporary containment "
                "expiry contract was invalid."
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    if (
        expiry_required
        and containment_expiry_store
        is None
    ):
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "containment-expiry-store-unavailable"
            ),
            reason=(
                "Structured response was "
                "not executed because durable "
                "containment expiry storage "
                "was unavailable."
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    try:
        execution = (
            execute_structured_action(
                store=store,
                proposed_action=(
                    proposed_action
                ),
                policy_decision=(
                    policy_decision
                ),
                executor=executor,
                autonomous_response_enabled=(
                    autonomous_response_enabled
                ),
                target_protection_registry=(
                    target_protection_registry
                ),
                approval_id=approval_id,
                now=now,
            )
        )

    except ValueError as exc:
        case = _create_case(
            store=store,
            proposed_action=proposed_action,
            policy_decision=policy_decision,
            reason_code=(
                "authorization-invalid"
            ),
            reason=(
                "Structured response "
                "authorization failed: "
                f"{exc}"
            ),
            now=now,
        )

        return StructuredRuntimeOutcome(
            outcome="blocked",
            incident_case=case,
        )

    if execution.outcome != "executed":
        return StructuredRuntimeOutcome(
            outcome=(
                execution.outcome
                if execution.outcome
                in {
                    "awaiting_approval",
                    "blocked",
                    "failed",
                }
                else "failed"
            ),
            execution=execution,
            incident_case=(
                execution.incident_case
            ),
        )

    if (
        execution.response_action
        is None
        or execution.action_result
        is None
    ):
        raise ValueError(
            "Executed structured action "
            "is missing persisted "
            "execution records."
        )

    verification = verify_structured_action(
        store=store,
        proposed_action=(
            proposed_action
        ),
        response_action=(
            execution.response_action
        ),
        action_result=(
            execution.action_result
        ),
        verifier=verifier,
        now=now,
    )

    if verification.status == "SUCCESS":
        expiry = None

        if expiry_required:
            try:
                if (
                    containment_expiry_store
                    is None
                ):
                    raise RuntimeError(
                        "Containment expiry "
                        "store unavailable."
                    )

                expiry = (
                    ensure_containment_expiry(
                        store=(
                            containment_expiry_store
                        ),
                        proposed_action=(
                            proposed_action
                        ),
                        response_action=(
                            execution
                            .response_action
                        ),
                        verification=(
                            verification
                        ),
                    )
                )

            except Exception:
                rollback = (
                    rollback_verified_structured_action(
                        store=store,
                        proposed_action=(
                            proposed_action
                        ),
                        response_action=(
                            execution
                            .response_action
                        ),
                        verification=(
                            verification
                        ),
                        rollback_executor=(
                            rollback_executor
                        ),
                        now=now,
                    )
                )

                rollback_status = (
                    rollback.status
                )

                case = _create_case(
                    store=store,
                    proposed_action=(
                        proposed_action
                    ),
                    policy_decision=(
                        policy_decision
                    ),
                    reason_code=(
                        "containment-expiry-"
                        "persistence-failed"
                    ),
                    reason=(
                        "Verified temporary "
                        "containment could not "
                        "be durably scheduled "
                        "for expiry. Immediate "
                        "rollback status: "
                        f"{rollback_status}."
                    ),
                    now=now,
                )

                if (
                    rollback.status
                    == "completed"
                ):
                    outcome = "rolled_back"
                else:
                    outcome = "failed"

                return StructuredRuntimeOutcome(
                    outcome=outcome,
                    execution=execution,
                    verification=verification,
                    rollback=rollback,
                    incident_case=case,
                )

        return StructuredRuntimeOutcome(
            outcome="verified",
            execution=execution,
            verification=verification,
            expiry=expiry,
        )

    rollback = None

    if proposed_action.reversible:
        rollback = (
            rollback_structured_action(
                store=store,
                proposed_action=(
                    proposed_action
                ),
                response_action=(
                    execution
                    .response_action
                ),
                verification=verification,
                rollback_executor=(
                    rollback_executor
                ),
                now=now,
            )
        )

    rollback_status = (
        rollback.status
        if rollback is not None
        else "not_available"
    )

    case = _create_case(
        store=store,
        proposed_action=proposed_action,
        policy_decision=policy_decision,
        reason_code=(
            "verification-"
            + verification.status.lower()
        ),
        reason=(
            "Post-action verification "
            f"returned {verification.status}. "
            "Rollback status: "
            f"{rollback_status}."
        ),
        now=now,
    )

    if (
        rollback is not None
        and rollback.status
        == "completed"
    ):
        outcome = "rolled_back"
    else:
        outcome = "failed"

    return StructuredRuntimeOutcome(
        outcome=outcome,
        execution=execution,
        verification=verification,
        rollback=rollback,
        incident_case=case,
    )
