from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from typing import (
    Any,
    Literal,
    Protocol,
)
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionExecutionResultRecord,
    IncidentCaseRecord,
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.action_approval import (
    approval_matches_action,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)
from app.services.target_protection import (
    TargetProtectionRegistry,
)


StructuredExecutionOutcomeType = Literal[
    "executed",
    "awaiting_approval",
    "blocked",
    "failed",
]


@dataclass(
    frozen=True,
)
class StructuredExecutorResult:
    message: str

    details: dict[
        str,
        Any,
    ]


class StructuredActionExecutor(
    Protocol
):
    def execute(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
    ) -> StructuredExecutorResult:
        ...


@dataclass(
    frozen=True,
)
class StructuredExecutionOutcome:
    outcome: (
        StructuredExecutionOutcomeType
    )

    response_action: (
        ResponseActionRecord | None
    ) = None

    action_result: (
        ActionExecutionResultRecord
        | None
    ) = None

    incident_case: (
        IncidentCaseRecord | None
    ) = None


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _response_action_id(
    *,
    proposed_action_id: str,
    approval_id: str | None,
) -> str:
    authorization = (
        approval_id
        if approval_id is not None
        else "AUTO_ALLOWED"
    )

    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-response-action:"
            f"{proposed_action_id}:"
            f"{authorization}"
        ),
    )

    return (
        "ACT-"
        f"{str(value).upper()}"
    )


def _action_result_id(
    response_action_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-action-result:"
            f"{response_action_id}"
        ),
    )

    return (
        "ARES-"
        f"{str(value).upper()}"
    )


def _execution_case_id(
    *,
    response_action_id: str,
    reason_code: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-execution-case:"
            f"{response_action_id}:"
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
    proposed_action: (
        ProposedActionRecord
    ),
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    response_action_id: str,
    reason_code: str,
    reason: str,
    now: datetime,
) -> IncidentCaseRecord:
    incident_case = IncidentCaseRecord(
        case_id=(
            _execution_case_id(
                response_action_id=(
                    response_action_id
                ),
                reason_code=reason_code,
            )
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
        incident_case
    )

    return incident_case


def _validate_policy_identity(
    *,
    proposed_action: (
        ProposedActionRecord
    ),
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
) -> None:
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


def _resolve_approval(
    *,
    store: IncidentResponseStore,
    proposed_action: (
        ProposedActionRecord
    ),
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    approval_id: str | None,
    now: datetime,
):
    if (
        policy_decision.outcome
        == "AUTO_ALLOWED"
    ):
        if approval_id is not None:
            raise ValueError(
                "AUTO_ALLOWED actions must "
                "not depend on a human "
                "approval record."
            )

        return (
            "authorized",
            None,
        )

    if (
        policy_decision.outcome
        == "NOT_ALLOWED"
    ):
        return (
            "blocked",
            None,
        )

    if (
        policy_decision.outcome
        != "APPROVAL_REQUIRED"
    ):
        raise ValueError(
            "Unsupported policy outcome."
        )

    if approval_id is None:
        return (
            "awaiting_approval",
            None,
        )

    approval = (
        store.get_approval_request(
            approval_id
        )
    )

    if approval is None:
        raise ValueError(
            "Approval request was not found."
        )

    if (
        approval.policy_decision_id
        != policy_decision.decision_id
        or approval.proposed_action_id
        != proposed_action
        .proposed_action_id
        or approval.incident_id
        != proposed_action.incident_id
    ):
        raise ValueError(
            "Approval request does not "
            "match the proposed action "
            "and policy decision."
        )

    if not approval_matches_action(
        approval,
        proposed_action,
    ):
        raise ValueError(
            "Approval action fingerprint "
            "does not match the proposed "
            "action."
        )

    if (
        approval.expires_at
        is not None
        and now >= approval.expires_at
    ):
        raise ValueError(
            "Approval authorization "
            "has expired."
        )

    if approval.status == "PENDING":
        return (
            "awaiting_approval",
            approval,
        )

    if approval.status == "APPROVED":
        return (
            "authorized",
            approval,
        )

    return (
        "blocked",
        approval,
    )


def execute_structured_action(
    *,
    store: IncidentResponseStore,
    proposed_action: (
        ProposedActionRecord
    ),
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    executor: StructuredActionExecutor,
    autonomous_response_enabled: bool,
    target_protection_registry: (
        TargetProtectionRegistry | None
    ) = None,
    approval_id: str | None = None,
    now: datetime | None = None,
) -> StructuredExecutionOutcome:
    _validate_policy_identity(
        proposed_action=(
            proposed_action
        ),
        policy_decision=(
            policy_decision
        ),
    )

    if now is None:
        now = _utc_now()

    (
        authorization,
        approval,
    ) = _resolve_approval(
        store=store,
        proposed_action=(
            proposed_action
        ),
        policy_decision=(
            policy_decision
        ),
        approval_id=approval_id,
        now=now,
    )

    if authorization == "awaiting_approval":
        return StructuredExecutionOutcome(
            outcome="awaiting_approval",
        )

    if authorization == "blocked":
        return StructuredExecutionOutcome(
            outcome="blocked",
        )

    resolved_approval_id = (
        approval.approval_id
        if approval is not None
        else None
    )

    response_action_id = (
        _response_action_id(
            proposed_action_id=(
                proposed_action
                .proposed_action_id
            ),
            approval_id=(
                resolved_approval_id
            ),
        )
    )

    existing_action = (
        store.get_response_action(
            response_action_id
        )
    )

    if existing_action is not None:
        existing_result = (
            store.get_action_result(
                _action_result_id(
                    response_action_id
                )
            )
        )

        if (
            existing_action.status
            == "completed"
            and existing_result
            is not None
            and existing_result.status
            == "completed"
        ):
            return StructuredExecutionOutcome(
                outcome="executed",
                response_action=(
                    existing_action
                ),
                action_result=(
                    existing_result
                ),
            )

        if existing_action.status == "failed":
            return StructuredExecutionOutcome(
                outcome="failed",
                response_action=(
                    existing_action
                ),
                action_result=(
                    existing_result
                ),
            )

        return StructuredExecutionOutcome(
            outcome="blocked",
            response_action=(
                existing_action
            ),
            action_result=(
                existing_result
            ),
        )

    if (
        target_protection_registry
        is not None
    ):
        try:
            protection = (
                target_protection_registry
                .inspect(
                    target_type=(
                        proposed_action
                        .target_type
                    ),
                    target=(
                        proposed_action
                        .target
                    ),
                )
            )

        except Exception:
            response_action = (
                ResponseActionRecord(
                    response_action_id=(
                        response_action_id
                    ),
                    incident_id=(
                        proposed_action
                        .incident_id
                    ),
                    proposed_action_id=(
                        proposed_action
                        .proposed_action_id
                    ),
                    approval_id=(
                        resolved_approval_id
                    ),
                    executor="cortex",
                    status="blocked",
                    created_at=now,
                )
            )

            store.save_response_action(
                response_action
            )

            incident_case = _create_case(
                store=store,
                proposed_action=(
                    proposed_action
                ),
                policy_decision=(
                    policy_decision
                ),
                response_action_id=(
                    response_action_id
                ),
                reason_code=(
                    "target-protection-check-failed"
                ),
                reason=(
                    "Structured response was "
                    "blocked because target "
                    "protection could not be "
                    "revalidated immediately "
                    "before Cortex execution."
                ),
                now=now,
            )

            return StructuredExecutionOutcome(
                outcome="blocked",
                response_action=(
                    response_action
                ),
                incident_case=(
                    incident_case
                ),
            )

        if (
            protection.protected_target
            or protection
            .allowlisted_target
        ):
            response_action = (
                ResponseActionRecord(
                    response_action_id=(
                        response_action_id
                    ),
                    incident_id=(
                        proposed_action
                        .incident_id
                    ),
                    proposed_action_id=(
                        proposed_action
                        .proposed_action_id
                    ),
                    approval_id=(
                        resolved_approval_id
                    ),
                    executor="cortex",
                    status="blocked",
                    created_at=now,
                )
            )

            store.save_response_action(
                response_action
            )

            if (
                protection
                .protected_target
                and protection
                .allowlisted_target
            ):
                protection_reason = (
                    "protected and allowlisted"
                )

            elif (
                protection
                .protected_target
            ):
                protection_reason = (
                    "protected"
                )

            else:
                protection_reason = (
                    "allowlisted"
                )

            incident_case = _create_case(
                store=store,
                proposed_action=(
                    proposed_action
                ),
                policy_decision=(
                    policy_decision
                ),
                response_action_id=(
                    response_action_id
                ),
                reason_code=(
                    "target-protected"
                ),
                reason=(
                    "Structured response was "
                    "blocked immediately before "
                    "Cortex execution because "
                    f"the target is "
                    f"{protection_reason}."
                ),
                now=now,
            )

            return StructuredExecutionOutcome(
                outcome="blocked",
                response_action=(
                    response_action
                ),
                incident_case=(
                    incident_case
                ),
            )

    if not autonomous_response_enabled:
        response_action = (
            ResponseActionRecord(
                response_action_id=(
                    response_action_id
                ),
                incident_id=(
                    proposed_action
                    .incident_id
                ),
                proposed_action_id=(
                    proposed_action
                    .proposed_action_id
                ),
                approval_id=(
                    resolved_approval_id
                ),
                executor="cortex",
                status="blocked",
                created_at=now,
            )
        )

        store.save_response_action(
            response_action
        )

        incident_case = _create_case(
            store=store,
            proposed_action=(
                proposed_action
            ),
            policy_decision=(
                policy_decision
            ),
            response_action_id=(
                response_action_id
            ),
            reason_code=(
                "kill-switch"
            ),
            reason=(
                "Structured response was "
                "authorized but Cortex "
                "execution was blocked by "
                "AUTONOMOUS_RESPONSE_ENABLED."
            ),
            now=now,
        )

        return StructuredExecutionOutcome(
            outcome="blocked",
            response_action=(
                response_action
            ),
            incident_case=(
                incident_case
            ),
        )

    started_action = (
        ResponseActionRecord(
            response_action_id=(
                response_action_id
            ),
            incident_id=(
                proposed_action.incident_id
            ),
            proposed_action_id=(
                proposed_action
                .proposed_action_id
            ),
            approval_id=(
                resolved_approval_id
            ),
            executor="cortex",
            status="started",
            created_at=now,
        )
    )

    store.save_response_action(
        started_action
    )

    try:
        receipt = executor.execute(
            proposed_action
        )

    except Exception as exc:
        failed_action = (
            started_action.model_copy(
                update={
                    "status": "failed",
                }
            )
        )

        store.save_response_action(
            failed_action
        )

        action_result = (
            ActionExecutionResultRecord(
                action_result_id=(
                    _action_result_id(
                        response_action_id
                    )
                ),
                response_action_id=(
                    response_action_id
                ),
                status="failed",
                message=(
                    "Structured Cortex "
                    "execution failed: "
                    f"{exc}"
                ),
                details={
                    "error": str(exc),
                },
                recorded_at=now,
            )
        )

        store.save_action_result(
            action_result
        )

        incident_case = _create_case(
            store=store,
            proposed_action=(
                proposed_action
            ),
            policy_decision=(
                policy_decision
            ),
            response_action_id=(
                response_action_id
            ),
            reason_code=(
                "execution-failed"
            ),
            reason=(
                "Structured Cortex "
                "execution failed: "
                f"{exc}"
            ),
            now=now,
        )

        return StructuredExecutionOutcome(
            outcome="failed",
            response_action=(
                failed_action
            ),
            action_result=(
                action_result
            ),
            incident_case=(
                incident_case
            ),
        )

    completed_action = (
        started_action.model_copy(
            update={
                "status": "completed",
            }
        )
    )

    store.save_response_action(
        completed_action
    )

    action_result = (
        ActionExecutionResultRecord(
            action_result_id=(
                _action_result_id(
                    response_action_id
                )
            ),
            response_action_id=(
                response_action_id
            ),
            status="completed",
            message=receipt.message,
            details=dict(
                receipt.details
            ),
            recorded_at=now,
        )
    )

    store.save_action_result(
        action_result
    )

    return StructuredExecutionOutcome(
        outcome="executed",
        response_action=(
            completed_action
        ),
        action_result=(
            action_result
        ),
    )