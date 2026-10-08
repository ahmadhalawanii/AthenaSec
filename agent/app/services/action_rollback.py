from datetime import (
    datetime,
    timezone,
)
from typing import Protocol
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionRollbackRecord,
    ActionVerificationRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
)


class StructuredRollbackExecutor(
    Protocol
):
    def rollback(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
    ) -> StructuredExecutorResult:
        ...


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _rollback_id(
    *,
    response_action_id: str,
    verification_id: str,
    rollback_action_type: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-action-rollback:"
            f"{response_action_id}:"
            f"{verification_id}:"
            f"{rollback_action_type}"
        ),
    )

    return (
        "ROLLBACK-"
        f"{str(value).upper()}"
    )


def rollback_structured_action(
    *,
    store: IncidentResponseStore,
    proposed_action: (
        ProposedActionRecord
    ),
    response_action: (
        ResponseActionRecord
    ),
    verification: (
        ActionVerificationRecord
    ),
    rollback_executor: (
        StructuredRollbackExecutor
    ),
    now: datetime | None = None,
) -> ActionRollbackRecord:
    if (
        response_action
        .proposed_action_id
        != proposed_action
        .proposed_action_id
    ):
        raise ValueError(
            "Response action does not "
            "match the proposed action."
        )

    if (
        verification
        .proposed_action_id
        != proposed_action
        .proposed_action_id
        or verification
        .response_action_id
        != response_action
        .response_action_id
    ):
        raise ValueError(
            "Verification does not "
            "match the proposed action "
            "and response action."
        )

    if (
        response_action.status
        != "completed"
    ):
        raise ValueError(
            "Rollback requires a "
            "completed response action."
        )

    if verification.status == "SUCCESS":
        raise ValueError(
            "SUCCESS verification must "
            "not trigger rollback."
        )

    if (
        not proposed_action.reversible
        or proposed_action
        .rollback_action_type
        is None
    ):
        raise ValueError(
            "Proposed action is not "
            "reversible."
        )

    if now is None:
        now = _utc_now()

    rollback_id = _rollback_id(
        response_action_id=(
            response_action
            .response_action_id
        ),
        verification_id=(
            verification
            .verification_id
        ),
        rollback_action_type=(
            proposed_action
            .rollback_action_type
        ),
    )

    existing = (
        store.get_action_rollback(
            rollback_id
        )
    )

    if existing is not None:
        return existing

    try:
        result = (
            rollback_executor.rollback(
                proposed_action
            )
        )

        status = "completed"
        message = result.message
        details = dict(
            result.details
        )

    except Exception as exc:
        status = "failed"

        message = (
            "Structured rollback "
            "failed: "
            f"{exc}"
        )

        details = {
            "error": str(exc),
        }

    record = ActionRollbackRecord(
        rollback_id=rollback_id,
        response_action_id=(
            response_action
            .response_action_id
        ),
        proposed_action_id=(
            proposed_action
            .proposed_action_id
        ),
        verification_id=(
            verification
            .verification_id
        ),
        rollback_action_type=(
            proposed_action
            .rollback_action_type
        ),
        target=(
            proposed_action.target
        ),
        status=status,
        message=message,
        details=details,
        recorded_at=now,
    )

    store.save_action_rollback(
        record
    )

    return record