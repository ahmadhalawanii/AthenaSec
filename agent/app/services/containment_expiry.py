from datetime import timedelta
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionVerificationRecord,
    ContainmentExpiryRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.containment_expiry_store import (
    ContainmentExpiryStore,
)


MAX_DURATION_MINUTES = 1440


def _duration_minutes(
    proposed_action: ProposedActionRecord,
) -> int | None:
    value = (
        proposed_action.parameters.get(
            "duration_minutes"
        )
    )

    if value is None:
        return None

    if (
        type(value) is not int
        or value < 1
        or value > MAX_DURATION_MINUTES
    ):
        raise ValueError(
            "Temporary containment "
            "duration_minutes must be "
            "an integer from 1 to 1440."
        )

    return value


def requires_containment_expiry(
    proposed_action: ProposedActionRecord,
) -> bool:
    duration = _duration_minutes(
        proposed_action
    )

    if duration is None:
        return False

    if (
        not proposed_action.reversible
        or proposed_action
        .rollback_action_type
        is None
    ):
        raise ValueError(
            "Temporary containment must "
            "have an explicit reversible "
            "rollback action."
        )

    return True


def _expiry_id(
    *,
    response_action_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-containment-expiry:"
            f"{response_action_id}"
        ),
    )

    return (
        "EXPIRY-"
        f"{str(value).upper()}"
    )


def _same_identity(
    existing: ContainmentExpiryRecord,
    expected: ContainmentExpiryRecord,
) -> bool:
    return (
        existing.expiry_id
        == expected.expiry_id
        and existing.incident_id
        == expected.incident_id
        and existing.proposed_action_id
        == expected.proposed_action_id
        and existing.response_action_id
        == expected.response_action_id
        and existing.rollback_action_type
        == expected.rollback_action_type
        and existing.target
        == expected.target
        and existing.rollback_parameters
        == expected.rollback_parameters
        and existing.due_at
        == expected.due_at
        and existing.created_at
        == expected.created_at
    )


def ensure_containment_expiry(
    *,
    store: ContainmentExpiryStore,
    proposed_action: ProposedActionRecord,
    response_action: ResponseActionRecord,
    verification: ActionVerificationRecord,
) -> ContainmentExpiryRecord | None:
    if not requires_containment_expiry(
        proposed_action
    ):
        return None

    if (
        response_action
        .proposed_action_id
        != proposed_action
        .proposed_action_id
        or response_action.incident_id
        != proposed_action.incident_id
    ):
        raise ValueError(
            "Response action does not "
            "match temporary containment."
        )

    if (
        response_action.status
        != "completed"
    ):
        raise ValueError(
            "Containment expiry requires "
            "a completed response action."
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
            "Verification does not match "
            "temporary containment."
        )

    if verification.status != "SUCCESS":
        raise ValueError(
            "Containment expiry requires "
            "SUCCESS verification."
        )

    duration = _duration_minutes(
        proposed_action
    )

    if duration is None:
        return None

    rollback_action_type = (
        proposed_action
        .rollback_action_type
    )

    if rollback_action_type is None:
        raise ValueError(
            "Temporary containment has "
            "no rollback action."
        )

    expiry_id = _expiry_id(
        response_action_id=(
            response_action
            .response_action_id
        )
    )

    created_at = (
        verification.verified_at
    )

    expected = (
        ContainmentExpiryRecord(
            expiry_id=expiry_id,
            incident_id=(
                proposed_action.incident_id
            ),
            proposed_action_id=(
                proposed_action
                .proposed_action_id
            ),
            response_action_id=(
                response_action
                .response_action_id
            ),
            rollback_action_type=(
                rollback_action_type
            ),
            target=(
                proposed_action.target
            ),
            rollback_parameters=dict(
                proposed_action
                .rollback_parameters
            ),
            due_at=(
                created_at
                + timedelta(
                    minutes=duration
                )
            ),
            status="PENDING",
            attempt_count=0,
            lease_owner=None,
            lease_expires_at=None,
            last_error=None,
            created_at=created_at,
            updated_at=created_at,
            completed_at=None,
        )
    )

    existing = store.get_expiry(
        expiry_id
    )

    if existing is not None:
        if not _same_identity(
            existing,
            expected,
        ):
            raise ValueError(
                "Existing containment "
                "expiry does not match "
                "the verified action."
            )

        return existing

    persisted = store.create_expiry_if_absent(
        expected
    )

    if not _same_identity(
        persisted,
        expected,
    ):
        raise ValueError(
            "Persisted containment expiry "
            "does not match the verified action."
        )

    return persisted
