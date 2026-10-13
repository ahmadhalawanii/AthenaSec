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
    ActionVerificationRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)


VerificationStatus = Literal[
    "SUCCESS",
    "PARTIAL",
    "FAILED",
    "UNVERIFIED",
]


@dataclass(
    frozen=True,
)
class StructuredVerificationObservation:
    status: VerificationStatus

    message: str

    details: dict[
        str,
        Any,
    ]


class StructuredActionVerifier(
    Protocol
):
    def verify(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
        action_result: (
            ActionExecutionResultRecord
        ),
    ) -> (
        StructuredVerificationObservation
    ):
        ...


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def _verification_id(
    *,
    response_action_id: str,
    action_result_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-action-verification:"
            f"{response_action_id}:"
            f"{action_result_id}"
        ),
    )

    return (
        "VERIFY-"
        f"{str(value).upper()}"
    )


def verify_structured_action(
    *,
    store: IncidentResponseStore,
    proposed_action: (
        ProposedActionRecord
    ),
    response_action: (
        ResponseActionRecord
    ),
    action_result: (
        ActionExecutionResultRecord
    ),
    verifier: StructuredActionVerifier,
    now: datetime | None = None,
) -> ActionVerificationRecord:
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
        action_result
        .response_action_id
        != response_action
        .response_action_id
    ):
        raise ValueError(
            "Execution action result "
            "does not match the "
            "response action."
        )

    if (
        response_action.status
        != "completed"
        or action_result.status
        != "completed"
    ):
        raise ValueError(
            "Only completed structured "
            "execution can be verified."
        )

    verification_id = _verification_id(
        response_action_id=(
            response_action.response_action_id
        ),
        action_result_id=(
            action_result.action_result_id
        ),
    )

    existing = store.get_action_verification(
        verification_id
    )

    if existing is not None:
        if (
            existing.response_action_id
            != response_action.response_action_id
            or existing.proposed_action_id
            != proposed_action.proposed_action_id
        ):
            raise ValueError(
                "Existing verification identity "
                "does not match the completed action."
            )

        return existing

    if now is None:
        now = _utc_now()

    try:
        observation = verifier.verify(
            proposed_action,
            action_result,
        )

        if (
            observation.status
            not in {
                "SUCCESS",
                "PARTIAL",
                "FAILED",
                "UNVERIFIED",
            }
        ):
            raise ValueError(
                "Verifier returned an "
                "unsupported verification "
                "status."
            )

        if not observation.message.strip():
            raise ValueError(
                "Verifier returned an empty "
                "verification message."
            )

        status = observation.status
        message = observation.message
        details = dict(
            observation.details
        )

    except Exception as exc:
        status = "UNVERIFIED"

        message = (
            "Post-action verification "
            "could not be completed: "
            f"{exc}"
        )

        details = {
            "error": str(exc),
        }

    record = (
        ActionVerificationRecord(
            verification_id=verification_id,
            response_action_id=(
                response_action
                .response_action_id
            ),
            proposed_action_id=(
                proposed_action
                .proposed_action_id
            ),
            status=status,
            message=message,
            details=details,
            verified_at=now,
        )
    )

    store.save_action_verification(
        record
    )

    return record
