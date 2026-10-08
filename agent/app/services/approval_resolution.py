from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ApprovalRequestRecord,
    IncidentCaseRecord,
)
from app.services.action_approval import (
    HumanApprovalDecision,
    decide_approval_request,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)


@dataclass(
    frozen=True,
)
class ApprovalResolution:
    approval: ApprovalRequestRecord

    incident_case: (
        IncidentCaseRecord | None
    )


def _case_id(
    *,
    approval_id: str,
    status: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-approval-case:"
            f"{approval_id}:"
            f"{status}"
        ),
    )

    return (
        "CASE-"
        f"{str(value).upper()}"
    )


def resolve_approval_request(
    *,
    store: IncidentResponseStore,
    approval_id: str,
    decision: HumanApprovalDecision,
    decided_by: str,
    reason: str,
    decided_at: datetime | None = None,
) -> ApprovalResolution:
    approval = (
        store.get_approval_request(
            approval_id
        )
    )

    if approval is None:
        raise LookupError(
            "Approval request was not found."
        )

    proposed_action = (
        store.get_proposed_action(
            approval.proposed_action_id
        )
    )

    if proposed_action is None:
        raise ValueError(
            "Approval request references "
            "a missing proposed action."
        )

    if decided_at is None:
        decided_at = datetime.now(
            timezone.utc
        )

    resolved = (
        decide_approval_request(
            approval=approval,
            proposed_action=(
                proposed_action
            ),
            decision=decision,
            decided_by=decided_by,
            reason=reason,
            decided_at=decided_at,
        )
    )

    store.save_approval_request(
        resolved
    )

    incident_case = None

    if (
        resolved.status
        in {
            "REJECTED",
            "EXPIRED",
        }
    ):
        case_reason = (
            "Human approval was rejected."
            if (
                resolved.status
                == "REJECTED"
            )
            else (
                "Human approval expired "
                "before authorization."
            )
        )

        if (
            resolved.decision_reason
        ):
            case_reason = (
                f"{case_reason} "
                f"{resolved.decision_reason}"
            )

        incident_case = (
            IncidentCaseRecord(
                case_id=(
                    _case_id(
                        approval_id=(
                            resolved.approval_id
                        ),
                        status=(
                            resolved.status
                        ),
                    )
                ),
                incident_id=(
                    resolved.incident_id
                ),
                investigation_id=(
                    proposed_action
                    .investigation_id
                ),
                policy_decision_id=(
                    resolved
                    .policy_decision_id
                ),
                status="open",
                reason=case_reason,
                created_at=decided_at,
                updated_at=decided_at,
            )
        )

        store.save_incident_case(
            incident_case
        )

    return ApprovalResolution(
        approval=resolved,
        incident_case=incident_case,
    )
