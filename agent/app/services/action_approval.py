import hashlib
import json
from datetime import datetime
from typing import Literal
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ApprovalRequestRecord,
    IncidentPolicyDecisionRecord,
    ProposedActionRecord,
)


HumanApprovalDecision = Literal[
    "APPROVED",
    "REJECTED",
]


def _fingerprint_payload(
    proposed_action: ProposedActionRecord,
) -> dict:
    return {
        "proposed_action_id": (
            proposed_action
            .proposed_action_id
        ),
        "incident_id": (
            proposed_action.incident_id
        ),
        "investigation_id": (
            proposed_action
            .investigation_id
        ),
        "action_type": (
            proposed_action.action_type
        ),
        "target_type": (
            proposed_action.target_type
        ),
        "target": (
            proposed_action.target
        ),
        "parameters": (
            proposed_action.parameters
        ),
        "reversible": (
            proposed_action.reversible
        ),
        "rollback_action_type": (
            proposed_action
            .rollback_action_type
        ),
        "rollback_parameters": (
            proposed_action
            .rollback_parameters
        ),
    }


def build_action_fingerprint(
    proposed_action: ProposedActionRecord,
) -> str:
    canonical = json.dumps(
        _fingerprint_payload(
            proposed_action
        ),
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
        ensure_ascii=False,
    )

    digest = hashlib.sha256(
        canonical.encode(
            "utf-8"
        )
    ).hexdigest()

    return (
        f"sha256:{digest}"
    )


def approval_matches_action(
    approval: ApprovalRequestRecord,
    proposed_action: ProposedActionRecord,
) -> bool:
    if (
        approval.proposed_action_id
        != proposed_action
        .proposed_action_id
    ):
        return False

    return (
        approval.action_fingerprint
        == build_action_fingerprint(
            proposed_action
        )
    )


def _approval_id(
    *,
    policy_decision_id: str,
    action_fingerprint: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-approval:"
            f"{policy_decision_id}:"
            f"{action_fingerprint}"
        ),
    )

    return (
        "APR-"
        f"{str(value).upper()}"
    )


def create_approval_request(
    *,
    proposed_action: ProposedActionRecord,
    policy_decision: (
        IncidentPolicyDecisionRecord
    ),
    requested_at: datetime,
    expires_at: datetime | None = None,
) -> ApprovalRequestRecord:
    if (
        policy_decision.outcome
        != "APPROVAL_REQUIRED"
    ):
        raise ValueError(
            "Approval requests may only "
            "be created for "
            "APPROVAL_REQUIRED policy "
            "decisions."
        )

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

    if (
        expires_at is not None
        and expires_at <= requested_at
    ):
        raise ValueError(
            "Approval expiry must be "
            "after the request time."
        )

    fingerprint = (
        build_action_fingerprint(
            proposed_action
        )
    )

    return ApprovalRequestRecord(
        approval_id=(
            _approval_id(
                policy_decision_id=(
                    policy_decision
                    .decision_id
                ),
                action_fingerprint=(
                    fingerprint
                ),
            )
        ),
        incident_id=(
            proposed_action.incident_id
        ),
        proposed_action_id=(
            proposed_action
            .proposed_action_id
        ),
        policy_decision_id=(
            policy_decision.decision_id
        ),
        action_fingerprint=(
            fingerprint
        ),
        status="PENDING",
        requested_by=(
            "athenasec-policy"
        ),
        requested_at=requested_at,
        expires_at=expires_at,
    )


def decide_approval_request(
    *,
    approval: ApprovalRequestRecord,
    proposed_action: ProposedActionRecord,
    decision: HumanApprovalDecision,
    decided_by: str,
    reason: str,
    decided_at: datetime,
) -> ApprovalRequestRecord:
    if approval.status != "PENDING":
        raise ValueError(
            "Only PENDING approval "
            "requests may be decided."
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
        and decided_at
        > approval.expires_at
    ):
        return approval.model_copy(
            update={
                "status": "EXPIRED",
                "decided_at": decided_at,
                "decided_by": decided_by,
                "decision_reason": (
                    "Approval expired before "
                    "the decision could "
                    "authorize execution."
                ),
            }
        )

    if not decided_by.strip():
        raise ValueError(
            "decided_by is required."
        )

    if not reason.strip():
        raise ValueError(
            "Approval decision reason "
            "is required."
        )

    return approval.model_copy(
        update={
            "status": decision,
            "decided_at": decided_at,
            "decided_by": decided_by,
            "decision_reason": reason,
        }
    )
