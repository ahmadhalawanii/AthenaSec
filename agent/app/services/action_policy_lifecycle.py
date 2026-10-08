from dataclasses import dataclass

from app.schemas import (
    ApprovalRequestRecord,
    IncidentPolicyDecisionRecord,
    InvestigationResponse,
)
from app.services.action_approval import (
    approval_matches_action,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)


@dataclass(
    frozen=True,
)
class PersistedActionPolicyLifecycle:
    policy_decisions: list[
        IncidentPolicyDecisionRecord
    ]

    approval_requests: list[
        ApprovalRequestRecord
    ]


def persist_action_policy_lifecycle(
    *,
    store: IncidentResponseStore,
    investigation: InvestigationResponse,
) -> (
    PersistedActionPolicyLifecycle
    | None
):
    if (
        investigation.incident_id
        is None
        or investigation.investigation_id
        is None
    ):
        return None

    policy_decisions = list(
        investigation
        .action_policy_decisions
    )

    approval_requests = list(
        investigation
        .approval_requests
    )

    if (
        not policy_decisions
        and not approval_requests
    ):
        return None

    actions_by_id = {
        action.proposed_action_id: action
        for action
        in investigation.proposed_actions
    }

    decisions_by_id = {}

    for decision in policy_decisions:
        if (
            decision.incident_id
            != investigation.incident_id
        ):
            raise ValueError(
                "Action policy decision "
                "incident identity does not "
                "match the investigation."
            )

        if (
            decision.proposed_action_id
            not in actions_by_id
        ):
            raise ValueError(
                "Action policy decision "
                "references an unknown "
                "proposed action."
            )

        store.save_policy_decision(
            decision
        )

        decisions_by_id[
            decision.decision_id
        ] = decision

    for approval in (
        approval_requests
    ):
        decision = decisions_by_id.get(
            approval.policy_decision_id
        )

        if decision is None:
            raise ValueError(
                "Approval request references "
                "an unknown policy decision."
            )

        action = actions_by_id.get(
            approval.proposed_action_id
        )

        if action is None:
            raise ValueError(
                "Approval request references "
                "an unknown proposed action."
            )

        if (
            approval.incident_id
            != investigation.incident_id
        ):
            raise ValueError(
                "Approval request incident "
                "identity does not match the "
                "investigation."
            )

        if not approval_matches_action(
            approval,
            action,
        ):
            raise ValueError(
                "Approval request fingerprint "
                "does not match the proposed "
                "action."
            )

        store.save_approval_request(
            approval
        )

    return (
        PersistedActionPolicyLifecycle(
            policy_decisions=(
                policy_decisions
            ),
            approval_requests=(
                approval_requests
            ),
        )
    )
