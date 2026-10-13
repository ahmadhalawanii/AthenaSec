from collections.abc import Callable
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    ActionRiskAssessmentRecord,
)
from app.services.action_approval import (
    create_approval_request,
)
from app.services.action_policy_engine import (
    evaluate_action_policy,
)


ActionPolicyClock = Callable[
    [],
    datetime,
]


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def make_action_policy_node(
    *,
    clock: ActionPolicyClock = _utc_now,
    approval_ttl_minutes: int = 30,
):
    def evaluate_response_action_policy(
        state: InvestigationState,
    ) -> InvestigationState:
        proposed_actions = list(
            state.get(
                "proposed_actions",
                [],
            )
        )

        action_risks = list(
            state.get(
                "action_risk_assessments",
                [],
            )
        )

        if not proposed_actions:
            if action_risks:
                raise ValueError(
                    "Action-risk assessments "
                    "exist without proposed "
                    "actions."
                )

            return {
                "action_policy_decisions": [],
                "approval_requests": [],
                "status": (
                    "action_policy_evaluated"
                ),
            }

        risks_by_action_id: dict[
            str,
            ActionRiskAssessmentRecord,
        ] = {}

        for action_risk in action_risks:
            proposed_action_id = (
                action_risk
                .proposed_action_id
            )

            if (
                proposed_action_id
                in risks_by_action_id
            ):
                raise ValueError(
                    "Duplicate action-risk "
                    "assessment for proposed "
                    "action."
                )

            risks_by_action_id[
                proposed_action_id
            ] = action_risk

        action_ids = {
            action.proposed_action_id
            for action in proposed_actions
        }

        if (
            set(
                risks_by_action_id
            )
            != action_ids
        ):
            raise ValueError(
                "Proposed actions and "
                "action-risk assessments "
                "must have a one-to-one "
                "identity match."
            )

        decided_at = clock()

        policy_decisions = []
        approval_requests = []

        for proposed_action in (
            proposed_actions
        ):
            action_risk = (
                risks_by_action_id[
                    proposed_action
                    .proposed_action_id
                ]
            )

            decision = (
                evaluate_action_policy(
                    proposed_action=(
                        proposed_action
                    ),
                    action_risk=(
                        action_risk
                    ),
                    decided_at=(
                        decided_at
                    ),
                )
            )

            policy_decisions.append(
                decision
            )

            if (
                decision.outcome
                == "APPROVAL_REQUIRED"
            ):
                approval_requests.append(
                    create_approval_request(
                        proposed_action=(
                            proposed_action
                        ),
                        policy_decision=(
                            decision
                        ),
                        requested_at=(
                            decided_at
                        ),
                        expires_at=(
                            decided_at
                            + timedelta(
                                minutes=(
                                    approval_ttl_minutes
                                )
                            )
                        ),
                    )
                )

        return {
            "action_policy_decisions": (
                policy_decisions
            ),
            "approval_requests": (
                approval_requests
            ),
            "status": (
                "action_policy_evaluated"
            ),
        }

    return evaluate_response_action_policy
