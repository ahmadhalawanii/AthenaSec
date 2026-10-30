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
    ActionPolicyContent,
    ActionRiskAssessmentRecord,
)
from app.services.approvals.action_approval import (
    create_approval_request,
)
from app.services.policy.action_catalogue import (
    AGENT_ACTION_KEYS,
    whitelist_entry,
)
from app.services.policy.action_policy_engine import (
    evaluate_action_policy,
)


ActionPolicyClock = Callable[
    [],
    datetime,
]

# Returns the administrator's action policy in force (action_policy_store.current_or_default)
ActionPolicyProvider = Callable[
    [],
    ActionPolicyContent,
]


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def make_action_policy_node(
    *,
    clock: ActionPolicyClock = _utc_now,
    approval_ttl_minutes: int = 30,
    policy_provider: ActionPolicyProvider | None = None,
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

        # Read once per investigation, so every action is judged by the same version
        admin_policy = (
            policy_provider()
            if policy_provider is not None
            else None
        )

        risk = state.get("risk_assessment")
        incident_risk = (
            risk.score
            if risk is not None
            else None
        )

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
                    admin_policy=admin_policy,
                    incident_risk=incident_risk,
                )
            )

            policy_decisions.append(
                decision
            )

            if (
                decision.outcome
                == "APPROVAL_REQUIRED"
            ):
                # The administrator's "time to decide" for this action, when set
                entry = (
                    whitelist_entry(
                        admin_policy,
                        AGENT_ACTION_KEYS.get(
                            proposed_action.action_type,
                            proposed_action.action_type,
                        ),
                    )
                    if admin_policy is not None
                    else None
                )
                ttl_minutes = (
                    entry.limits.window_minutes
                    if entry is not None
                    and entry.limits is not None
                    else approval_ttl_minutes
                )

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
                                    ttl_minutes
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
