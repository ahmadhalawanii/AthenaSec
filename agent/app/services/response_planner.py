from app.schemas import (
    PolicyDecision,
    ResponsePlan,
)


def create_response_plan(
    policy: PolicyDecision,
) -> ResponsePlan:
    if policy.response_allowed:
        return ResponsePlan(
            policy_id=policy.policy_id,
            actions=list(
                policy.actions
            ),
            response_allowed=True,
            status="ready_for_execution",
            reason=policy.reason,
        )

    return ResponsePlan(
        policy_id=policy.policy_id,
        actions=[],
        response_allowed=False,
        status="create_case",
        reason=policy.reason,
    )