from app.schemas import (
    PolicyDecision,
    ResponsePlan,
)


def create_response_plan(
    policy: PolicyDecision,
) -> ResponsePlan:
    if not policy.matched:
        return ResponsePlan(
            policy_id=policy.policy_id,
            actions=[],
            approval_type="none",
            execution_mode=policy.execution_mode,
            status="no_action",
            reason=policy.reason,
        )

    if policy.approval_type == "analyst":
        status = "pending_approval"

    else:
        status = "ready_for_dry_run"

    return ResponsePlan(
        policy_id=policy.policy_id,
        actions=policy.actions,
        approval_type=policy.approval_type,
        execution_mode=policy.execution_mode,
        status=status,
        reason=policy.reason,
    )