from app.schemas import (
    AnalystDecision,
    ResponsePlan,
)


def apply_analyst_decision(
    plan: ResponsePlan,
    decision: AnalystDecision,
) -> ResponsePlan:
    if plan.status != "pending_approval":
        raise ValueError(
            "Only a response plan pending approval "
            "can receive an analyst decision."
        )

    if plan.approval_type != "analyst":
        raise ValueError(
            "This response plan does not require "
            "analyst approval."
        )

    if decision.decision == "approve":
        new_status = "approved"

    else:
        new_status = "rejected"

    decision_reason = (
        f"{plan.reason} "
        f"Analyst {decision.analyst_id} "
        f"{decision.decision}d the plan: "
        f"{decision.reason}"
    )

    return plan.model_copy(
        update={
            "status": new_status,
            "reason": decision_reason,
        }
    )