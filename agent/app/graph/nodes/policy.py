from app.graph.state import InvestigationState
from app.services.policy_engine import (
    evaluate_policy,
)


def evaluate_investigation_policy(
    state: InvestigationState,
) -> InvestigationState:
    policy_decision = evaluate_policy(
        state["analysis"],
        state["risk_assessment"],
    )

    ml_error = state.get(
        "ml_error"
    )

    if ml_error is not None:
        policy_decision = (
            policy_decision.model_copy(
                update={
                    "response_allowed": False,
                    "actions": [],
                    "reason": (
                        "Autonomous response denied "
                        "because ML classification "
                        "failed: "
                        f"{ml_error}"
                    ),
                }
            )
        )

    return {
        "policy_decision": policy_decision,
        "status": "policy_evaluated",
    }
