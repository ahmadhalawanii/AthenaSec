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

    return {
        "policy_decision": policy_decision,
        "status": "policy_evaluated",
    }