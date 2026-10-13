from app.graph.state import InvestigationState
from app.services.response_planner import (
    create_response_plan,
)


def create_investigation_response_plan(
    state: InvestigationState,
) -> InvestigationState:
    response_plan = create_response_plan(
        state["policy_decision"]
    )

    return {
        "response_plan": response_plan,
        "status": "response_planned",
    }