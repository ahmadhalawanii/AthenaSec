from app.schemas import (
    InvestigationResponse,
)


M4_HOLD_REASON = (
    "Structured response actions require "
    "deterministic action policy evaluation "
    "before execution."
)


def hold_legacy_execution_for_structured_response(
    investigation: InvestigationResponse,
) -> InvestigationResponse:
    if (
        investigation.response_proposal
        is None
    ):
        return investigation

    if (
        investigation.response_plan.status
        != "ready_for_execution"
    ):
        return investigation

    policy_decision = (
        investigation
        .policy_decision
        .model_copy(
            update={
                "response_allowed": False,
                "actions": [],
                "reason": M4_HOLD_REASON,
            }
        )
    )

    response_plan = (
        investigation
        .response_plan
        .model_copy(
            update={
                "response_allowed": False,
                "actions": [],
                "status": "create_case",
                "reason": M4_HOLD_REASON,
            }
        )
    )

    return investigation.model_copy(
        update={
            "policy_decision": (
                policy_decision
            ),
            "response_plan": (
                response_plan
            ),
        }
    )