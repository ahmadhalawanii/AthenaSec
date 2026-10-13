from app.graph.state import (
    InvestigationState,
)
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

    denial_reasons: list[str] = []

    ml_error = state.get(
        "ml_error"
    )

    if ml_error is not None:
        denial_reasons.append(
            (
                "ML classification failed: "
                f"{ml_error}"
            )
        )

    verification = state.get(
        "analysis_verification"
    )

    if (
        verification is not None
        and not verification.verified
    ):
        issues = ", ".join(
            verification.blocking_issues
        )

        if not issues:
            issues = (
                "verification_failed"
            )

        denial_reasons.append(
            (
                "Analysis verification failed: "
                f"{issues}"
            )
        )

    if denial_reasons:
        policy_decision = (
            policy_decision.model_copy(
                update={
                    "response_allowed": False,
                    "actions": [],
                    "reason": (
                        "Autonomous response denied. "
                        + " | ".join(
                            denial_reasons
                        )
                    ),
                }
            )
        )

    return {
        "policy_decision": (
            policy_decision
        ),
        "status": "policy_evaluated",
    }