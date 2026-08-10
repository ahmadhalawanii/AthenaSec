from app.schemas import (
    ActionExecutionResult,
    DryRunExecutionResult,
    ResponsePlan,
)


def execute_dry_run(
    plan: ResponsePlan,
) -> DryRunExecutionResult:
    allowed_statuses = {
        "approved",
        "ready_for_dry_run",
    }

    if plan.status not in allowed_statuses:
        raise ValueError(
            "Response plan must be approved or "
            "ready for dry run before execution."
        )

    if plan.execution_mode != "dry_run":
        raise ValueError(
            "Only dry-run execution is currently supported."
        )

    results: list[ActionExecutionResult] = []

    for action in plan.actions:
        results.append(
            ActionExecutionResult(
                action=action,
                status="simulated",
                message=(
                    f"SIMULATION ONLY: {action} "
                    f"would be executed."
                ),
            )
        )

    return DryRunExecutionResult(
        policy_id=plan.policy_id,
        execution_mode="dry_run",
        status="completed",
        action_results=results,
    )