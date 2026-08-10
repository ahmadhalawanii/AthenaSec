import pytest

from app.schemas import (
    AnalystDecision,
    PolicyDecision,
)
from app.services.approval_service import (
    apply_analyst_decision,
)
from app.services.dry_run_executor import (
    execute_dry_run,
)
from app.services.response_planner import (
    create_response_plan,
)


def make_pending_plan():
    policy = PolicyDecision(
        policy_id="POL-BF-HIGH",
        policy_name="High-Risk Brute Force Review",
        matched=True,
        approval_type="analyst",
        execution_mode="dry_run",
        actions=[
            "block_ip",
            "notify_administrator",
            "create_case",
        ],
        reason="Analyst approval required.",
    )

    return create_response_plan(
        policy
    )


def test_pending_plan_cannot_execute():
    plan = make_pending_plan()

    with pytest.raises(
        ValueError,
        match="approved",
    ):
        execute_dry_run(
            plan
        )


def test_approved_plan_executes_as_simulation():
    plan = make_pending_plan()

    approved_plan = apply_analyst_decision(
        plan,
        AnalystDecision(
            decision="approve",
            analyst_id="analyst-001",
            reason="Containment approved.",
        ),
    )

    execution = execute_dry_run(
        approved_plan
    )

    assert execution.status == "completed"

    assert execution.execution_mode == "dry_run"

    assert len(
        execution.action_results
    ) == 3

    assert all(
        result.status == "simulated"
        for result in execution.action_results
    )


def test_automatic_policy_can_execute_dry_run():
    policy = PolicyDecision(
        policy_id="POL-BF-CRITICAL",
        policy_name="Critical Brute Force Containment",
        matched=True,
        approval_type="automatic",
        execution_mode="dry_run",
        actions=[
            "block_ip",
            "notify_administrator",
            "create_case",
            "record_response",
        ],
        reason="Automatic threshold reached.",
    )

    plan = create_response_plan(
        policy
    )

    execution = execute_dry_run(
        plan
    )

    assert plan.status == "ready_for_dry_run"

    assert execution.status == "completed"

    assert len(
        execution.action_results
    ) == 4