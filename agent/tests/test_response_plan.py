from app.schemas import (
    PolicyDecision,
)
from app.services.response_planner import (
    create_response_plan,
)


def test_analyst_policy_creates_pending_plan():
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

    plan = create_response_plan(
        policy
    )

    assert plan.policy_id == "POL-BF-HIGH"

    assert (
        plan.status
        == "pending_approval"
    )

    assert (
        plan.approval_type
        == "analyst"
    )

    assert plan.execution_mode == "dry_run"

    assert plan.actions == [
        "block_ip",
        "notify_administrator",
        "create_case",
    ]


def test_automatic_policy_is_ready_for_dry_run():
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
        reason="Automatic policy threshold reached.",
    )

    plan = create_response_plan(
        policy
    )

    assert (
        plan.status
        == "ready_for_dry_run"
    )


def test_unmatched_policy_creates_no_action_plan():
    policy = PolicyDecision(
        policy_id="NONE",
        policy_name="No Response Policy",
        matched=False,
        approval_type="none",
        execution_mode="dry_run",
        actions=[],
        reason="No policy matched.",
    )

    plan = create_response_plan(
        policy
    )

    assert plan.status == "no_action"

    assert plan.actions == []