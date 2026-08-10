import pytest

from app.schemas import (
    AnalystDecision,
    PolicyDecision,
)
from app.services.approval_service import (
    apply_analyst_decision,
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


def test_analyst_can_approve_pending_plan():
    plan = make_pending_plan()

    decision = AnalystDecision(
        decision="approve",
        analyst_id="analyst-001",
        reason="Evidence supports containment.",
    )

    result = apply_analyst_decision(
        plan,
        decision,
    )

    assert result.status == "approved"

    assert result.actions == [
        "block_ip",
        "notify_administrator",
        "create_case",
    ]


def test_analyst_can_reject_pending_plan():
    plan = make_pending_plan()

    decision = AnalystDecision(
        decision="reject",
        analyst_id="analyst-001",
        reason="Source is an approved testing host.",
    )

    result = apply_analyst_decision(
        plan,
        decision,
    )

    assert result.status == "rejected"


def test_cannot_approve_plan_that_is_not_pending():
    plan = make_pending_plan()

    first_decision = AnalystDecision(
        decision="approve",
        analyst_id="analyst-001",
        reason="Approved.",
    )

    approved_plan = apply_analyst_decision(
        plan,
        first_decision,
    )

    second_decision = AnalystDecision(
        decision="approve",
        analyst_id="analyst-002",
        reason="Approve again.",
    )

    with pytest.raises(
        ValueError,
        match="pending approval",
    ):
        apply_analyst_decision(
            approved_plan,
            second_decision,
        )