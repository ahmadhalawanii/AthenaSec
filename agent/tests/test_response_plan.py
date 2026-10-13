from app.schemas import PolicyDecision
from app.services.response_planner import create_response_plan


def test_allowed_policy_creates_automatic_execution_plan():
    decision = PolicyDecision(
        policy_id="POL-BF-CRITICAL",
        policy_name=(
            "Critical Brute Force Containment"
        ),
        matched=True,
        response_allowed=True,
        actions=[
            "block_ip",
        ],
        reason=(
            "Critical brute-force activity met "
            "the autonomous containment threshold."
        ),
    )

    plan = create_response_plan(
        decision
    )

    assert plan.policy_id == (
        "POL-BF-CRITICAL"
    )

    assert plan.actions == [
        "block_ip",
    ]

    assert plan.response_allowed is True

    assert (
        plan.status
        == "ready_for_execution"
    )


def test_not_allowed_policy_creates_case_plan():
    decision = PolicyDecision(
        policy_id="POL-BF-HIGH",
        policy_name=(
            "High-Risk Brute Force"
        ),
        matched=True,
        response_allowed=False,
        actions=[],
        reason=(
            "Automatic containment "
            "is not permitted."
        ),
    )

    plan = create_response_plan(
        decision
    )

    assert plan.response_allowed is False

    assert (
        plan.status
        == "create_case"
    )

    assert plan.actions == []


def test_unmatched_policy_creates_case_plan():
    policy = PolicyDecision(
        policy_id="NONE",
        policy_name=(
            "No Autonomous Response Policy"
        ),
        matched=False,
        response_allowed=False,
        actions=[],
        reason=(
            "No autonomous response "
            "policy matched."
        ),
    )

    plan = create_response_plan(
        policy
    )

    assert (
        plan.response_allowed
        is False
    )

    assert (
        plan.status
        == "create_case"
    )

    assert plan.actions == []


def test_response_plan_has_no_approval_type():
    decision = PolicyDecision(
        policy_id="POL-BF-CRITICAL",
        policy_name=(
            "Critical Brute Force Containment"
        ),
        matched=True,
        response_allowed=True,
        actions=[
            "block_ip",
        ],
        reason="Allowed.",
    )

    plan = create_response_plan(
        decision
    )

    assert not hasattr(
        plan,
        "approval_type",
    )