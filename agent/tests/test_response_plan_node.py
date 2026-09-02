from app.graph.nodes.response_plan import (
    create_investigation_response_plan,
)
from app.schemas import PolicyDecision


def test_response_plan_node_creates_ready_for_execution_plan():
    policy = PolicyDecision(
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

    result = create_investigation_response_plan(
        {
            "policy_decision": policy,
        }
    )

    plan = result["response_plan"]

    assert plan.policy_id == (
        "POL-BF-CRITICAL"
    )

    assert plan.response_allowed is True

    assert plan.actions == [
        "block_ip",
    ]

    assert (
        plan.status
        == "ready_for_execution"
    )


def test_response_plan_node_creates_case_plan():
    policy = PolicyDecision(
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

    result = create_investigation_response_plan(
        {
            "policy_decision": policy,
        }
    )

    plan = result["response_plan"]

    assert plan.response_allowed is False

    assert plan.actions == []

    assert (
        plan.status
        == "create_case"
    )


def test_response_plan_node_creates_case_for_unmatched_policy():
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

    result = create_investigation_response_plan(
        {
            "policy_decision": policy,
        }
    )

    plan = result[
        "response_plan"
    ]

    assert (
        plan.response_allowed
        is False
    )

    assert (
        plan.status
        == "create_case"
    )

    assert plan.actions == []