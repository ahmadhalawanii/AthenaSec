from app.graph.nodes.response_plan import (
    create_investigation_response_plan,
)
from app.schemas import PolicyDecision


def test_response_plan_node_creates_pending_approval():
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

    result = create_investigation_response_plan(
        {
            "policy_decision": policy,
            "status": "policy_evaluated",
        }
    )

    plan = result["response_plan"]

    assert (
        plan.status
        == "pending_approval"
    )

    assert plan.actions == [
        "block_ip",
        "notify_administrator",
        "create_case",
    ]

    assert (
        result["status"]
        == "response_planned"
    )