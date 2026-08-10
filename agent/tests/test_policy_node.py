from app.graph.nodes.policy import (
    evaluate_investigation_policy,
)
from app.schemas import (
    AlertAnalysis,
    RiskAssessment,
)


def test_policy_node_evaluates_high_brute_force():
    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary="SSH brute force detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    risk = RiskAssessment(
        score=75,
        band="high",
        factors=[],
    )

    result = evaluate_investigation_policy(
        {
            "analysis": analysis,
            "risk_assessment": risk,
            "status": "risk_scored",
        }
    )

    decision = result["policy_decision"]

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-BF-HIGH"
    )

    assert (
        decision.approval_type
        == "analyst"
    )

    assert (
        decision.execution_mode
        == "dry_run"
    )

    assert "block_ip" in decision.actions

    assert (
        result["status"]
        == "policy_evaluated"
    )