from app.schemas import (
    AlertAnalysis,
    RiskAssessment,
)
from app.services.policy_engine import evaluate_policy


def make_analysis(
    classification: str,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification=classification,
        confidence=0.95,
        severity_assessment="high",
        summary="Test analysis",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_risk(
    score: int,
) -> RiskAssessment:
    if score >= 90:
        band = "critical"
    elif score >= 70:
        band = "high"
    elif score >= 40:
        band = "medium"
    else:
        band = "low"

    return RiskAssessment(
        score=score,
        band=band,
        factors=[],
    )


def test_critical_brute_force_allows_autonomous_response():
    decision = evaluate_policy(
        make_analysis("brute_force"),
        make_risk(92),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-BF-CRITICAL"
    )

    assert (
        decision.response_allowed
        is True
    )

    assert decision.actions == [
        "block_ip",
    ]


def test_high_brute_force_does_not_allow_autonomous_response():
    decision = evaluate_policy(
        make_analysis("brute_force"),
        make_risk(78),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-BF-HIGH"
    )

    assert (
        decision.response_allowed
        is False
    )

    assert decision.actions == []


def test_privilege_misuse_does_not_automatically_lock_account():
    decision = evaluate_policy(
        make_analysis(
            "privilege_misuse"
        ),
        make_risk(85),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-PM-HIGH"
    )

    assert (
        decision.response_allowed
        is False
    )

    assert decision.actions == []


def test_low_risk_has_no_authorized_response():
    decision = evaluate_policy(
        make_analysis("brute_force"),
        make_risk(45),
    )

    assert decision.matched is False
    assert decision.policy_id == "NONE"

    assert (
        decision.response_allowed
        is False
    )

    assert decision.actions == []


def test_benign_event_has_no_authorized_response():
    decision = evaluate_policy(
        make_analysis("benign"),
        make_risk(0),
    )

    assert decision.matched is False
    assert decision.policy_id == "NONE"

    assert (
        decision.response_allowed
        is False
    )

    assert decision.actions == []


def test_policy_decision_has_no_human_approval_field():
    decision = evaluate_policy(
        make_analysis("brute_force"),
        make_risk(92),
    )

    assert not hasattr(
        decision,
        "approval_type",
    )