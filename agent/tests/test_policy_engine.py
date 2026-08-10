from app.schemas import (
    AlertAnalysis,
    RiskAssessment,
)
from app.services.policy_engine import (
    evaluate_policy,
)


def make_analysis(
    classification: str,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification=classification,
        confidence=0.95,
        severity_assessment="high",
        summary="Test investigation.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_risk(
    score: int,
    band: str,
) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        band=band,
        factors=[],
    )


def test_high_brute_force_requires_analyst_approval():
    decision = evaluate_policy(
        make_analysis(
            "brute_force"
        ),
        make_risk(
            75,
            "high",
        ),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-BF-HIGH"
    )

    assert (
        decision.approval_type
        == "analyst"
    )

    assert decision.execution_mode == "dry_run"

    assert "block_ip" in decision.actions
    assert "create_case" in decision.actions


def test_critical_brute_force_matches_critical_policy():
    decision = evaluate_policy(
        make_analysis(
            "brute_force"
        ),
        make_risk(
            95,
            "critical",
        ),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-BF-CRITICAL"
    )

    assert (
        decision.approval_type
        == "automatic"
    )

    assert decision.execution_mode == "dry_run"

    assert decision.actions == [
        "block_ip",
        "notify_administrator",
        "create_case",
        "record_response",
    ]


def test_high_privilege_misuse_requires_approval():
    decision = evaluate_policy(
        make_analysis(
            "privilege_misuse"
        ),
        make_risk(
            85,
            "high",
        ),
    )

    assert decision.matched is True

    assert (
        decision.policy_id
        == "POL-PM-HIGH"
    )

    assert (
        decision.approval_type
        == "analyst"
    )

    assert "lock_account" in decision.actions

    assert (
        "capture_telemetry"
        in decision.actions
    )


def test_low_risk_does_not_match_response_policy():
    decision = evaluate_policy(
        make_analysis(
            "brute_force"
        ),
        make_risk(
            35,
            "low",
        ),
    )

    assert decision.matched is False

    assert decision.policy_id == "NONE"

    assert decision.approval_type == "none"

    assert decision.actions == []


def test_benign_event_never_matches_response_policy():
    decision = evaluate_policy(
        make_analysis(
            "benign"
        ),
        make_risk(
            0,
            "low",
        ),
    )

    assert decision.matched is False

    assert decision.actions == []