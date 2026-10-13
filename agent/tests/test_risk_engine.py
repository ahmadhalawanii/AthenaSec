from app.schemas import (
    AlertAnalysis,
    RiskContext,
)
from app.services.risk_engine import (
    calculate_risk,
)


def make_brute_force_analysis():
    return AlertAnalysis(
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


def test_brute_force_against_privileged_account_is_high():
    analysis = make_brute_force_analysis()

    context = RiskContext(
        failed_attempts=148,
        privileged_target=True,
        successful_authentication=None,
        asset_criticality="medium",
    )

    risk = calculate_risk(
        analysis,
        context,
    )

    assert risk.score == 75
    assert risk.band == "high"


def test_successful_authentication_makes_case_critical():
    analysis = make_brute_force_analysis()

    context = RiskContext(
        failed_attempts=148,
        privileged_target=True,
        successful_authentication=True,
        asset_criticality="medium",
    )

    risk = calculate_risk(
        analysis,
        context,
    )

    assert risk.score == 95
    assert risk.band == "critical"


def test_confirmed_privilege_misuse_can_be_critical():
    analysis = AlertAnalysis(
        classification="privilege_misuse",
        confidence=0.90,
        severity_assessment="high",
        summary="Privilege misuse detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    context = RiskContext(
        privileged_target=True,
        policy_violation_observed=True,
        asset_criticality="critical",
    )

    risk = calculate_risk(
        analysis,
        context,
    )

    assert risk.score == 94
    assert risk.band == "critical"


def test_benign_event_has_zero_risk():
    analysis = AlertAnalysis(
        classification="benign",
        confidence=0.98,
        severity_assessment="low",
        summary="Benign administrative activity.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    context = RiskContext(
        privileged_target=True,
        asset_criticality="critical",
    )

    risk = calculate_risk(
        analysis,
        context,
    )

    assert risk.score == 0
    assert risk.band == "low"


def test_risk_score_never_exceeds_100():
    analysis = AlertAnalysis(
        classification="privilege_escalation",
        confidence=1.0,
        severity_assessment="critical",
        summary="Privilege escalation detected.",
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    context = RiskContext(
        privileged_target=True,
        successful_authentication=True,
        privilege_change_observed=True,
        policy_violation_observed=True,
        asset_criticality="critical",
    )

    risk = calculate_risk(
        analysis,
        context,
    )

    assert risk.score == 100
    assert risk.band == "critical"