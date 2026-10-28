import pytest

from app.graph.nodes.policy import evaluate_investigation_policy
from app.graph.nodes.propose_response import make_response_proposal_node
from app.ml.operational_events import operational_event_reason
from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceRecord,
    RiskAssessment,
    SecurityAlertInput,
)
from app.services.analysis_verifier import verify_analysis
from app.services.evidence_sufficiency import evaluate_evidence_sufficiency


def alert_only_evidence():
    return [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            evidence_type="privilege_activity",
            content="Original triggering event only.",
        ),
        EvidenceRecord(
            evidence_id="E002",
            source="alert",
            evidence_type="authentication_history",
            content="Repeated original event metadata.",
        ),
    ]


def test_alert_records_cannot_impersonate_independent_evidence():
    assessment = evaluate_evidence_sufficiency(
        classification="privilege_misuse",
        evidence_records=alert_only_evidence(),
    )

    assert assessment.sufficient is False
    assert assessment.satisfied_evidence == []
    assert set(assessment.missing_evidence) == {
        "privilege_activity",
        "authentication_history",
    }


@pytest.mark.parametrize("rule_id,description,level", [
    ("40704", "Systemd: Service exited due to a failure.", 5),
    ("5502", "PAM: Login session closed.", 3),
    ("5402", "Successful sudo to ROOT executed.", 3),
])
def test_sparse_wazuh_pattern_fails_closed(
    rule_id, description, level
):
    # Synthetic reproduction of observed Wazuh rule signatures.
    # No benign/malicious ground-truth label is assumed.
    alert = SecurityAlertInput(
        alert_id=f"fixture:{rule_id}",
        source="wazuh",
        event_text=description,
        metadata={
            "rule_id": rule_id,
            "rule_level": level,
            "agent_id": "001",
        },
    )

    assert operational_event_reason(alert) is None

    records = alert_only_evidence()
    assessment = evaluate_evidence_sufficiency(
        classification="privilege_misuse",
        evidence_records=records,
    )
    assert assessment.sufficient is False

    analysis = AlertAnalysis(
        classification="privilege_misuse",
        confidence=0.99,
        severity_assessment="critical",
        summary="Uncorroborated privilege-misuse prediction.",
        evidence_refs=["E001"],
        uncertainties=["Independent evidence unavailable."],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    prediction = AttackPrediction(
        classification="privilege_misuse",
        confidence=0.99,
        model_version="synthetic-high-confidence-test",
    )

    verification = verify_analysis(
        alert=alert,
        analysis=analysis,
        evidence_records=records,
        ml_prediction=prediction,
        evidence_sufficiency=assessment,
        investigation_budget_exhausted=True,
    )

    assert verification.verified is False
    assert "evidence_insufficient" in verification.blocking_issues

    risk = RiskAssessment(
        score=95,
        band="critical",
        factors=[],
    )

    decision = evaluate_investigation_policy({
        "analysis": analysis,
        "risk_assessment": risk,
        "analysis_verification": verification,
    })["policy_decision"]

    assert decision.response_allowed is False
    assert decision.actions == []

    def forbidden_proposer(_context):
        raise AssertionError(
            "Unverified analysis must not reach response proposer"
        )

    proposer = make_response_proposal_node(forbidden_proposer)
    proposal_result = proposer({
        "alert": alert,
        "analysis": analysis,
        "risk_assessment": risk,
        "analysis_verification": verification,
        "evidence_records": records,
    })

    assert proposal_result["response_proposal"].actions == []
