
from app.schemas import (
    SecurityAlertInput,
    AlertAnalysis,
    EvidenceRecord,
    EvidenceSufficiencyAssessment,
)
from app.services.investigations.analysis_verifier import verify_analysis


def test_conflicting_ssh_counts_fail_verification():
    alert = SecurityAlertInput(
        alert_id="conflict-test",
        source="wazuh",
        event_text="Repeated SSH failures",
    )

    analysis = AlertAnalysis(
        classification="brute_force",
        confidence=0.9,
        severity_assessment="high",
        summary="Repeated SSH failures",
        evidence_refs=["E001", "E002", "E003"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )

    records = [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            evidence_type="alert",
            content="Repeated SSH failures",
        ),
        EvidenceRecord(
            evidence_id="E002",
            source="mock_wazuh",
            evidence_type="authentication_history",
            content="source_ip=198.51.100.42; 12 SSH password failures",
        ),
        EvidenceRecord(
            evidence_id="E003",
            source="mock_wazuh",
            evidence_type="related_security_events",
            content="source_ip=198.51.100.42; zero SSH failures in same period",
        ),
    ]

    sufficiency = EvidenceSufficiencyAssessment(
        classification="brute_force",
        sufficient=True,
        required_evidence=["authentication_history"],
        satisfied_evidence=["authentication_history"],
        missing_evidence=[],
    )

    result = verify_analysis(
        alert=alert,
        analysis=analysis,
        evidence_records=records,
        ml_prediction=None,
        evidence_sufficiency=sufficiency,
        investigation_budget_exhausted=False,
    )

    assert result.verified is False
    assert "contradictory_authentication_evidence" in result.blocking_issues


def test_uncontradicted_ssh_counts_do_not_trigger_conflict():
    from app.services.investigations.analysis_verifier import (
        _conflicting_authentication_counts,
    )

    records = [
        EvidenceRecord(
            evidence_id="E001",
            source="mock_wazuh",
            evidence_type="authentication_history",
            content="source_ip=198.51.100.23; 17 failed SSH attempts",
        ),
    ]
    assert _conflicting_authentication_counts(records) is False
