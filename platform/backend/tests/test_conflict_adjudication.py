from app.graph.nodes.verify_analysis import verify_investigation_analysis
from app.schemas import (
    AlertAnalysis, EvidenceRecord, EvidenceSufficiencyAssessment, SecurityAlertInput,
)


def make_state(conflicting):
    records = [
        EvidenceRecord(evidence_id="E001", source="alert", evidence_type="alert",
                       content="source_ip=198.51.100.42; repeated SSH failures"),
        EvidenceRecord(evidence_id="E002", source="mock_wazuh",
                       evidence_type="authentication_history",
                       content="source_ip=198.51.100.42; 12 SSH password failures"),
    ]
    if conflicting:
        records.append(EvidenceRecord(
            evidence_id="E003", source="mock_wazuh",
            evidence_type="related_security_events",
            content="source_ip=198.51.100.42; zero SSH failures in same period",
        ))
    return {
        "alert": SecurityAlertInput(
            alert_id="conflict-reconcile", source="wazuh",
            event_text="source_ip=198.51.100.42; repeated SSH failures",
        ),
        "analysis": AlertAnalysis(
            classification="brute_force", confidence=0.9,
            severity_assessment="high", summary="Repeated SSH failures",
            evidence_refs=["E001", "E002"],
            uncertainties=[], recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[], needs_more_evidence=False,
        ),
        "evidence_records": records,
        "evidence_sufficiency": EvidenceSufficiencyAssessment(
            classification="brute_force", sufficient=True,
            required_evidence=["authentication_history"],
            satisfied_evidence=["authentication_history"], missing_evidence=[],
        ),
        "investigation_iteration": 1,
    }


def test_conflicting_records_reconcile_to_unknown_and_fail_closed():
    result = verify_investigation_analysis(make_state(True))
    assert result["analysis"].classification == "unknown"
    assert result["analysis"].confidence == 0.0
    assert "E003" in result["analysis"].evidence_refs
    assert result["analysis"].recommended_response_actions == []
    assert result["analysis_verification"].verified is False
    assert "contradictory_authentication_evidence" in (
        result["analysis_verification"].blocking_issues
    )


def test_uncontradicted_brute_force_stays_brute_force():
    result = verify_investigation_analysis(make_state(False))
    assert result["analysis"].classification == "brute_force"
    assert result["analysis_verification"].verified is True
