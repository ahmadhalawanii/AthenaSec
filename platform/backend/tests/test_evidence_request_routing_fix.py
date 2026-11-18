from app.graph.nodes.gather_evidence import _resolve_evidence_requests
from app.graph.routing import route_after_analysis
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    EvidenceSufficiencyAssessment,
    SecurityAlertInput,
)


def state():
    return {
        "alert": SecurityAlertInput(
            alert_id="routing-test",
            source="wazuh",
            event_text="Multiple SSH failures",
        ),
        "analysis": AlertAnalysis(
            classification="unknown",
            confidence=0.3,
            severity_assessment="medium",
            summary="Multiple SSH failures require investigation",
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[
                "authentication_history",
                "source_endpoint_context",
            ],
            needs_more_evidence=True,
        ),
        "evidence_records": [
            EvidenceRecord(
                evidence_id="E001",
                source="alert",
                evidence_type="alert",
                content="Multiple SSH failures",
            ),
        ],
        "evidence_sufficiency": EvidenceSufficiencyAssessment(
            classification="unknown",
            sufficient=False,
            required_evidence=["related_security_events"],
            satisfied_evidence=[],
            missing_evidence=["related_security_events"],
        ),
        "investigation_iteration": 0,
    }


def test_requests_include_qwen_requested_evidence():
    requests = _resolve_evidence_requests(state())
    assert "authentication_history" in requests
    assert "source_endpoint_context" in requests


def test_retrieved_evidence_not_requested_again():
    s = state()
    s["evidence_records"].append(
        EvidenceRecord(
            evidence_id="E002",
            source="mock_wazuh",
            evidence_type="authentication_history",
            content="17 failed SSH login attempts",
        )
    )
    assert "authentication_history" not in _resolve_evidence_requests(s)


def test_sufficient_unknown_does_not_hide_outstanding_request():
    s = state()
    s["evidence_sufficiency"] = (
        s["evidence_sufficiency"].model_copy(
            update={
                "sufficient": True,
                "missing_evidence": [],
                "satisfied_evidence": ["related_security_events"],
            }
        )
    )
    assert route_after_analysis(s) == "gather_evidence"


def test_iteration_limit_is_preserved():
    s = state()
    s["investigation_iteration"] = 100
    assert route_after_analysis(s) == "calculate_risk"
