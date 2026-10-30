from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)


def build_operational_event_investigation(
    *,
    alert: SecurityAlertInput,
    reason: str,
) -> InvestigationResponse:
    if reason != "wazuh_manager_startup":
        raise ValueError("Unsupported operational event reason.")

    policy_id = "POL-OPERATIONAL-NO-ACTION"
    explanation = (
        "A deterministic Wazuh operational-event rule "
        "identified a known manager startup. "
        "ML inference and automated response were skipped."
    )

    return InvestigationResponse(
        alert_id=alert.alert_id,
        incident_id=None,
        source=alert.source,
        alert_metadata=dict(alert.metadata),
        status="complete",
        normalized_event=alert.event_text,
        ml_prediction=None,
        ml_error=None,
        analysis=AlertAnalysis(
            classification="benign",
            confidence=0.0,
            severity_assessment="low",
            summary=explanation,
            evidence_refs=["E001"],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        ),
        evidence_records=[
            EvidenceRecord(
                evidence_id="E001",
                source="alert",
                evidence_type="alert",
                content=alert.event_text,
            )
        ],
        risk_assessment=RiskAssessment(
            score=0,
            band="low",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id=policy_id,
            policy_name="Operational Event No Action",
            matched=True,
            response_allowed=False,
            actions=[],
            reason=explanation,
        ),
        response_plan=ResponsePlan(
            policy_id=policy_id,
            actions=[],
            response_allowed=False,
            status="no_action",
            reason=explanation,
        ),
        investigation_iteration=0,
    )
