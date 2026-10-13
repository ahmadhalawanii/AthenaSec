from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)


def build_benign_investigation(
    *,
    alert: SecurityAlertInput,
    prediction: AttackPrediction,
) -> InvestigationResponse:
    if (
        prediction.classification
        != "benign"
    ):
        raise ValueError(
            "Benign investigation builder "
            "requires a benign prediction."
        )

    normalized_event = " ".join(
        alert.event_text.split()
    )

    evidence = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        content=normalized_event,
    )

    reason = (
        "The ML classifier identified "
        "the alert as benign, so no "
        "automated response is required."
    )

    return InvestigationResponse(
        alert_id=alert.alert_id,
        incident_id=None,
        source=alert.source,
        alert_metadata=dict(
            alert.metadata
        ),
        status="complete",
        normalized_event=(
            normalized_event
        ),
        ml_prediction=prediction,
        ml_error=None,
        misp_enrichment=None,
        misp_error=None,
        analysis=AlertAnalysis(
            classification="benign",
            confidence=(
                prediction.confidence
            ),
            severity_assessment="low",
            summary=(
                "Alert classified as benign."
            ),
            evidence_refs=[
                "E001",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        ),
        evidence_records=[
            evidence,
        ],
        risk_assessment=RiskAssessment(
            score=0,
            band="low",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id=(
                "POL-BENIGN-NO-ACTION"
            ),
            policy_name=(
                "Benign No Action"
            ),
            matched=True,
            response_allowed=False,
            actions=[],
            reason=reason,
        ),
        response_plan=ResponsePlan(
            policy_id=(
                "POL-BENIGN-NO-ACTION"
            ),
            actions=[],
            response_allowed=False,
            status="no_action",
            reason=reason,
        ),
        investigation_iteration=0,
    )