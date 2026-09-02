from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
)
from app.services.case_service import (
    create_case_record,
)


def make_case_investigation() -> InvestigationResponse:
    return InvestigationResponse(
        alert_id="ALT-CASE-001",
        source="wazuh",
        status="complete",
        normalized_event=(
            "Repeated SSH authentication "
            "failures against root."
        ),
        analysis=AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "High-risk SSH brute force detected."
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
            EvidenceRecord(
                evidence_id="E001",
                source="alert",
                content=(
                    "148 failed SSH login attempts "
                    "against root."
                ),
            ),
        ],
        risk_assessment=RiskAssessment(
            score=78,
            band="high",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id="POL-BF-HIGH",
            policy_name=(
                "High-Risk Brute Force"
            ),
            matched=True,
            response_allowed=False,
            actions=[],
            reason=(
                "Automatic containment "
                "is not permitted."
            ),
        ),
        response_plan=ResponsePlan(
            policy_id="POL-BF-HIGH",
            actions=[],
            response_allowed=False,
            status="create_case",
            reason=(
                "Automatic containment "
                "is not permitted."
            ),
        ),
        investigation_iteration=1,
    )


def test_case_record_is_created_from_investigation():
    investigation = make_case_investigation()

    case = create_case_record(
        investigation
    )

    assert case.case_id

    assert (
        case.alert_id
        == "ALT-CASE-001"
    )

    assert (
        case.policy_id
        == "POL-BF-HIGH"
    )

    assert case.risk_score == 78

    assert case.risk_band == "high"

    assert case.status == "open"

    assert (
        case.reason
        == "Automatic containment "
        "is not permitted."
    )


def test_case_id_is_stable_for_same_investigation():
    investigation = make_case_investigation()

    first = create_case_record(
        investigation
    )

    second = create_case_record(
        investigation
    )

    assert (
        first.case_id
        == second.case_id
    )


def test_case_cannot_be_created_for_execution_plan():
    investigation = make_case_investigation()

    execution_plan = (
        investigation.response_plan.model_copy(
            update={
                "response_allowed": True,
                "status": "ready_for_execution",
                "actions": [
                    "block_ip",
                ],
            }
        )
    )

    investigation = investigation.model_copy(
        update={
            "response_plan": execution_plan,
        }
    )

    try:
        create_case_record(
            investigation
        )
    except ValueError as exc:
        assert (
            "does not require case creation"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected ValueError"
        )