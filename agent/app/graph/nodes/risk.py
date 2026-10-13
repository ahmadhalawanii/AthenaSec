from app.graph.state import InvestigationState
from app.schemas import RiskContext
from app.services.risk_engine import calculate_risk


def build_risk_context(
    state: InvestigationState,
) -> RiskContext:
    alert = state["alert"]

    metadata = alert.metadata

    return RiskContext(
        failed_attempts=metadata.get(
            "failed_attempts",
            0,
        ),
        privileged_target=metadata.get(
            "privileged_target",
            False,
        ),
        successful_authentication=metadata.get(
            "successful_authentication"
        ),
        privilege_change_observed=metadata.get(
            "privilege_change_observed",
            False,
        ),
        policy_violation_observed=metadata.get(
            "policy_violation_observed",
            False,
        ),
        asset_criticality=metadata.get(
            "asset_criticality",
            "medium",
        ),
    )


def calculate_investigation_risk(
    state: InvestigationState,
) -> InvestigationState:
    risk_context = build_risk_context(
        state
    )

    risk_assessment = calculate_risk(
        state["analysis"],
        risk_context,
    )

    return {
        "risk_context": risk_context,
        "risk_assessment": risk_assessment,
        "status": "risk_scored",
    }