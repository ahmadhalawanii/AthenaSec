from app.graph.state import InvestigationState
from app.schemas import RiskContext
from app.services.risk.risk_engine import calculate_risk


def build_risk_context(
    state: InvestigationState,
) -> RiskContext:
    alert = state["alert"]

    metadata = alert.metadata

    def value(key, default):
        # Wazuh alerts store missing facts as None (a sudo alert has no
        # failure count), so a None value falls back to the default too.
        found = metadata.get(key)
        return default if found is None else found

    return RiskContext(
        failed_attempts=value("failed_attempts", 0),
        privileged_target=value("privileged_target", False),
        successful_authentication=metadata.get("successful_authentication"),
        privilege_change_observed=value("privilege_change_observed", False),
        policy_violation_observed=value("policy_violation_observed", False),
        asset_criticality=value("asset_criticality", "medium"),
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