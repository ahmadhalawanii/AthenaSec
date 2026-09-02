from typing import Literal

from app.graph.state import InvestigationState


MAX_INVESTIGATION_ITERATIONS = 1


def _requires_deterministic_wazuh_evidence(
    state: InvestigationState,
) -> bool:
    alert = state.get("alert")
    analysis = state.get("analysis")

    if alert is None or analysis is None:
        return False

    if alert.source != "wazuh":
        return False

    return analysis.classification in {
        "brute_force",
        "privilege_misuse",
        "privilege_escalation",
    }


def route_after_analysis(
    state: InvestigationState,
) -> Literal[
    "gather_evidence",
    "calculate_risk",
]:
    analysis = state.get("analysis")

    if analysis is None:
        return "calculate_risk"

    iteration = state.get(
        "investigation_iteration",
        0,
    )

    if iteration >= MAX_INVESTIGATION_ITERATIONS:
        return "calculate_risk"

    if _requires_deterministic_wazuh_evidence(
        state
    ):
        return "gather_evidence"

    if (
        analysis.needs_more_evidence
        and analysis.requested_evidence
    ):
        return "gather_evidence"

    return "calculate_risk"