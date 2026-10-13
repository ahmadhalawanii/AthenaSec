from typing import Literal

from app.graph.state import (
    InvestigationState,
)
from app.services.investigation_budget import (
    max_investigation_iterations,
)


def _legacy_requires_wazuh_evidence(
    state: InvestigationState,
) -> bool:
    alert = state.get(
        "alert"
    )

    analysis = state.get(
        "analysis"
    )

    if (
        alert is None
        or analysis is None
    ):
        return False

    if alert.source != "wazuh":
        return False

    return analysis.classification in {
        "brute_force",
        "privilege_misuse",
        "privilege_escalation",
        "unknown",
    }


def route_after_analysis(
    state: InvestigationState,
) -> Literal[
    "gather_evidence",
    "calculate_risk",
]:
    analysis = state.get(
        "analysis"
    )

    if analysis is None:
        return "calculate_risk"

    alert = state.get(
        "alert"
    )

    source = (
        alert.source
        if alert is not None
        else "manual"
    )

    iteration = state.get(
        "investigation_iteration",
        0,
    )

    max_iterations = (
        max_investigation_iterations(
            source
        )
    )

    if iteration >= max_iterations:
        return "calculate_risk"

    assessment = state.get(
        "evidence_sufficiency"
    )

    if (
        source == "wazuh"
        and assessment is not None
    ):
        if assessment.sufficient:
            return "calculate_risk"

        if state.get(
            "investigation_budget_exhausted",
            False,
        ):
            return "calculate_risk"

        if assessment.missing_evidence:
            return "gather_evidence"

        return "calculate_risk"

    if _legacy_requires_wazuh_evidence(
        state
    ):
        return "gather_evidence"

    if (
        analysis.needs_more_evidence
        and analysis.requested_evidence
    ):
        return "gather_evidence"

    return "calculate_risk"