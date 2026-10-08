from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    AttackClassification,
)
from app.services.evidence_sufficiency import (
    evaluate_evidence_sufficiency,
)
from app.services.investigation_budget import (
    max_investigation_iterations,
)
from app.services.investigation_trace import (
    append_investigation_trace,
)


def _resolve_classification(
    state: InvestigationState,
) -> AttackClassification:
    prediction = state.get(
        "ml_prediction"
    )

    if prediction is not None:
        return (
            prediction.classification
        )

    analysis = state.get(
        "analysis"
    )

    if analysis is not None:
        return (
            analysis.classification
        )

    return "unknown"


def assess_evidence_sufficiency(
    state: InvestigationState,
) -> InvestigationState:
    classification = (
        _resolve_classification(
            state
        )
    )

    assessment = (
        evaluate_evidence_sufficiency(
            classification=classification,
            evidence_records=state.get(
                "evidence_records",
                [],
            ),
        )
    )

    alert = state.get(
        "alert"
    )

    alert_source = (
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
            alert_source
        )
    )

    budget_exhausted = (
        not assessment.sufficient
        and iteration >= max_iterations
    )

    if assessment.sufficient:
        status = (
            "evidence_sufficient"
        )

    elif budget_exhausted:
        status = (
            "investigation_budget_exhausted"
        )

    else:
        status = "needs_evidence"

    trace = (
        append_investigation_trace(
            state,
            step_type=(
                "evidence_sufficiency"
            ),
            status=status,
            details={
                "classification": (
                    assessment.classification
                ),
                "sufficient": (
                    assessment.sufficient
                ),
                "required_evidence": list(
                    assessment.required_evidence
                ),
                "satisfied_evidence": list(
                    assessment.satisfied_evidence
                ),
                "missing_evidence": list(
                    assessment.missing_evidence
                ),
                "budget_exhausted": (
                    budget_exhausted
                ),
                "iteration": iteration,
                "max_iterations": (
                    max_iterations
                ),
            },
        )
    )

    return {
        "evidence_sufficiency": (
            assessment
        ),
        "investigation_budget_exhausted": (
            budget_exhausted
        ),
        "investigation_trace": trace,
        "status": status,
    }