from app.graph.state import (
    InvestigationState,
)
from app.services.analysis_verifier import (
    verify_analysis,
)
from app.services.investigation_trace import (
    append_investigation_trace,
)


def verify_investigation_analysis(
    state: InvestigationState,
) -> InvestigationState:
    verification = verify_analysis(
        alert=state["alert"],
        analysis=state["analysis"],
        evidence_records=state.get(
            "evidence_records",
            [],
        ),
        ml_prediction=state.get(
            "ml_prediction"
        ),
        evidence_sufficiency=(
            state.get(
                "evidence_sufficiency"
            )
        ),
        investigation_budget_exhausted=(
            state.get(
                "investigation_budget_exhausted",
                False,
            )
        ),
    )

    status = (
        "analysis_verified"
        if verification.verified
        else "analysis_verification_failed"
    )

    trace = (
        append_investigation_trace(
            state,
            step_type=(
                "analysis_verification"
            ),
            status=status,
            details={
                "verified": (
                    verification.verified
                ),
                "classification_consistent": (
                    verification
                    .classification_consistent
                ),
                "evidence_sufficient": (
                    verification
                    .evidence_sufficient
                ),
                "checked_evidence_refs": list(
                    verification
                    .checked_evidence_refs
                ),
                "blocking_issues": list(
                    verification
                    .blocking_issues
                ),
                "warnings": list(
                    verification.warnings
                ),
            },
        )
    )

    return {
        "analysis_verification": (
            verification
        ),
        "investigation_trace": trace,
        "status": status,
    }