from app.graph.state import (
    InvestigationState,
)
from app.services.investigations.analysis_verifier import (
    verify_analysis,
)
from app.services.investigations.investigation_trace import (
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

    # _ATHENASEC_CONFLICT_ADJUDICATION_V1
    # Preserve Qwen's original label in the earlier analysis trace.
    # Contradictory source evidence triggers deterministic abstention.
    final_analysis = state["analysis"]
    if "contradictory_authentication_evidence" in verification.blocking_issues:
        relevant = [
            record.evidence_id
            for record in state.get("evidence_records", [])
            if record.evidence_type in {
                "authentication_history", "related_security_events"
            }
        ]
        final_analysis = final_analysis.model_copy(update={
            "classification": "unknown",
            "confidence": 0.0,
            "summary": (
                "Conflicting authentication records prevent a reliable "
                "attack classification; analyst review is required."
            ),
            "evidence_refs": list(dict.fromkeys(
                [*final_analysis.evidence_refs, *relevant]
            )),
            "uncertainties": [
                *final_analysis.uncertainties,
                "Same source IP has conflicting authentication failure counts.",
            ],
            "recommended_response_actions": [],
            "needs_more_evidence": False,
            "requested_evidence": [],
        })

    return {
        "analysis": final_analysis,
        "analysis_verification": (
            verification
        ),
        "investigation_trace": trace,
        "status": status,
    }