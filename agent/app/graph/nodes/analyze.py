from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import AlertAnalysis


Analyzer = Callable[
    [str],
    AlertAnalysis,
]


def build_analysis_context(
    state: InvestigationState,
) -> str:
    records = state.get(
        "evidence_records",
        [],
    )

    evidence_text = "\n\n".join(
        (
            f"[{record.evidence_id}] "
            f"source={record.source}\n"
            f"{record.content}"
        )
        for record in records
    )

    return (
        "AVAILABLE EVIDENCE RECORDS:\n\n"
        f"{evidence_text}"
    )


def validate_evidence_references(
    state: InvestigationState,
    analysis: AlertAnalysis,
) -> None:
    records = state.get(
        "evidence_records",
        [],
    )

    valid_ids = {
        record.evidence_id
        for record in records
    }

    if (
        records
        and not analysis.evidence_refs
    ):
        raise ValueError(
            "Analysis must cite at least one "
            "available evidence record."
        )

    invalid_ids = [
        evidence_id
        for evidence_id in analysis.evidence_refs
        if evidence_id not in valid_ids
    ]

    if invalid_ids:
        raise ValueError(
            "Analysis referenced unavailable evidence: "
            + ", ".join(invalid_ids)
        )


def make_analyze_alert_node(
    analyzer: Analyzer,
):
    def analyze_alert(
        state: InvestigationState,
    ) -> InvestigationState:
        context = build_analysis_context(
            state
        )

        analysis = analyzer(
            context
        )

        validate_evidence_references(
            state,
            analysis,
        )

        return {
            "analysis": analysis,
            "status": "analyzed",
        }

    return analyze_alert