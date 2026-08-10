from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import AlertAnalysis


Analyzer = Callable[[str], AlertAnalysis]


def build_analysis_context(
    state: InvestigationState,
) -> str:
    event = state["normalized_event"]

    evidence = state.get(
        "gathered_evidence",
        [],
    )

    if not evidence:
        return event

    evidence_text = "\n".join(
        f"- {item}" for item in evidence
    )

    return (
        f"ORIGINAL EVENT:\n"
        f"{event}\n\n"
        f"ADDITIONAL EVIDENCE:\n"
        f"{evidence_text}"
    )


def make_analyze_alert_node(
    analyzer: Analyzer,
):
    def analyze_alert(
        state: InvestigationState,
    ) -> InvestigationState:
        context = build_analysis_context(state)

        analysis = analyzer(context)

        return {
            "analysis": analysis,
            "status": "analyzed",
        }

    return analyze_alert