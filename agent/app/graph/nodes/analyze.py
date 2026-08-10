from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import AlertAnalysis


Analyzer = Callable[[str], AlertAnalysis]


def make_analyze_alert_node(
    analyzer: Analyzer,
):
    def analyze_alert(
        state: InvestigationState,
    ) -> InvestigationState:
        analysis = analyzer(
            state["normalized_event"]
        )

        return {
            "analysis": analysis,
            "status": "analyzed",
        }

    return analyze_alert