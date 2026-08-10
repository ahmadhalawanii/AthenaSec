from collections.abc import Callable

from langgraph.graph import END, START, StateGraph

from app.graph.nodes.analyze import (
    make_analyze_alert_node,
)
from app.graph.nodes.finalize import (
    finalize_investigation,
)
from app.graph.nodes.normalize import normalize_alert
from app.graph.state import InvestigationState
from app.llm import analyze_security_event
from app.schemas import AlertAnalysis


Analyzer = Callable[[str], AlertAnalysis]


def build_investigation_graph(
    analyzer: Analyzer = analyze_security_event,
):
    builder = StateGraph(InvestigationState)

    builder.add_node(
        "normalize_alert",
        normalize_alert,
    )

    builder.add_node(
        "analyze_alert",
        make_analyze_alert_node(analyzer),
    )

    builder.add_node(
        "finalize_investigation",
        finalize_investigation,
    )

    builder.add_edge(
        START,
        "normalize_alert",
    )

    builder.add_edge(
        "normalize_alert",
        "analyze_alert",
    )

    builder.add_edge(
        "analyze_alert",
        "finalize_investigation",
    )

    builder.add_edge(
        "finalize_investigation",
        END,
    )

    return builder.compile()