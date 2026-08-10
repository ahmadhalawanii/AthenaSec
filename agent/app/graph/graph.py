from collections.abc import Callable

from langgraph.graph import (
    END,
    START,
    StateGraph,
)

from app.graph.nodes.analyze import (
    make_analyze_alert_node,
)
from app.graph.nodes.finalize import (
    finalize_investigation,
)
from app.graph.nodes.gather_evidence import (
    make_gather_evidence_node,
)
from app.graph.nodes.normalize import (
    normalize_alert,
)
from app.graph.routing import (
    route_after_analysis,
)
from app.graph.state import InvestigationState
from app.llm import analyze_security_event
from app.schemas import (
    AlertAnalysis,
    SecurityAlertInput,
)
from app.tools.mock_wazuh import (
    search_related_security_events,
)


Analyzer = Callable[
    [str],
    AlertAnalysis,
]

EvidenceProvider = Callable[
    [SecurityAlertInput],
    list[str],
]


def build_investigation_graph(
    analyzer: Analyzer = analyze_security_event,
    evidence_provider: EvidenceProvider = (
        search_related_security_events
    ),
):
    builder = StateGraph(
        InvestigationState
    )

    builder.add_node(
        "normalize_alert",
        normalize_alert,
    )

    builder.add_node(
        "analyze_alert",
        make_analyze_alert_node(
            analyzer
        ),
    )

    builder.add_node(
        "gather_evidence",
        make_gather_evidence_node(
            evidence_provider
        ),
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

    builder.add_conditional_edges(
        "analyze_alert",
        route_after_analysis,
    )

    builder.add_edge(
        "gather_evidence",
        "analyze_alert",
    )

    builder.add_edge(
        "finalize_investigation",
        END,
    )

    return builder.compile()