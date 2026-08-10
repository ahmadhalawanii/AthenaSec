from typing import Any

from fastapi import FastAPI

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    InvestigationResponse,
    SecurityAlertInput,
)


def create_app(
    investigation_graph: Any = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.1.0",
        description=(
            "Agentic cybersecurity investigation "
            "service for AthenaSec."
        ),
    )

    graph = (
        investigation_graph
        if investigation_graph is not None
        else build_investigation_graph()
    )

    @app.get(
        "/health"
    )
    def health():
        return {
            "status": "ok",
            "service": "athenasec-agent",
        }

    @app.post(
        "/api/v1/analyze",
        response_model=InvestigationResponse,
    )
    def analyze_alert(
        alert: SecurityAlertInput,
    ) -> InvestigationResponse:
        result = graph.invoke(
            {
                "alert": alert,
                "status": "received",
            }
        )

        return InvestigationResponse(
            alert_id=result["alert"].alert_id,
            source=result["alert"].source,
            status=result["status"],
            normalized_event=(
                result["normalized_event"]
            ),
            analysis=result["analysis"],
            evidence_records=(
                result["evidence_records"]
            ),
            risk_assessment=(
                result["risk_assessment"]
            ),
            policy_decision=(
                result["policy_decision"]
            ),
            response_plan=(
                result["response_plan"]
            ),
            investigation_iteration=(
                result.get(
                    "investigation_iteration",
                    0,
                )
            ),
        )

    return app


app = create_app()