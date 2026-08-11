from typing import Any

from fastapi import (
    FastAPI,
    HTTPException,
)

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AnalystDecision,
    InvestigationResponse,
    SecurityAlertInput,
)
from app.services.approval_service import (
    apply_analyst_decision,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)


def create_app(
    investigation_graph: Any = None,
    investigation_store: (
        InMemoryInvestigationStore | None
    ) = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.2.0",
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

    store = (
        investigation_store
        if investigation_store is not None
        else InMemoryInvestigationStore()
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

        investigation = InvestigationResponse(
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

        store.save(
            investigation
        )

        return investigation

    @app.get(
        (
            "/api/v1/investigations/"
            "{alert_id}"
        ),
        response_model=InvestigationResponse,
    )
    def get_investigation(
        alert_id: str,
    ) -> InvestigationResponse:
        investigation = store.get(
            alert_id
        )

        if investigation is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Investigation {alert_id} "
                    "was not found."
                ),
            )

        return investigation

    @app.post(
        (
            "/api/v1/investigations/"
            "{alert_id}/decision"
        ),
        response_model=InvestigationResponse,
    )
    def submit_analyst_decision(
        alert_id: str,
        decision: AnalystDecision,
    ) -> InvestigationResponse:
        investigation = store.get(
            alert_id
        )

        if investigation is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Investigation {alert_id} "
                    "was not found."
                ),
            )

        try:
            updated_plan = apply_analyst_decision(
                investigation.response_plan,
                decision,
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

        return store.update_response_plan(
            alert_id,
            updated_plan,
        )

    return app


app = create_app()