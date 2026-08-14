import os
import secrets
from typing import Any

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
)

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AnalystDecision,
    DryRunExecutionResult,
    InvestigationResponse,
    SecurityAlertInput,
)
from app.services.approval_service import (
    apply_analyst_decision,
)
from app.services.dry_run_executor import (
    execute_dry_run,
)
from app.services.investigation_store import (
    InvestigationStore,
    SQLiteInvestigationStore,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)


def create_app(
    investigation_graph: Any = None,
    investigation_store: (
        InvestigationStore | None
    ) = None,
    wazuh_ingest_key: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.4.0",
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
        else SQLiteInvestigationStore(
            os.getenv(
                "ATHENASEC_DB_PATH",
                "data/athenasec.db",
            )
        )
    )

    configured_wazuh_ingest_key = (
        wazuh_ingest_key
        if wazuh_ingest_key is not None
        else os.getenv(
            "ATHENASEC_WAZUH_INGEST_KEY"
        )
    )

    def run_investigation(
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
        return run_investigation(
            alert
        )

    @app.post(
        "/api/v1/integrations/wazuh/alerts",
        response_model=InvestigationResponse,
    )
    def ingest_wazuh_alert(
        payload: dict[str, Any],
        x_athenasec_integration_key: (
            str | None
        ) = Header(
            default=None
        ),
    ) -> InvestigationResponse:
        if not configured_wazuh_ingest_key:
            raise HTTPException(
                status_code=503,
                detail=(
                    "Wazuh ingestion is not configured."
                ),
            )

        provided_key = (
            x_athenasec_integration_key
            or ""
        )

        if not secrets.compare_digest(
            provided_key,
            configured_wazuh_ingest_key,
        ):
            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid Wazuh integration key."
                ),
            )

        try:
            alert = parse_wazuh_alert(
                payload
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        return run_investigation(
            alert
        )

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

    @app.post(
        (
            "/api/v1/investigations/"
            "{alert_id}/execute"
        ),
        response_model=DryRunExecutionResult,
    )
    def execute_investigation(
        alert_id: str,
    ) -> DryRunExecutionResult:
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

        if (
            investigation.execution_result
            is not None
        ):
            return investigation.execution_result

        try:
            execution_result = execute_dry_run(
                investigation.response_plan
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

        store.update_execution_result(
            alert_id,
            execution_result,
        )

        return execution_result

    return app


app = create_app()