import os
import secrets
from typing import Any

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
)
from app.ml.runtime_config import (
    build_live_ml_classifier,
)
import app.services.cortex_config as cortex_config

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AuditRecord,
    CaseRecord,
    InvestigationResponse,
    SecurityAlertInput,
)
from app.services.audit_service import (
    create_audit_record,
)
from app.services.audit_store import (
    AuditStore,
    SQLiteAuditStore,
)
from app.services.autonomous_response import (
    ResponseExecutor,
    process_autonomous_response,
)
from app.services.case_service import (
    create_case_record,
)
from app.services.investigation_store import (
    InvestigationStore,
    SQLiteInvestigationStore,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)
from app.services.misp_config import (
    build_live_misp_client,
)


def _read_autonomous_response_enabled() -> bool:
    value = os.getenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "false",
    )

    return value.strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def create_app(
    investigation_graph: Any = None,
    investigation_store: (
        InvestigationStore | None
    ) = None,
    wazuh_ingest_key: str | None = None,
    response_executor: (
        ResponseExecutor | None
    ) = None,
    autonomous_response_enabled: (
        bool | None
    ) = None,
    audit_store: (
        AuditStore | None
    ) = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.5.0",
        description=(
            "Agentic cybersecurity investigation "
            "service for AthenaSec."
        ),
    )

    if investigation_graph is not None:
        graph = investigation_graph
    else:
        ml_classifier = (
            build_live_ml_classifier()
        )

        misp_client = (
            build_live_misp_client()
        )

        graph = build_investigation_graph(
            ml_classifier=ml_classifier,
            misp_client=misp_client,
        )

    database_path = os.getenv(
        "ATHENASEC_DB_PATH",
        "data/athenasec.db",
    )

    store = (
        investigation_store
        if investigation_store is not None
        else SQLiteInvestigationStore(
            database_path
        )
    )

    configured_audit_store = (
        audit_store
        if audit_store is not None
        else SQLiteAuditStore(
            database_path
        )
    )

    configured_wazuh_ingest_key = (
        wazuh_ingest_key
        if wazuh_ingest_key is not None
        else os.getenv(
            "ATHENASEC_WAZUH_INGEST_KEY"
        )
    )

    configured_autonomous_response_enabled = (
        autonomous_response_enabled
        if autonomous_response_enabled is not None
        else _read_autonomous_response_enabled()
    )

    configured_response_executor = (
        response_executor
        if response_executor is not None
        else (
            cortex_config
            .build_cortex_response_executor_from_env()
        )
    )

    def save_audit_event(
        alert_id: str,
        event_type: str,
        message: str,
        details: dict[str, object],
    ) -> None:
        record = create_audit_record(
            alert_id=alert_id,
            event_type=event_type,
            message=message,
            details=details,
        )

        configured_audit_store.save(
            record
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
            alert_metadata=dict(
                result["alert"].metadata
            ),
            status=result["status"],
            normalized_event=(
                result["normalized_event"]
            ),
            ml_prediction=result.get(
                "ml_prediction"
            ),
            ml_error=result.get(
                "ml_error"
            ),
            misp_enrichment=result.get(
                "misp_enrichment"
            ),
            misp_error=result.get(
                "misp_error"
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

        save_audit_event(
            alert_id=investigation.alert_id,
            event_type="investigation_created",
            message=(
                "Investigation was created."
            ),
            details={
                "source": investigation.source,
                "classification": (
                    investigation
                    .analysis
                    .classification
                ),
                "risk_score": (
                    investigation
                    .risk_assessment
                    .score
                ),
            },
        )

        if (
            investigation.ml_prediction
            is not None
            and investigation.ml_error
            is None
        ):
            save_audit_event(
                alert_id=investigation.alert_id,
                event_type=(
                    "ml_classification_completed"
                ),
                message=(
                    "ML classification completed."
                ),
                details={
                    "classification": (
                        investigation
                        .ml_prediction
                        .classification
                    ),
                    "confidence": (
                        investigation
                        .ml_prediction
                        .confidence
                    ),
                    "model_version": (
                        investigation
                        .ml_prediction
                        .model_version
                    ),
                },
            )

        elif investigation.ml_error is not None:
            save_audit_event(
                alert_id=investigation.alert_id,
                event_type=(
                    "ml_classification_failed"
                ),
                message=(
                    "ML classification failed."
                ),
                details={
                    "error": investigation.ml_error,
                    "classification": (
                        investigation
                        .ml_prediction
                        .classification
                        if (
                            investigation
                            .ml_prediction
                            is not None
                        )
                        else "unknown"
                    ),
                    "confidence": (
                        investigation
                        .ml_prediction
                        .confidence
                        if (
                            investigation
                            .ml_prediction
                            is not None
                        )
                        else 0.0
                    ),
                    "model_version": (
                        investigation
                        .ml_prediction
                        .model_version
                        if (
                            investigation
                            .ml_prediction
                            is not None
                        )
                        else "unavailable"
                    ),
                },
            )


        if investigation.misp_error is not None:
            queried_indicators = []

            if (
                investigation.misp_enrichment
                is not None
            ):
                queried_indicators = (
                    investigation
                    .misp_enrichment
                    .queried_indicators
                )

            save_audit_event(
                alert_id=investigation.alert_id,
                event_type=(
                    "misp_enrichment_failed"
                ),
                message=(
                    "MISP enrichment failed."
                ),
                details={
                    "error": (
                        investigation.misp_error
                    ),
                    "queried_indicators": (
                        queried_indicators
                    ),
                },
            )

        elif (
            investigation.misp_enrichment
            is not None
        ):
            save_audit_event(
                alert_id=investigation.alert_id,
                event_type=(
                    "misp_enrichment_completed"
                ),
                message=(
                    "MISP enrichment completed."
                ),
                details={
                    "queried_indicators": (
                        investigation
                        .misp_enrichment
                        .queried_indicators
                    ),
                    "match_count": len(
                        investigation
                        .misp_enrichment
                        .matches
                    ),
                },
            )


        save_audit_event(
            alert_id=investigation.alert_id,
            event_type="policy_evaluated",
            message=(
                "Autonomous response policy "
                "was evaluated."
            ),
            details={
                "policy_id": (
                    investigation
                    .policy_decision
                    .policy_id
                ),
                "matched": (
                    investigation
                    .policy_decision
                    .matched
                ),
                "response_allowed": (
                    investigation
                    .policy_decision
                    .response_allowed
                ),
            },
        )

        if configured_response_executor is not None:
            ready_for_execution = (
                investigation.response_plan.status
                == "ready_for_execution"
            )

            should_execute = (
                ready_for_execution
                and (
                    configured_autonomous_response_enabled
                )
            )

            kill_switch_blocked = (
                ready_for_execution
                and not (
                    configured_autonomous_response_enabled
                )
            )

            if kill_switch_blocked:
                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type=(
                        "autonomous_response_blocked"
                    ),
                    message=(
                        "Autonomous response was "
                        "blocked by the global "
                        "kill switch."
                    ),
                    details={
                        "policy_id": (
                            investigation
                            .policy_decision
                            .policy_id
                        ),
                        "actions": list(
                            investigation
                            .response_plan
                            .actions
                        ),
                        "autonomous_response_enabled": (
                            False
                        ),
                    },
                )

            if should_execute:
                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type=(
                        "cortex_execution_started"
                    ),
                    message=(
                        "Cortex autonomous response "
                        "execution started."
                    ),
                    details={
                        "policy_id": (
                            investigation
                            .policy_decision
                            .policy_id
                        ),
                        "actions": list(
                            investigation
                            .response_plan
                            .actions
                        ),
                    },
                )

            response_outcome = (
                process_autonomous_response(
                    investigation=investigation,
                    store=store,
                    executor=(
                        configured_response_executor
                    ),
                    autonomous_response_enabled=(
                        configured_autonomous_response_enabled
                    ),
                )
            )

            updated_investigation = store.get(
                investigation.alert_id
            )

            if updated_investigation is not None:
                investigation = (
                    updated_investigation
                )

            if (
                response_outcome["outcome"]
                == "executed"
            ):
                execution_result = (
                    investigation.execution_result
                )

                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type=(
                        "cortex_execution_completed"
                    ),
                    message=(
                        "Cortex autonomous response "
                        "execution completed."
                    ),
                    details={
                        "policy_id": (
                            investigation
                            .policy_decision
                            .policy_id
                        ),
                        "actions": list(
                            investigation
                            .response_plan
                            .actions
                        ),
                        "status": (
                            execution_result.status
                            if execution_result
                            is not None
                            else "completed"
                        ),
                    },
                )

            elif (
                should_execute
                and (
                    response_outcome["outcome"]
                    == "case_created"
                )
            ):
                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type=(
                        "cortex_execution_failed"
                    ),
                    message=(
                        "Cortex autonomous response "
                        "execution failed."
                    ),
                    details={
                        "policy_id": (
                            investigation
                            .policy_decision
                            .policy_id
                        ),
                        "actions": list(
                            investigation
                            .response_plan
                            .actions
                        ),
                        "fallback": (
                            "case_created"
                        ),
                    },
                )

            case = store.get_case_by_alert_id(
                investigation.alert_id
            )

            if case is not None:
                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type="case_created",
                    message=(
                        "Case was created "
                        "automatically."
                    ),
                    details={
                        "case_id": case.case_id,
                        "policy_id": (
                            case.policy_id
                        ),
                        "risk_score": (
                            case.risk_score
                        ),
                    },
                )
        elif (
            investigation.response_plan.status
            in {
                "create_case",
                "ready_for_execution",
            }
        ):
            case_investigation = investigation

            if (
                investigation.response_plan.status
                == "ready_for_execution"
            ):
                fallback_plan = (
                    investigation
                    .response_plan
                    .model_copy(
                        update={
                            "response_allowed": False,
                            "actions": [],
                            "status": "create_case",
                            "reason": (
                                "Autonomous response "
                                "could not execute "
                                "because the Cortex "
                                "executor is unavailable."
                            ),
                        }
                    )
                )

                case_investigation = (
                    investigation.model_copy(
                        update={
                            "response_plan": (
                                fallback_plan
                            )
                        }
                    )
                )

            case = create_case_record(
                case_investigation
            )

            store.save_case(
                case
            )

            save_audit_event(
                alert_id=investigation.alert_id,
                event_type="case_created",
                message=(
                    "Case was created "
                    "automatically."
                ),
                details={
                    "case_id": case.case_id,
                    "policy_id": (
                        case.policy_id
                    ),
                    "risk_score": (
                        case.risk_score
                    ),
                    "fallback_reason": (
                        "cortex_unavailable"
                        if (
                            investigation
                            .response_plan
                            .status
                            == "ready_for_execution"
                        )
                        else "policy_case"
                    ),
                },
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

    @app.get(
        (
            "/api/v1/investigations/"
            "{alert_id}/case"
        ),
        response_model=CaseRecord,
    )
    def get_case_for_investigation(
        alert_id: str,
    ) -> CaseRecord:
        case = store.get_case_by_alert_id(
            alert_id
        )

        if case is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Case for investigation "
                    f"{alert_id} was not found."
                ),
            )

        return case

    @app.get(
        (
            "/api/v1/investigations/"
            "{alert_id}/audit"
        ),
        response_model=list[AuditRecord],
    )
    def get_investigation_audit_history(
        alert_id: str,
    ) -> list[AuditRecord]:
        return (
            configured_audit_store
            .list_by_alert_id(
                alert_id
            )
        )

    return app


app = create_app()