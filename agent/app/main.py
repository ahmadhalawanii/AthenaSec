import os
import secrets
from typing import Any

from fastapi import (
    FastAPI,
    Header,
    HTTPException,
)
from app.llm import (
    propose_security_response,
)
from app.ml.runtime_config import (
    build_live_ml_classifier,
)
import app.services.cortex_config as cortex_config

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    ApprovalDecisionRequest,
    ApprovalRequestRecord,
    AttackPrediction,
    AuditRecord,
    CaseRecord,
    InvestigationResponse,
    SecurityAlertInput,
)
from app.services.audit_service import (
    create_audit_record,
    create_incident_audit_record,
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
from app.services.persistence_config import (
    build_incident_response_store_from_env,
    build_persistence_stores_from_env,
)
from app.services.benign_investigation import (
    build_benign_investigation,
)
from app.services.incident_correlator import (
    correlate_or_create_incident,
)
from app.services.ml_classifier import (
    MLClassifier,
)
from app.services.investigation_lifecycle import (
    build_investigation_id,
    persist_investigation_lifecycle,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
    InMemoryIncidentResponseStore,
)
from app.services.response_risk_lifecycle import (
    persist_response_risk_lifecycle,
)
from app.services.action_policy_lifecycle import (
    persist_action_policy_lifecycle,
)
from app.services.structured_action_policy import (
    apply_structured_action_policy,
    process_structured_policy_outcomes,
)
from app.services.approval_resolution import (
    resolve_approval_request,
)
from app.services.structured_response_runtime import (
    process_structured_response_action,
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
    ml_classifier: (
        MLClassifier | None
    ) = None,
    incident_response_store: (
        IncidentResponseStore | None
    ) = None,
    structured_action_executor: Any = None,
    structured_action_verifier: Any = None,
    structured_rollback_executor: Any = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.5.0",
        description=(
            "Agentic cybersecurity investigation "
            "service for AthenaSec."
        ),
    )

    configured_ml_classifier = (
        ml_classifier
    )

    if investigation_graph is not None:
        graph = investigation_graph

    else:
        if (
            configured_ml_classifier
            is None
        ):
            configured_ml_classifier = (
                build_live_ml_classifier()
            )

        misp_client = (
            build_live_misp_client()
        )

        graph = build_investigation_graph(
            ml_classifier=(
                configured_ml_classifier
            ),
            misp_client=misp_client,
            response_proposer=(
                propose_security_response
            ),
        )

    default_investigation_store = None
    default_audit_store = None

    if (
        investigation_store is None
        or audit_store is None
    ):
        (
            default_investigation_store,
            default_audit_store,
        ) = build_persistence_stores_from_env()

    store = (
        investigation_store
        if investigation_store is not None
        else default_investigation_store
    )

    configured_audit_store = (
        audit_store
        if audit_store is not None
        else default_audit_store
    )

    if (
        incident_response_store
        is not None
    ):
        configured_incident_response_store = (
            incident_response_store
        )

    elif (
        default_investigation_store
        is not None
        or default_audit_store
        is not None
    ):
        configured_incident_response_store = (
            build_incident_response_store_from_env()
        )

    else:
        configured_incident_response_store = (
            InMemoryIncidentResponseStore()
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

    structured_cortex_runtime = (
        cortex_config
        .build_structured_cortex_runtime_from_env()
        if (
            structured_action_executor
            is None
            or structured_rollback_executor
            is None
        )
        else None
    )

    configured_structured_action_executor = (
        structured_action_executor
        if structured_action_executor
        is not None
        else (
            structured_cortex_runtime.executor
            if structured_cortex_runtime
            is not None
            else None
        )
    )

    configured_structured_rollback_executor = (
        structured_rollback_executor
        if structured_rollback_executor
        is not None
        else (
            structured_cortex_runtime
            .rollback_executor
            if structured_cortex_runtime
            is not None
            else None
        )
    )

    configured_structured_action_verifier = (
        structured_action_verifier
    )

    structured_runtime_configured = any(
        component is not None
        for component in (
            configured_structured_action_executor,
            configured_structured_action_verifier,
            configured_structured_rollback_executor,
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

    def save_incident_audit_event(
        *,
        incident_id: str,
        event_type: str,
        entity_type: str,
        entity_id: str,
        message: str,
        details: dict[str, object],
    ) -> None:
        record = (
            create_incident_audit_record(
                incident_id=incident_id,
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                message=message,
                details=details,
            )
        )

        configured_audit_store.save_incident_event(
            record
        )

    def run_structured_action_runtime(
        *,
        proposed_action,
        policy_decision,
        approval_id=None,
    ):
        outcome = (
            process_structured_response_action(
                store=(
                    configured_incident_response_store
                ),
                proposed_action=(
                    proposed_action
                ),
                policy_decision=(
                    policy_decision
                ),
                executor=(
                    configured_structured_action_executor
                ),
                verifier=(
                    configured_structured_action_verifier
                ),
                rollback_executor=(
                    configured_structured_rollback_executor
                ),
                autonomous_response_enabled=(
                    configured_autonomous_response_enabled
                ),
                approval_id=approval_id,
            )
        )

        execution = outcome.execution

        if (
            execution is not None
            and execution.response_action
            is not None
        ):
            response_action = (
                execution.response_action
            )

            save_incident_audit_event(
                incident_id=(
                    proposed_action.incident_id
                ),
                event_type=(
                    "structured_cortex_execution_"
                    + response_action.status
                ),
                entity_type="response_action",
                entity_id=(
                    response_action
                    .response_action_id
                ),
                message=(
                    "Structured Cortex "
                    "execution lifecycle "
                    "was recorded."
                ),
                details={
                    "proposed_action_id": (
                        proposed_action
                        .proposed_action_id
                    ),
                    "status": (
                        response_action.status
                    ),
                    "approval_id": (
                        response_action
                        .approval_id
                    ),
                },
            )

        if (
            execution is not None
            and execution.action_result
            is not None
        ):
            action_result = (
                execution.action_result
            )

            save_incident_audit_event(
                incident_id=(
                    proposed_action.incident_id
                ),
                event_type=(
                    "structured_cortex_result_recorded"
                ),
                entity_type="action_result",
                entity_id=(
                    action_result
                    .action_result_id
                ),
                message=(
                    "Structured Cortex "
                    "execution result "
                    "was persisted."
                ),
                details={
                    "status": (
                        action_result.status
                    ),
                },
            )

        if outcome.verification is not None:
            verification = (
                outcome.verification
            )

            save_incident_audit_event(
                incident_id=(
                    proposed_action.incident_id
                ),
                event_type=(
                    "action_verification_completed"
                ),
                entity_type="verification",
                entity_id=(
                    verification.verification_id
                ),
                message=(
                    "Post-action verification "
                    "was completed."
                ),
                details={
                    "status": (
                        verification.status
                    ),
                    "proposed_action_id": (
                        proposed_action
                        .proposed_action_id
                    ),
                },
            )

        if outcome.rollback is not None:
            rollback = outcome.rollback

            save_incident_audit_event(
                incident_id=(
                    proposed_action.incident_id
                ),
                event_type=(
                    "action_rollback_"
                    + rollback.status
                ),
                entity_type="rollback",
                entity_id=(
                    rollback.rollback_id
                ),
                message=(
                    "Structured response "
                    "rollback was recorded."
                ),
                details={
                    "status": rollback.status,
                    "rollback_action_type": (
                        rollback
                        .rollback_action_type
                    ),
                    "target": (
                        rollback.target
                    ),
                },
            )

        if outcome.incident_case is not None:
            case = outcome.incident_case

            save_incident_audit_event(
                incident_id=(
                    case.incident_id
                ),
                event_type="case_created",
                entity_type="case",
                entity_id=case.case_id,
                message=(
                    "AthenaSec created "
                    "an incident case from "
                    "the structured response "
                    "runtime."
                ),
                details={
                    "policy_decision_id": (
                        case
                        .policy_decision_id
                    ),
                    "reason": case.reason,
                },
            )

        return outcome

    def run_investigation(
        alert: SecurityAlertInput,
        *,
        incident_id: str | None = None,
        ml_prediction: (
            AttackPrediction | None
        ) = None,
        ml_error: str | None = None,
    ) -> InvestigationResponse:
        initial_state = {
            "alert": alert,
            "status": "received",
        }

        investigation_id = None

        if incident_id is not None:
            investigation_id = (
                build_investigation_id(
                    incident_id=(
                        incident_id
                    ),
                    alert_id=(
                        alert.alert_id
                    ),
                )
            )

            initial_state[
                "incident_id"
            ] = incident_id

            initial_state[
                "investigation_id"
            ] = investigation_id

        if ml_prediction is not None:
            initial_state[
                "ml_prediction"
            ] = ml_prediction

        if ml_error is not None:
            initial_state[
                "ml_error"
            ] = ml_error

        result = graph.invoke(
            initial_state
        )

        investigation = InvestigationResponse(
            alert_id=result["alert"].alert_id,
            incident_id=incident_id,
            investigation_id=(
                result.get(
                    "investigation_id",
                    investigation_id,
                )
            ),
            source=result["alert"].source,
            alert_metadata=dict(
                result["alert"].metadata
            ),
            status=result["status"],
            normalized_event=(
                result["normalized_event"]
            ),
            ml_prediction=result.get(
                "ml_prediction",
                ml_prediction,
            ),
            ml_error=result.get(
                "ml_error",
                ml_error,
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
            evidence_sufficiency=(
                result.get(
                    "evidence_sufficiency"
                )
            ),
            analysis_verification=(
                result.get(
                    "analysis_verification"
                )
            ),
            response_proposal=(
                result.get(
                    "response_proposal"
                )
            ),
            proposed_actions=(
                result.get(
                    "proposed_actions",
                    [],
                )
            ),
            action_risk_assessments=(
                result.get(
                    "action_risk_assessments",
                    [],
                )
            ),
            action_policy_decisions=(
                result.get(
                    "action_policy_decisions",
                    [],
                )
            ),
            approval_requests=(
                result.get(
                    "approval_requests",
                    [],
                )
            ),
            investigation_budget_exhausted=(
                result.get(
                    "investigation_budget_exhausted",
                    False,
                )
            ),
            investigation_trace=(
                result.get(
                    "investigation_trace",
                    [],
                )
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

        investigation = (
            apply_structured_action_policy(
                investigation
            )
        )

        lifecycle_record = (
            persist_investigation_lifecycle(
                store=store,
                investigation=investigation,
            )
        )

        if lifecycle_record is not None:
            investigation = (
                investigation.model_copy(
                    update={
                        "investigation_id": (
                            lifecycle_record
                            .investigation_id
                        ),
                    }
                )
            )

        response_risk_lifecycle = (
            persist_response_risk_lifecycle(
                store=(
                    configured_incident_response_store
                ),
                investigation=investigation,
            )
        )

        persist_action_policy_lifecycle(
            store=(
                configured_incident_response_store
            ),
            investigation=investigation,
        )

        store.save(
            investigation
        )

        if (
            response_risk_lifecycle
            is not None
        ):
            incident_risk = (
                response_risk_lifecycle
                .incident_risk
            )

            save_incident_audit_event(
                incident_id=(
                    incident_risk.incident_id
                ),
                event_type=(
                    "incident_risk_assessed"
                ),
                entity_type=(
                    "incident_risk"
                ),
                entity_id=(
                    incident_risk
                    .risk_assessment_id
                ),
                message=(
                    "Deterministic incident "
                    "risk was persisted."
                ),
                details={
                    "score": (
                        incident_risk.score
                    ),
                    "band": (
                        incident_risk.band
                    ),
                },
            )

            for proposed_action in (
                response_risk_lifecycle
                .proposed_actions
            ):
                save_incident_audit_event(
                    incident_id=(
                        proposed_action
                        .incident_id
                    ),
                    event_type=(
                        "response_action_proposed"
                    ),
                    entity_type=(
                        "proposed_action"
                    ),
                    entity_id=(
                        proposed_action
                        .proposed_action_id
                    ),
                    message=(
                        "Structured response "
                        "action was proposed."
                    ),
                    details={
                        "action_type": (
                            proposed_action
                            .action_type
                        ),
                        "target_type": (
                            proposed_action
                            .target_type
                        ),
                        "target": (
                            proposed_action
                            .target
                        ),
                        "reversible": (
                            proposed_action
                            .reversible
                        ),
                    },
                )

            for action_risk in (
                response_risk_lifecycle
                .action_risks
            ):
                save_incident_audit_event(
                    incident_id=(
                        investigation
                        .incident_id
                    ),
                    event_type=(
                        "action_risk_assessed"
                    ),
                    entity_type=(
                        "action_risk"
                    ),
                    entity_id=(
                        action_risk
                        .action_risk_id
                    ),
                    message=(
                        "Deterministic action "
                        "risk was assessed."
                    ),
                    details={
                        "proposed_action_id": (
                            action_risk
                            .proposed_action_id
                        ),
                        "score": (
                            action_risk.score
                        ),
                        "band": (
                            action_risk.band
                        ),
                        "blast_radius": (
                            action_risk
                            .blast_radius
                        ),
                        "requires_approval": (
                            action_risk
                            .requires_approval
                        ),
                    },
                )

        if (
            lifecycle_record is not None
            and (
                investigation
                .analysis_verification
                is not None
            )
        ):
            save_incident_audit_event(
                incident_id=(
                    lifecycle_record
                    .incident_id
                ),
                event_type=(
                    "investigation_completed"
                ),
                entity_type=(
                    "investigation"
                ),
                entity_id=(
                    lifecycle_record
                    .investigation_id
                ),
                message=(
                    "Agentic investigation "
                    "lifecycle was completed "
                    "and persisted."
                ),
                details={
                    "primary_alert_id": (
                        lifecycle_record
                        .primary_alert_id
                    ),
                    "iteration_count": (
                        lifecycle_record
                        .iteration_count
                    ),
                    "budget_exhausted": (
                        lifecycle_record
                        .budget_exhausted
                    ),
                    "evidence_sufficient": (
                        lifecycle_record
                        .evidence_sufficient
                    ),
                    "analysis_verified": (
                        lifecycle_record
                        .analysis_verified
                    ),
                    "step_count": len(
                        investigation
                        .investigation_trace
                    ),
                    "evidence_count": len(
                        investigation
                        .evidence_records
                    ),
                },
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

        if (
            investigation.response_proposal
            is not None
        ):
            structured_outcome = (
                process_structured_policy_outcomes(
                    investigation=investigation,
                    store=(
                        configured_incident_response_store
                    ),
                )
            )

            if (
                investigation.incident_id
                is not None
            ):
                for decision in (
                    investigation
                    .action_policy_decisions
                ):
                    save_incident_audit_event(
                        incident_id=(
                            investigation
                            .incident_id
                        ),
                        event_type=(
                            "action_policy_evaluated"
                        ),
                        entity_type=(
                            "policy_decision"
                        ),
                        entity_id=(
                            decision.decision_id
                        ),
                        message=(
                            "Deterministic action "
                            "policy was evaluated."
                        ),
                        details={
                            "proposed_action_id": (
                                decision
                                .proposed_action_id
                            ),
                            "policy_id": (
                                decision.policy_id
                            ),
                            "outcome": (
                                decision.outcome
                            ),
                        },
                    )

                for approval in (
                    investigation
                    .approval_requests
                ):
                    save_incident_audit_event(
                        incident_id=(
                            investigation
                            .incident_id
                        ),
                        event_type=(
                            "approval_requested"
                        ),
                        entity_type=(
                            "approval_request"
                        ),
                        entity_id=(
                            approval.approval_id
                        ),
                        message=(
                            "Human approval was "
                            "requested for an exact "
                            "structured response "
                            "action."
                        ),
                        details={
                            "proposed_action_id": (
                                approval
                                .proposed_action_id
                            ),
                            "action_fingerprint": (
                                approval
                                .action_fingerprint
                            ),
                            "status": (
                                approval.status
                            ),
                            "expires_at": (
                                approval
                                .expires_at
                                .isoformat()
                                if (
                                    approval
                                    .expires_at
                                    is not None
                                )
                                else None
                            ),
                        },
                    )

                if (
                    structured_outcome[
                        "outcome"
                    ]
                    == "case_created"
                ):
                    case = (
                        structured_outcome[
                            "case"
                        ]
                    )

                    save_incident_audit_event(
                        incident_id=(
                            investigation
                            .incident_id
                        ),
                        event_type=(
                            "case_created"
                        ),
                        entity_type="case",
                        entity_id=(
                            case.case_id
                        ),
                        message=(
                            "AthenaSec created an "
                            "incident case because "
                            "structured action policy "
                            "denied the proposed "
                            "action."
                        ),
                        details={
                            "policy_decision_id": (
                                case
                                .policy_decision_id
                            ),
                            "reason": (
                                case.reason
                            ),
                        },
                    )

            if (
                structured_outcome[
                    "outcome"
                ]
                == "auto_allowed"
                and structured_runtime_configured
            ):
                actions_by_id = {
                    action.proposed_action_id: (
                        action
                    )
                    for action
                    in investigation
                    .proposed_actions
                }

                for decision in (
                    investigation
                    .action_policy_decisions
                ):
                    if (
                        decision.outcome
                        != "AUTO_ALLOWED"
                    ):
                        continue

                    proposed_action = (
                        actions_by_id.get(
                            decision
                            .proposed_action_id
                        )
                    )

                    if proposed_action is None:
                        raise ValueError(
                            "Structured policy "
                            "decision references "
                            "a missing proposed "
                            "action."
                        )

                    run_structured_action_runtime(
                        proposed_action=(
                            proposed_action
                        ),
                        policy_decision=(
                            decision
                        ),
                    )

        elif configured_response_executor is not None:
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

    def run_benign_wazuh_investigation(
        *,
        alert: SecurityAlertInput,
        prediction: AttackPrediction,
    ) -> InvestigationResponse:
        investigation = (
            build_benign_investigation(
                alert=alert,
                prediction=prediction,
            )
        )

        store.save(
            investigation
        )

        save_audit_event(
            alert_id=alert.alert_id,
            event_type=(
                "investigation_created"
            ),
            message=(
                "Benign investigation "
                "record was created."
            ),
            details={
                "source": alert.source,
                "classification": "benign",
                "risk_score": 0,
            },
        )

        save_audit_event(
            alert_id=alert.alert_id,
            event_type=(
                "ml_classification_completed"
            ),
            message=(
                "ML classification completed."
            ),
            details={
                "classification": (
                    prediction.classification
                ),
                "confidence": (
                    prediction.confidence
                ),
                "model_version": (
                    prediction.model_version
                ),
            },
        )

        save_audit_event(
            alert_id=alert.alert_id,
            event_type="policy_evaluated",
            message=(
                "Benign no-action policy "
                "was evaluated."
            ),
            details={
                "policy_id": (
                    "POL-BENIGN-NO-ACTION"
                ),
                "matched": True,
                "response_allowed": False,
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

        if configured_ml_classifier is None:
            return run_investigation(
                alert
            )

        try:
            prediction = (
                configured_ml_classifier
                .classify(
                    alert
                )
            )

            ml_error = None

        except Exception as exc:
            prediction = AttackPrediction(
                classification="unknown",
                confidence=0.0,
                model_version="unavailable",
            )

            ml_error = str(exc)

        if (
            prediction.classification
            == "benign"
            and ml_error is None
        ):
            return (
                run_benign_wazuh_investigation(
                    alert=alert,
                    prediction=prediction,
                )
            )

        correlation = (
            correlate_or_create_incident(
                alert=alert,
                prediction=prediction,
                store=store,
            )
        )

        if correlation.duplicate_alert:
            save_incident_audit_event(
                incident_id=(
                    correlation
                    .incident
                    .incident_id
                ),
                event_type=(
                    "duplicate_alert_received"
                ),
                entity_type="alert",
                entity_id=alert.alert_id,
                message=(
                    "Duplicate Wazuh alert "
                    "was received."
                ),
                details={
                    "classification": (
                        prediction
                        .classification
                    ),
                    "correlation_score": (
                        correlation
                        .correlation_score
                    ),
                    "correlation_reasons": (
                        correlation
                        .correlation_reasons
                    ),
                },
            )

            existing_investigation = (
                store.get(
                    alert.alert_id
                )
            )

            if (
                existing_investigation
                is not None
            ):
                return (
                    existing_investigation
                )

        else:
            if (
                correlation
                .created_new_incident
            ):
                event_type = (
                    "incident_created"
                )

                entity_type = (
                    "incident"
                )

                entity_id = (
                    correlation
                    .incident
                    .incident_id
                )

                message = (
                    "A new incident was "
                    "created for the Wazuh alert."
                )

            else:
                event_type = (
                    "alert_correlated"
                )

                entity_type = "alert"

                entity_id = (
                    alert.alert_id
                )

                message = (
                    "Wazuh alert was correlated "
                    "to an existing incident."
                )

            save_incident_audit_event(
                incident_id=(
                    correlation
                    .incident
                    .incident_id
                ),
                event_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id,
                message=message,
                details={
                    "classification": (
                        prediction
                        .classification
                    ),
                    "correlation_score": (
                        correlation
                        .correlation_score
                    ),
                    "correlation_reasons": (
                        correlation
                        .correlation_reasons
                    ),
                },
            )

        return run_investigation(
            alert,
            incident_id=(
                correlation
                .incident
                .incident_id
            ),
            ml_prediction=prediction,
            ml_error=ml_error,
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

    @app.get(
        "/api/v1/approvals/{approval_id}",
        response_model=(
            ApprovalRequestRecord
        ),
    )
    def get_approval_request(
        approval_id: str,
    ) -> ApprovalRequestRecord:
        approval = (
            configured_incident_response_store
            .get_approval_request(
                approval_id
            )
        )

        if approval is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    "Approval request "
                    "was not found."
                ),
            )

        return approval

    @app.post(
        (
            "/api/v1/approvals/"
            "{approval_id}/decision"
        ),
        response_model=(
            ApprovalRequestRecord
        ),
    )
    def decide_approval(
        approval_id: str,
        request: ApprovalDecisionRequest,
    ) -> ApprovalRequestRecord:
        try:
            resolution = (
                resolve_approval_request(
                    store=(
                        configured_incident_response_store
                    ),
                    approval_id=(
                        approval_id
                    ),
                    decision=(
                        request.decision
                    ),
                    decided_by=(
                        request.decided_by
                    ),
                    reason=request.reason,
                )
            )

        except LookupError as exc:
            raise HTTPException(
                status_code=404,
                detail=str(exc),
            ) from exc

        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

        approval = (
            resolution.approval
        )

        save_incident_audit_event(
            incident_id=(
                approval.incident_id
            ),
            event_type=(
                "approval_decided"
            ),
            entity_type=(
                "approval_request"
            ),
            entity_id=(
                approval.approval_id
            ),
            message=(
                "Human approval decision "
                "was recorded."
            ),
            details={
                "proposed_action_id": (
                    approval
                    .proposed_action_id
                ),
                "status": (
                    approval.status
                ),
                "decided_by": (
                    approval.decided_by
                ),
                "decision_reason": (
                    approval
                    .decision_reason
                ),
            },
        )

        if (
            resolution.incident_case
            is not None
        ):
            case = (
                resolution.incident_case
            )

            save_incident_audit_event(
                incident_id=(
                    case.incident_id
                ),
                event_type=(
                    "case_created"
                ),
                entity_type="case",
                entity_id=(
                    case.case_id
                ),
                message=(
                    "AthenaSec created "
                    "an incident case "
                    "after the approval "
                    "workflow did not "
                    "authorize execution."
                ),
                details={
                    "policy_decision_id": (
                        case
                        .policy_decision_id
                    ),
                    "reason": (
                        case.reason
                    ),
                },
            )

        if (
            approval.status == "APPROVED"
            and structured_runtime_configured
        ):
            proposed_action = (
                configured_incident_response_store
                .get_proposed_action(
                    approval
                    .proposed_action_id
                )
            )

            policy_decision = (
                configured_incident_response_store
                .get_policy_decision(
                    approval
                    .policy_decision_id
                )
            )

            if (
                proposed_action is None
                or policy_decision is None
            ):
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Approved action "
                        "references missing "
                        "runtime records."
                    ),
                )

            run_structured_action_runtime(
                proposed_action=(
                    proposed_action
                ),
                policy_decision=(
                    policy_decision
                ),
                approval_id=(
                    approval.approval_id
                ),
            )

        return approval

    return app
