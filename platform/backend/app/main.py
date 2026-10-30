import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import (
    Path,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app.ml.operational_events import (
    operational_event_reason,
)
from app.services.investigations.operational_event_investigation import (
    build_operational_event_investigation,
)
from app.llm import (
    ModelUnavailable,
    propose_security_response,
)
from app.ml.runtime_config import (
    build_live_ml_classifier,
)
import app.services.cortex.cortex_config as cortex_config

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    ActionPolicyContent,
    ActionPolicyDocument,
    ActionPolicyUpdateRequest,
    ActionPolicyVersionListResponse,
    AlertDetail,
    ApprovalActionDetail,
    AlertListResponse,
    AlertWorkflowRecord,
    CaseActionRecord,
    CaseActionUpdateRequest,
    CaseNoteRecord,
    CaseWorkflowRecord,
    StatusChangeRequest,
    ConfigurationDocument,
    ConfigurationUpdateRequest,
    ConfigurationValues,
    PasswordChangeRequest,
    AccountActivityEntry,
    AccountActivityResponse,
    ResponseRun,
    ResponseRunListResponse,
    ResponseStep,
    ProfileDocument,
    ProfileUpdateRequest,
    UserSettings,
    UserCredentialsResponse,
    MfaResetResponse,
    UserStatusRequest,
    UserWriteRequest,
    ApprovalDecisionRequest,
    ApprovalListResponse,
    ApprovalRequestRecord,
    AttackClassification,
    AttackPrediction,
    AuditEvent,
    AuditListResponse,
    AuditRecord,
    AuditResult,
    Case,
    CaseListResponse,
    ChainVerification,
    DashboardSummary,
    DashboardWindow,
    HealthEventListResponse,
    HealthSeverity,
    IncidentCaseStatus,
    CaseRecord,
    InvestigationListResponse,
    PolicyDocument,
    PolicyUpdateRequest,
    PolicyVersionListResponse,
    PolicyVersionSummary,
    SystemHealth,
    InvestigationResponse,
    RuntimeControlUpdateRequest,
    SecurityAlertInput,
    UserListResponse,
    UserRecord,
    UserRole,
)
from app.services.audit.audit_service import (
    create_audit_record,
    create_incident_audit_record,
)
from app.services.audit.audit_store import (
    AuditStore,
    SQLiteAuditStore,
)
from app.services.response.autonomous_response import ResponseExecutor
from app.services.cases.case_service import (
    create_case_record,
)
from app.services.investigations.investigation_store import (
    build_alert_list,
    InvestigationStore,
    SQLiteInvestigationStore,
)
from app.tools.wazuh_alert_parser import (
    parse_wazuh_alert,
)
from app.services.misp.misp_config import (
    build_live_misp_client,
)
from app.services.storage.persistence_config import (
    build_alert_workflow_store_from_env,
    build_settings_store_from_env,
    build_case_workflow_store_from_env,
    build_incident_response_store_from_env,
    build_health_event_store_from_env,
    build_operator_audit_store_from_env,
    build_action_policy_store_from_env,
    build_response_policy_store_from_env,
    build_persistence_stores_from_env,
    build_runtime_control_store_from_env,
    build_target_protection_store_from_env,
    build_containment_expiry_store_from_env,
)
from app.services.dashboard.list_pagination import (
    DEFAULT_LIST_LIMIT,
    MAX_LIST_LIMIT,
    InvalidCursor,
    as_utc,
    paginate,
)
import app.services.dashboard.dashboard_summary as dashboard_module
from app.services.dashboard.dashboard_summary import build_dashboard_summary
from app.services.cases.case_view import (
    build_case,
    case_matches,
)
from app.services.runtime.settings_store import (
    InMemorySettingsStore,
    SettingsSchemaNotReady,
    SettingsVersionConflict,
)
from app.services.investigations.alert_workflow_store import (
    AlertWorkflowSchemaNotReady,
    InMemoryAlertWorkflowStore,
)
from app.services.cases.case_workflow_store import (
    CaseWorkflowSchemaNotReady,
    InMemoryCaseWorkflowStore,
)
import app.services.health.health_probes as health_module
from app.services.health.health_event_store import (
    HealthSchemaNotReady,
    InMemoryHealthEventStore,
)
from app.services.health.health_probes import default_probes
from app.services.health.system_health import build_system_health
from app.services.policy.policy_document import (
    build_policy_document,
    read_protected_targets,
)
from app.services.policy.action_catalogue import validate_action_policy
from app.services.policy.action_policy_store import (
    ActionPolicySchemaNotReady,
    ActionPolicyVersionConflict,
    InMemoryActionPolicyStore,
    current_or_default,
    default_document,
)
from app.services.policy.response_policy_store import (
    InMemoryResponsePolicyStore,
    PolicySchemaNotReady,
    PolicyVersionConflict,
)
from app.services.audit.operator_audit_store import (
    InMemoryOperatorAuditStore,
    OperatorAuditSchemaNotReady,
    incident_event_view,
    view_matches,
)
from app.services.investigations.benign_investigation import (
    build_benign_investigation,
)
from app.services.investigations.incident_correlator import (
    correlate_or_create_incident,
)
from app.services.investigations.ml_classifier import (
    MLClassifier,
)
from app.services.investigations.investigation_lifecycle import (
    build_investigation_id,
    persist_investigation_lifecycle,
)
from app.services.storage.incident_response_store import (
    IncidentResponseStore,
    InMemoryIncidentResponseStore,
)
from app.services.risk.response_risk_lifecycle import (
    persist_response_risk_lifecycle,
)
from app.services.policy.action_policy_lifecycle import (
    persist_action_policy_lifecycle,
)
from app.services.policy.structured_action_policy import (
    apply_structured_action_policy,
    process_structured_policy_outcomes,
)
from app.services.approvals.approval_resolution import (
    resolve_approval_request,
)
from app.services.response.structured_response_runtime import (
    process_structured_response_action,
)
from app.services.policy.response_mode import (
    normalize_response_mode,
)
from app.services.runtime.runtime_control import (
    RuntimeControlManager,
)
from app.services.runtime.runtime_control_store import (
    InMemoryRuntimeControlStore,
)
from app.services.execution.target_protection import (
    PersistentTargetProtectionRegistry,
    initialize_target_protection_store_from_env,
)
from app.services.execution.target_protection_store import (
    InMemoryTargetProtectionStore,
)
from app.services.containment.containment_expiry_store import (
    InMemoryContainmentExpiryStore,
    PostgresContainmentExpiryStore,
)
from app.services.execution.target_operation_coordinator import (
    InMemoryTargetOperationCoordinator,
    PostgresTargetOperationCoordinator,
)
from app.services.risk.action_risk_context import (
    make_action_risk_context_provider,
)
from app.services.auth.operator_identity import (
    build_operator_identity_store_from_env,
)
from app.services.auth.web_auth import (
    SESSION_COOKIE_NAME,
    InvalidCredentials,
    UserConflict,
    UsersSchemaNotReady,
    build_browser_auth_store_from_env,
)


class BrowserLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=1024)


class BrowserMfaRequest(BaseModel):
    challenge: str = Field(min_length=1, max_length=200)
    code: str = Field(min_length=6, max_length=6)


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


DEFAULT_CORS_ORIGINS = "http://localhost:5173"


def _read_cors_origins(
    configured: list[str] | None = None,
) -> list[str]:
    if configured is None:
        raw = os.getenv(
            "ATHENASEC_CORS_ORIGINS",
            DEFAULT_CORS_ORIGINS,
        )
        configured = raw.split(",")

    origins = [
        origin.strip().rstrip("/")
        for origin in configured
        if origin.strip()
    ]

    # Browser login uses a session cookie, so credentials are allowed and
    # origins must be explicit. A wildcard is refused rather than ignored.
    if "*" in origins:
        raise ValueError(
            "ATHENASEC_CORS_ORIGINS must list explicit origins; "
            "'*' is not allowed because credentials are enabled."
        )

    return origins


# The only routes open while a temporary password is in use
PASSWORD_CHANGE_PATHS = frozenset({
    "/api/v1/auth/me",
    "/api/v1/auth/logout",
    "/api/v1/me/password",
})


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
    response_mode: str | None = None,
    operator_control_key: str | None = None,
    runtime_control_store: Any = None,
    target_protection_registry: Any = None,
    target_protection_store: Any = None,
    containment_expiry_store: Any = None,
    target_operation_coordinator: Any = None,
    operator_identity_store: Any = None,
    browser_auth_store: Any = None,
    cors_origins: list[str] | None = None,
    operator_audit_store: Any = None,
    case_workflow_store: Any = None,
    alert_workflow_store: Any = None,
    settings_store: Any = None,
    response_policy_store: Any = None,
    action_policy_store: Any = None,
    health_event_store: Any = None,
    health_probes: Any = None,
) -> FastAPI:
    app = FastAPI(
        title="AthenaSec Agent API",
        version="0.5.0",
        description=(
            "Agentic cybersecurity investigation "
            "service for AthenaSec."
        ),
    )

    configured_cors_origins = _read_cors_origins(
        cors_origins
    )

    if configured_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=configured_cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT"],
            allow_headers=["*"],
        )

    configured_ml_classifier = (
        ml_classifier
    )

    if target_protection_registry is not None:
        configured_target_protection_registry = (
            target_protection_registry
        )

    else:
        if target_protection_store is not None:
            configured_target_protection_store = (
                target_protection_store
            )

        elif (
            investigation_store is None
            or audit_store is None
        ):
            configured_target_protection_store = (
                build_target_protection_store_from_env()
            )

        else:
            configured_target_protection_store = (
                InMemoryTargetProtectionStore()
            )

        initialize_target_protection_store_from_env(
            configured_target_protection_store
        )

        configured_target_protection_registry = (
            PersistentTargetProtectionRegistry(
                configured_target_protection_store
            )
        )

    def action_policy_in_force():
        # The administrator's newest action policy, or the built-in default before
        # one is saved (or while the table is not migrated yet).
        try:
            return current_or_default(configured_action_policy_store)
        except ActionPolicySchemaNotReady:
            return default_document()

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
            action_risk_context_provider=(
                make_action_risk_context_provider(
                    configured_target_protection_registry
                )
            ),
            # The administrator's whitelist and blacklist, read for every investigation
            action_policy_provider=action_policy_in_force,
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

    if health_event_store is not None:
        configured_health_event_store = health_event_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_health_event_store = (
            build_health_event_store_from_env()
        )

    else:
        configured_health_event_store = (
            InMemoryHealthEventStore()
        )

    default_health_probes = None
    health_started_at = health_module.utc_now()

    if response_policy_store is not None:
        configured_response_policy_store = response_policy_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_response_policy_store = (
            build_response_policy_store_from_env()
        )

    else:
        configured_response_policy_store = (
            InMemoryResponsePolicyStore()
        )

    if action_policy_store is not None:
        configured_action_policy_store = action_policy_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_action_policy_store = build_action_policy_store_from_env()

    else:
        configured_action_policy_store = InMemoryActionPolicyStore()

    if case_workflow_store is not None:
        configured_case_workflow_store = case_workflow_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_case_workflow_store = (
            build_case_workflow_store_from_env()
        )

    else:
        configured_case_workflow_store = (
            InMemoryCaseWorkflowStore()
        )

    if alert_workflow_store is not None:
        configured_alert_workflow_store = alert_workflow_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_alert_workflow_store = build_alert_workflow_store_from_env()

    else:
        configured_alert_workflow_store = InMemoryAlertWorkflowStore()

    if settings_store is not None:
        configured_settings_store = settings_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_settings_store = build_settings_store_from_env()

    else:
        configured_settings_store = InMemorySettingsStore()

    def configuration_in_force() -> ConfigurationDocument:
        # The administrator's saved configuration, or the defaults before one is saved
        try:
            saved = configured_settings_store.get("configuration")
        except SettingsSchemaNotReady:
            saved = None

        if saved is None:
            return ConfigurationDocument()

        return ConfigurationDocument(
            **ConfigurationValues(**saved.document).model_dump(),
            version=saved.version, updated_at=saved.updated_at, updated_by=saved.updated_by,
        )

    if operator_audit_store is not None:
        configured_operator_audit_store = operator_audit_store

    elif (
        default_investigation_store is not None
        or default_audit_store is not None
    ):
        configured_operator_audit_store = (
            build_operator_audit_store_from_env()
        )

    else:
        configured_operator_audit_store = (
            InMemoryOperatorAuditStore()
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

    if containment_expiry_store is not None:
        configured_containment_expiry_store = (
            containment_expiry_store
        )

    elif (
        default_investigation_store
        is not None
        or default_audit_store
        is not None
    ):
        configured_containment_expiry_store = (
            build_containment_expiry_store_from_env()
        )

    else:
        configured_containment_expiry_store = (
            InMemoryContainmentExpiryStore()
        )

    if target_operation_coordinator is not None:
        configured_target_coordinator = target_operation_coordinator
    elif isinstance(
        configured_containment_expiry_store,
        PostgresContainmentExpiryStore,
    ):
        configured_target_coordinator = PostgresTargetOperationCoordinator(
            configured_containment_expiry_store.database_url
        )
    else:
        # In-process only. The separate automatic runner refuses SQLite.
        configured_target_coordinator = InMemoryTargetOperationCoordinator()

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

    configured_response_mode = (
        normalize_response_mode(
            response_mode
            if response_mode is not None
            else os.getenv(
                "ATHENASEC_RESPONSE_MODE",
                "SUPERVISED",
            )
        )
    )

    configured_operator_identity_store = (
        operator_identity_store if operator_identity_store is not None
        else build_operator_identity_store_from_env()
    )
    configured_browser_auth_store = (
        browser_auth_store if browser_auth_store is not None
        else build_browser_auth_store_from_env()
    )

    configured_operator_control_key = (
        operator_control_key
        if operator_control_key is not None
        else os.getenv(
            "ATHENASEC_OPERATOR_CONTROL_KEY"
        )
    )

    if runtime_control_store is not None:
        configured_runtime_control_store = (
            runtime_control_store
        )

    elif (
        default_investigation_store
        is not None
        or default_audit_store
        is not None
    ):
        configured_runtime_control_store = (
            build_runtime_control_store_from_env()
        )

    else:
        configured_runtime_control_store = (
            InMemoryRuntimeControlStore()
        )

    runtime_controls = RuntimeControlManager(
        store=(
            configured_runtime_control_store
        ),
        initial_response_mode=(
            configured_response_mode
        ),
        initial_operator_execution_enabled=True,
    )

    # The old ResponseExecutor parameter is retained for source compatibility.
    # It must never authorize a Cortex action. Only the deterministic V2
    # structured response runtime may reach the Cortex executor.

    structured_cortex_runtime = (
        cortex_config
        .build_structured_cortex_runtime_from_env()
        if (
            structured_action_executor
            is None
            or structured_action_verifier
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
        if structured_action_verifier
        is not None
        else (
            structured_cortex_runtime.verifier
            if structured_cortex_runtime
            is not None
            else None
        )
    )

    structured_runtime_configured = any(
        component is not None
        for component in (
            configured_structured_action_executor,
            configured_structured_action_verifier,
            configured_structured_rollback_executor,
        )
    )

    def current_runtime_control():
        return (
            runtime_controls.snapshot()
        )

    def effective_execution_enabled():
        control = (
            current_runtime_control()
        )

        return (
            configured_autonomous_response_enabled
            and (
                control
                .operator_execution_enabled
            )
            and (
                control.response_mode
                != "SHADOW"
            )
        )

    def structured_runtime_reachable():
        control = (
            current_runtime_control()
        )

        return (
            structured_runtime_configured
            or control.response_mode
            == "SHADOW"
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
        control = (
            current_runtime_control()
        )

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
                    and (
                        control
                        .operator_execution_enabled
                    )
                ),
                target_protection_registry=(
                    configured_target_protection_registry
                ),
                containment_expiry_store=(
                    configured_containment_expiry_store
                ),
                target_coordinator=(
                    configured_target_coordinator
                ),
                response_mode=(
                    control.response_mode
                ),
                approval_id=approval_id,
            )
        )

        if outcome.outcome == "shadowed":
            save_incident_audit_event(
                incident_id=(
                    proposed_action.incident_id
                ),
                event_type=(
                    "structured_response_shadowed"
                ),
                entity_type=(
                    "proposed_action"
                ),
                entity_id=(
                    proposed_action
                    .proposed_action_id
                ),
                message=(
                    "Structured response was "
                    "evaluated in SHADOW mode "
                    "without Cortex execution."
                ),
                details={
                    "response_mode": (
                        control.response_mode
                    ),
                    "policy_decision_id": (
                        policy_decision
                        .decision_id
                    ),
                    "policy_outcome": (
                        policy_decision.outcome
                    ),
                },
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

        try:
            result = graph.invoke(
                initial_state
            )
        except ModelUnavailable as exc:
            # The model is down: no analysis, so no response either. Say so plainly
            # (503) and leave a trace on the incident instead of a bare 500.
            if incident_id is not None:
                save_incident_audit_event(
                    incident_id=incident_id,
                    event_type="investigation_failed",
                    entity_type="alert",
                    entity_id=alert.alert_id,
                    message=(
                        "AthenaSec could not investigate this alert: "
                        "the AI model was unavailable."
                    ),
                    details={"reason": str(exc), "source": alert.source},
                )

            raise HTTPException(
                status_code=503,
                detail=(
                    f"{exc} Alert {alert.alert_id} was not investigated; "
                    "send it again once the model is running."
                ),
            ) from exc

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
                and structured_runtime_reachable()
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
                control = current_runtime_control()
                save_audit_event(
                    alert_id=investigation.alert_id,
                    event_type="legacy_response_blocked",
                    message=(
                        "Legacy response was not executed: an exact V2 "
                        "deterministic action policy decision is required."
                    ),
                    details={
                        "legacy_policy_id": investigation.policy_decision.policy_id,
                        "requested_actions": list(investigation.response_plan.actions),
                        "response_mode": control.response_mode,
                        "reason": "v2_action_policy_required",
                    },
                )
                fallback_plan = (
                    investigation
                    .response_plan
                    .model_copy(
                        update={
                            "response_allowed": False,
                            "actions": [],
                            "status": "create_case",
                            "reason": (
                                "Legacy response denied: "
                                "deterministic V2 policy, "
                                "independent verification, and "
                                "containment expiry are required."
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
                        "v2_policy_required"
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

    def build_runtime_status():
        control = (
            current_runtime_control()
        )

        effective = (
            configured_autonomous_response_enabled
            and (
                control
                .operator_execution_enabled
            )
            and (
                control.response_mode
                != "SHADOW"
            )
        )

        return {
            "response_mode": (
                control.response_mode
            ),
            "autonomous_response_enabled": (
                configured_autonomous_response_enabled
            ),
            "operator_execution_enabled": (
                control
                .operator_execution_enabled
            ),
            "effective_execution_enabled": (
                effective
            ),
            "structured_runtime_configured": (
                structured_runtime_configured
            ),
            "cortex_execution_possible": (
                structured_runtime_configured
                and effective
            ),
            "control_version": (
                control.version
            ),
        }

    def require_operator_control_key(
        provided_key,
    ):
        if not configured_operator_control_key:
            raise HTTPException(
                status_code=503,
                detail=(
                    "AthenaSec operator "
                    "controls are not configured."
                ),
            )

        if not secrets.compare_digest(
            provided_key or "",
            configured_operator_control_key,
        ):
            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid AthenaSec "
                    "operator control key."
                ),
            )

    def require_web_session(request: Request, csrf: str | None = None):
        if configured_browser_auth_store is None:
            raise HTTPException(status_code=503, detail="Browser authentication unavailable.")
        session = request.cookies.get(SESSION_COOKIE_NAME)
        principal = configured_browser_auth_store.resolve_session(session)
        if principal is None:
            raise HTTPException(status_code=401, detail="Authenticated session required.")
        # A temporary password allows only choosing a new one (and signing out)
        if getattr(principal, "must_change_password", False) and request.url.path not in PASSWORD_CHANGE_PATHS:
            raise HTTPException(status_code=403, detail="Choose a new password before continuing.")
        if csrf is not None and not secrets.compare_digest(
            csrf, principal.csrf_token
        ):
            raise HTTPException(status_code=403, detail="Invalid CSRF token.")
        return principal

    def require_approval_identity(authorization, *, allow_decision=False,
                                  request: Request | None = None, csrf: str | None = None):
        # Browser sessions use httpOnly cookies and mandatory CSRF on mutations.
        if request is not None and SESSION_COOKIE_NAME in request.cookies:
            principal = require_web_session(request)
            if allow_decision and (
                not csrf or not secrets.compare_digest(csrf, principal.csrf_token)
            ):
                raise HTTPException(status_code=403, detail="CSRF token required.")
            if allow_decision and not principal.can_decide_approvals:
                raise HTTPException(status_code=403, detail="Approver permission required.")
            if not principal.can_read_approvals:
                raise HTTPException(status_code=403, detail="Approval-read permission required.")
            return principal
        # Keep M8's individually provisioned bearer tokens for non-browser access.
        if configured_operator_identity_store is None:
            raise HTTPException(status_code=503, detail="Human identity store is unavailable.")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Human authentication required.")
        token = authorization[7:]
        if not token or token.strip() != token:
            raise HTTPException(status_code=401, detail="Invalid operator credential.")
        identity = configured_operator_identity_store.resolve(token)
        if identity is None:
            raise HTTPException(status_code=401, detail="Invalid or expired operator credential.")
        if allow_decision and not identity.can_decide_approvals:
            raise HTTPException(status_code=403, detail="Approver permission required.")
        if not identity.can_read_approvals:
            raise HTTPException(status_code=403, detail="Approval-read permission required.")
        return identity

    @app.post("/api/v1/auth/login")
    def browser_login(payload: BrowserLoginRequest, response: Response):
        if configured_browser_auth_store is None:
            raise HTTPException(status_code=503, detail="Browser authentication unavailable.")
        try:
            challenge = configured_browser_auth_store.begin_login(
                payload.email, payload.password
            )
        except InvalidCredentials as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        response.headers["Cache-Control"] = "no-store"
        return {"challenge": challenge}

    @app.post("/api/v1/auth/mfa")
    def browser_mfa(payload: BrowserMfaRequest, response: Response):
        if configured_browser_auth_store is None:
            raise HTTPException(status_code=503, detail="Browser authentication unavailable.")
        try:
            session, principal = configured_browser_auth_store.complete_mfa(
                payload.challenge, payload.code
            )
        except InvalidCredentials as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        response.set_cookie(
            SESSION_COOKIE_NAME, session, httponly=True,
            secure=os.getenv("ATHENASEC_COOKIE_SECURE", "true").strip().lower()
                   not in {"false", "0", "no"},
            samesite="strict", path="/", max_age=8 * 3600,
        )
        response.headers["Cache-Control"] = "no-store"
        return signed_in(principal)

    def signed_in(principal):
        return {
            "user": principal.public_user(),
            "csrf_token": principal.csrf_token,
            "must_change_password": bool(getattr(principal, "must_change_password", False)),
        }

    @app.get("/api/v1/auth/me")
    def browser_me(request: Request, response: Response):
        principal = require_web_session(request)
        response.headers["Cache-Control"] = "no-store"
        return signed_in(principal)

    @app.post("/api/v1/auth/logout")
    def browser_logout(request: Request, response: Response,
                       x_athenasec_csrf: str | None = Header(default=None)):
        principal = require_web_session(request)
        if not x_athenasec_csrf or not secrets.compare_digest(
            x_athenasec_csrf, principal.csrf_token
        ):
            raise HTTPException(status_code=403, detail="CSRF token required.")
        configured_browser_auth_store.revoke_session(
            request.cookies[SESSION_COOKIE_NAME]
        )
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        response.headers["Cache-Control"] = "no-store"
        return {"status": "logged_out"}

    def require_admin(request: Request):
        principal = require_web_session(request)
        if principal.role != "Administrator":
            raise HTTPException(status_code=403, detail="Administrator permission required.")
        return principal

    def user_directory(request: Request, response: Response, operation):
        require_admin(request)
        response.headers["Cache-Control"] = "no-store"
        store = configured_browser_auth_store
        if not hasattr(store, "list_users"):
            raise HTTPException(status_code=503, detail="User directory unavailable.")
        try:
            return operation(store)
        except UsersSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="User directory schema is not migrated. Run alembic upgrade head.",
            ) from exc

    @app.get("/api/v1/users", response_model=UserListResponse)
    def list_users(
        request: Request,
        response: Response,
        role: UserRole | None = None,
        active: bool | None = None,
        q: str | None = Query(default=None, max_length=200),
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
    ) -> UserListResponse:
        entries = user_directory(
            request, response,
            lambda store: store.list_users(role=role, active=active, q=q),
        )
        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda entry: entry.created_at,
                id_key=lambda entry: entry.user_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return UserListResponse(total=len(entries), items=page, next_cursor=next_cursor)

    @app.get("/api/v1/users/{user_id}", response_model=UserRecord)
    def get_user(user_id: str, request: Request, response: Response) -> UserRecord:
        user = user_directory(request, response, lambda store: store.get_user(user_id))
        if user is None:
            raise HTTPException(status_code=404, detail=f"User {user_id} was not found.")
        return user

    # ----- User administration (admin + CSRF; every change audited) -----

    def user_admin(request: Request, response: Response, csrf: str | None):
        principal = require_admin(request)

        if not csrf or not secrets.compare_digest(csrf, principal.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        response.headers["Cache-Control"] = "no-store"
        store = configured_browser_auth_store

        if not hasattr(store, "create_user"):
            raise HTTPException(status_code=503, detail="User administration unavailable.")

        return principal, store

    def user_write(operation):
        try:
            return operation()
        except UserConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except UsersSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="User directory schema is not migrated. Run alembic upgrade head.",
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    def existing_user(store, user_id):
        user = user_write(lambda: store.get_user(user_id))

        if user is None:
            raise HTTPException(status_code=404, detail=f"User {user_id} was not found.")

        return user

    def keeps_an_administrator(store, user, *, demoting=False, removing=False):
        # The last active administrator cannot be removed, suspended or demoted
        if user.role != "Administrator" or not user.active or not (demoting or removing):
            return
        admins = user_write(lambda: store.list_users(role="Administrator", active=True))
        if len(admins) <= 1:
            raise HTTPException(status_code=409, detail="AthenaSec needs at least one active administrator.")

    def record_user_event(principal, *, action, target, event_type, detail):
        record_operator_event(principal, category="user", action=action, target=target,
                              event_type=event_type, detail=detail)

    @app.post("/api/v1/users", response_model=UserCredentialsResponse, status_code=201)
    def create_user(
        payload: UserWriteRequest,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> UserCredentialsResponse:
        principal, store = user_admin(request, response, x_athenasec_csrf)
        user, password, uri = user_write(lambda: store.create_user(
            name=payload.name, email=payload.email, role=payload.role,
            department=payload.department, phone=payload.phone,
        ))
        record_user_event(principal, action="create", target=user.user_id, event_type="user_created",
                          detail={"email": user.email, "role": user.role})

        return UserCredentialsResponse(user=user, temporary_password=password, totp_uri=uri)

    @app.put("/api/v1/users/{user_id}", response_model=UserRecord)
    def update_user(
        user_id: str,
        payload: UserWriteRequest,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> UserRecord:
        principal, store = user_admin(request, response, x_athenasec_csrf)
        before = existing_user(store, user_id)

        if user_id == principal.operator_id and payload.role != before.role:
            raise HTTPException(status_code=409, detail="You cannot change your own role.")

        keeps_an_administrator(store, before, demoting=payload.role != "Administrator")
        after = user_write(lambda: store.update_user(
            user_id, name=payload.name, email=payload.email, role=payload.role,
            department=payload.department, phone=payload.phone,
        ))
        changed = {
            field: {"from": getattr(before, field), "to": getattr(after, field)}
            for field in ("name", "email", "role", "department", "phone")
            if getattr(before, field) != getattr(after, field)
        }
        if changed:
            record_user_event(principal, action="update", target=user_id, event_type="user_updated",
                              detail=changed)

        return after

    @app.post("/api/v1/users/{user_id}/status", response_model=UserRecord)
    def change_user_status(
        user_id: str,
        payload: UserStatusRequest,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> UserRecord:
        principal, store = user_admin(request, response, x_athenasec_csrf)
        before = existing_user(store, user_id)

        if user_id == principal.operator_id:
            raise HTTPException(status_code=409, detail="You cannot suspend your own account.")

        if before.active != payload.active:
            if not payload.active:
                keeps_an_administrator(store, before, removing=True)
                user_write(lambda: store.disable_user(user_id))
            else:
                user_write(lambda: store.enable_user(user_id))
            record_user_event(
                principal, action="enable" if payload.active else "disable", target=user_id,
                event_type="user_enabled" if payload.active else "user_disabled",
                detail={"active": payload.active},
            )

        return existing_user(store, user_id)

    @app.delete("/api/v1/users/{user_id}", status_code=204)
    def delete_user(
        user_id: str,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> Response:
        principal, store = user_admin(request, response, x_athenasec_csrf)
        before = existing_user(store, user_id)

        if user_id == principal.operator_id:
            raise HTTPException(status_code=409, detail="You cannot delete your own account.")

        keeps_an_administrator(store, before, removing=True)
        user_write(lambda: store.delete_user(user_id))
        record_user_event(principal, action="delete", target=user_id, event_type="user_deleted",
                          detail={"email": before.email, "role": before.role})

        return Response(status_code=204)

    @app.post("/api/v1/users/{user_id}/reset-mfa", response_model=MfaResetResponse)
    def reset_user_mfa(
        user_id: str,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> MfaResetResponse:
        # Lost phone: a new authenticator secret; the old app stops working and they are signed out
        principal, store = user_admin(request, response, x_athenasec_csrf)

        if not hasattr(store, "reset_mfa"):
            raise HTTPException(status_code=503, detail="User administration unavailable.")

        user = existing_user(store, user_id)
        uri = user_write(lambda: store.reset_mfa(user_id))
        record_user_event(principal, action="reset_mfa", target=user_id,
                          event_type="user_mfa_reset", detail={"sessions_revoked": True})

        return MfaResetResponse(user=user, totp_uri=uri)

    @app.post("/api/v1/users/{user_id}/reset-password", response_model=UserCredentialsResponse)
    def reset_user_password(
        user_id: str,
        request: Request,
        response: Response,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> UserCredentialsResponse:
        principal, store = user_admin(request, response, x_athenasec_csrf)
        user = existing_user(store, user_id)
        password = user_write(lambda: store.reset_password(user_id))
        record_user_event(principal, action="reset_password", target=user_id,
                          event_type="user_password_reset", detail={"sessions_revoked": True})

        return UserCredentialsResponse(user=user, temporary_password=password)

    def audit_view(request: Request, response: Response, operation):
        require_admin(request)
        response.headers["Cache-Control"] = "no-store"
        try:
            return operation()
        except OperatorAuditSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Operator audit schema is not migrated. Run alembic upgrade head.",
            ) from exc

    @app.get("/api/v1/audit/verify", response_model=ChainVerification)
    def verify_audit_chain(request: Request, response: Response) -> ChainVerification:
        return audit_view(request, response, configured_operator_audit_store.verify_chain)

    @app.get("/api/v1/audit", response_model=AuditListResponse)
    def list_audit(
        request: Request,
        response: Response,
        actor: str | None = None,
        category: str | None = None,
        result: AuditResult | None = None,
        event_type: str | None = None,
        incident_id: str | None = None,
        alert_id: str | None = None,
        q: str | None = Query(default=None, max_length=200),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
    ) -> AuditListResponse:
        require_admin(request)

        if since is not None:
            since = as_utc(since)
        if until is not None:
            until = as_utc(until)
        if since is not None and until is not None and since > until:
            raise HTTPException(status_code=400, detail="since must not be after until.")

        def collect():
            # Operator events carry no incident, so an incident filter excludes them.
            operator_events = (
                []
                if incident_id is not None
                else configured_operator_audit_store.list_events(
                    actor=actor, category=category, result=result,
                    event_type=event_type, since=since, until=until,
                )
            )
            incident_events = [
                incident_event_view(record)
                for record in configured_audit_store.list_incident_events(
                    incident_id=incident_id, event_type=event_type,
                    since=since, until=until,
                )
            ]
            return operator_events, incident_events

        operator_events, incident_events = audit_view(request, response, collect)

        entries = [
            event
            for event in [*operator_events, *incident_events]
            if view_matches(event, actor=actor, category=category, result=result,
                            alert_id=alert_id, q=q)
        ]
        entries.sort(key=lambda event: (as_utc(event.occurred_at), event.event_id), reverse=True)

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda event: event.occurred_at,
                id_key=lambda event: event.event_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return AuditListResponse(
            total=len(entries),
            items=page,
            next_cursor=next_cursor,
            alert_events=(
                configured_audit_store.list_by_alert_id(alert_id)
                if alert_id is not None
                else []
            ),
        )

    @app.get("/api/v1/audit/{event_id}", response_model=AuditEvent)
    def get_audit_event(event_id: str, request: Request, response: Response) -> AuditEvent:
        def find():
            event = configured_operator_audit_store.get_event(event_id)
            if event is not None:
                return event
            record = configured_audit_store.get_incident_event(event_id)
            return incident_event_view(record) if record is not None else None

        event = audit_view(request, response, find)
        if event is None:
            raise HTTPException(status_code=404, detail=f"Audit event {event_id} was not found.")
        return event

    def case_view_for(operation):
        try:
            return operation()
        except CaseWorkflowSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Case workflow schema is not migrated. Run alembic upgrade head.",
            ) from exc

    def render_case(record):
        return build_case(
            record,
            investigation_store=store,
            workflow_store=configured_case_workflow_store,
        )

    @app.get("/api/v1/cases", response_model=CaseListResponse)
    def list_cases(
        request: Request,
        status: IncidentCaseStatus | None = None,
        incident_id: str | None = None,
        assigned_analyst: str | None = None,
        alert_id: str | None = None,
        q: str | None = Query(default=None, max_length=200),
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> CaseListResponse:
        require_approval_identity(authorization, request=request)

        def collect():
            records = [
                record
                for record in configured_incident_response_store.list_all_incident_cases()
                if (status is None or record.status == status)
                and (incident_id is None or record.incident_id == incident_id)
            ]
            return [
                case
                for case in (render_case(record) for record in records)
                if case_matches(
                    case, assigned_analyst=assigned_analyst, alert_id=alert_id, q=q,
                )
            ]

        entries = case_view_for(collect)

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda entry: entry.created_at,
                id_key=lambda entry: entry.case_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return CaseListResponse(total=len(entries), items=page, next_cursor=next_cursor)

    @app.get("/api/v1/cases/{case_id}", response_model=Case)
    def get_case(
        case_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> Case:
        require_approval_identity(authorization, request=request)
        record = configured_incident_response_store.get_incident_case(case_id)

        if record is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} was not found.")

        return case_view_for(lambda: render_case(record))

    # ----- Analyst actions from the website: close, reopen, assign, tick -----

    def require_browser_change(request: Request, csrf: str | None):
        # A signed-in person on the website, with the CSRF token every change carries
        principal = require_web_session(request)

        if not csrf or not secrets.compare_digest(csrf, principal.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        if not principal.can_read_approvals:
            raise HTTPException(status_code=403, detail="Read permission required.")

        return principal

    def record_operator_event(principal, *, category, action, target, event_type, detail):
        try:
            configured_operator_audit_store.append_event(
                actor_id=principal.operator_id,
                actor_role=principal.role,
                category=category,
                action=action,
                target=target,
                result="Success",
                event_type=event_type,
                detail=detail,
            )
        except OperatorAuditSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="The change was saved but its audit event could not be recorded. Run alembic upgrade head.",
            ) from exc

    def alert_workflow_view(operation):
        try:
            return operation()
        except AlertWorkflowSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Alert workflow schema is not migrated. Run alembic upgrade head.",
            ) from exc

    def with_alert_workflow(entries):
        workflows = alert_workflow_view(configured_alert_workflow_store.list_all)

        return [
            entry.model_copy(update={
                "analyst_status": workflows[entry.alert_id].status,
                "assigned_analyst": workflows[entry.alert_id].assigned_analyst,
            }) if entry.alert_id in workflows else entry
            for entry in entries
        ]

    def change_alert(alert_id, principal, *, status=None, assign=False):
        if store.get(alert_id) is None:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} was not found.")

        current = alert_workflow_view(lambda: configured_alert_workflow_store.get(alert_id))
        before_status = current.status if current is not None else "open"
        before_analyst = current.assigned_analyst if current is not None else None
        record = AlertWorkflowRecord(
            alert_id=alert_id,
            status=status or before_status,
            assigned_analyst=principal.name if assign else before_analyst,
            updated_at=datetime.now(timezone.utc),
            updated_by=principal.operator_id,
        )
        alert_workflow_view(lambda: configured_alert_workflow_store.save(record))

        if status is not None and status != before_status:
            record_operator_event(
                principal, category="alert", action="close" if status == "closed" else "reopen",
                target=alert_id, event_type="alert_status_changed",
                detail={"from": before_status, "to": status},
            )

        if assign and before_analyst != principal.name:
            record_operator_event(
                principal, category="alert", action="assign", target=alert_id,
                event_type="alert_assigned",
                detail={"from": before_analyst, "to": principal.name},
            )

        return alert_detail(alert_id)

    @app.post("/api/v1/alerts/{alert_id}/status", response_model=AlertDetail)
    def change_alert_status(
        alert_id: str,
        payload: StatusChangeRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> AlertDetail:
        principal = require_browser_change(request, x_athenasec_csrf)

        return change_alert(alert_id, principal, status=payload.status)

    @app.post("/api/v1/alerts/{alert_id}/assign", response_model=AlertDetail)
    def assign_alert(
        alert_id: str,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> AlertDetail:
        # Assigns the alert to the person signed in ("Assign to me")
        principal = require_browser_change(request, x_athenasec_csrf)

        return change_alert(alert_id, principal, assign=True)

    def case_or_404(case_id):
        record = configured_incident_response_store.get_incident_case(case_id)

        if record is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} was not found.")

        return record

    def save_case_workflow(case_id, *, now, **changes):
        current = configured_case_workflow_store.get_workflow(case_id)
        base = current.model_dump() if current is not None else {
            "case_id": case_id, "assigned_analyst": None, "summary": None,
            "closed_at": None, "version": 0,
        }
        base.update(changes, updated_at=now, version=base["version"] + 1)
        configured_case_workflow_store.save_workflow(CaseWorkflowRecord(**base))

    def add_case_note(case_id, *, now, title, description, author):
        notes = configured_case_workflow_store.list_notes(case_id)
        configured_case_workflow_store.append_note(CaseNoteRecord(
            case_id=case_id, seq=len(notes) + 1, occurred_at=now,
            title=title, description=description, author=author,
        ))

    @app.post("/api/v1/cases/{case_id}/status", response_model=Case)
    def change_case_status(
        case_id: str,
        payload: StatusChangeRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> Case:
        principal = require_browser_change(request, x_athenasec_csrf)
        record = case_or_404(case_id)
        before = "closed" if record.status in ("closed", "resolved") else "open"

        if payload.status == before:
            return case_view_for(lambda: render_case(record))

        now = datetime.now(timezone.utc)
        updated = record.model_copy(update={"status": payload.status, "updated_at": now})

        def apply():
            configured_incident_response_store.save_incident_case(updated)
            save_case_workflow(
                case_id, now=now, closed_at=now if payload.status == "closed" else None
            )
            add_case_note(
                case_id, now=now,
                title="Case closed" if payload.status == "closed" else "Case reopened",
                description=f"{'Closed' if payload.status == 'closed' else 'Reopened'} by {principal.name}.",
                author=principal.name,
            )

        case_view_for(apply)
        record_operator_event(
            principal, category="case", action="close" if payload.status == "closed" else "reopen",
            target=case_id, event_type="case_status_changed",
            detail={"from": record.status, "to": payload.status},
        )

        return case_view_for(lambda: render_case(updated))

    @app.post("/api/v1/cases/{case_id}/assign", response_model=Case)
    def assign_case(
        case_id: str,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> Case:
        principal = require_browser_change(request, x_athenasec_csrf)
        record = case_or_404(case_id)
        current = case_view_for(lambda: configured_case_workflow_store.get_workflow(case_id))
        before = current.assigned_analyst if current is not None else None

        if before != principal.name:
            now = datetime.now(timezone.utc)

            def apply():
                save_case_workflow(case_id, now=now, assigned_analyst=principal.name)
                add_case_note(case_id, now=now, title="Case assigned",
                              description=f"Assigned to {principal.name}.", author=principal.name)

            case_view_for(apply)
            record_operator_event(
                principal, category="case", action="assign", target=case_id,
                event_type="case_assigned", detail={"from": before, "to": principal.name},
            )

        return case_view_for(lambda: render_case(record))

    @app.put("/api/v1/cases/{case_id}/actions/{position}", response_model=Case)
    def update_case_action(
        case_id: str,
        payload: CaseActionUpdateRequest,
        request: Request,
        position: int = Path(ge=0),
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> Case:
        # Ticks or unticks one recommended action. Actions waiting on an approval
        # follow that approval and cannot be ticked by hand.
        principal = require_browser_change(request, x_athenasec_csrf)
        record = case_or_404(case_id)
        actions = case_view_for(lambda: render_case(record)).recommended_actions
        action = next((item for item in actions if item.position == position), None)

        if action is None:
            raise HTTPException(status_code=404, detail=f"Case {case_id} has no action {position}.")

        if action.approval_id:
            raise HTTPException(
                status_code=409,
                detail="This action follows its approval and cannot be ticked by hand.",
            )

        if action.done != payload.done:
            stored = [
                CaseActionRecord(
                    case_id=case_id, position=item.position, label=item.label,
                    proposed_action_id=item.proposed_action_id, approval_id=item.approval_id,
                    done=payload.done if item.position == position else item.done,
                )
                for item in actions
            ]
            case_view_for(lambda: configured_case_workflow_store.replace_actions(case_id, stored))
            record_operator_event(
                principal, category="case", action="update", target=case_id,
                event_type="case_action_updated",
                detail={"position": position, "label": action.label, "done": payload.done},
            )

        return case_view_for(lambda: render_case(record))

    # ----- Configuration (admin) and the signed-in person's settings and profile -----

    def settings_view(operation):
        try:
            return operation()
        except SettingsSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Settings schema is not migrated. Run alembic upgrade head.",
            ) from exc

    def require_self(request: Request, csrf: str | None):
        principal = require_web_session(request)

        if not csrf or not secrets.compare_digest(csrf, principal.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        return principal

    @app.get("/api/v1/configuration", response_model=ConfigurationDocument)
    def get_configuration(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> ConfigurationDocument:
        require_approval_identity(authorization, request=request)

        return configuration_in_force()

    @app.put("/api/v1/configuration", response_model=ConfigurationDocument)
    def update_configuration(
        payload: ConfigurationUpdateRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> ConfigurationDocument:
        principal = require_admin(request)

        if not x_athenasec_csrf or not secrets.compare_digest(x_athenasec_csrf, principal.csrf_token):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        before = configuration_in_force()
        values = ConfigurationValues(**payload.model_dump(exclude={"base_version"}))

        try:
            settings_view(lambda: configured_settings_store.put(
                "configuration", values.model_dump(), base_version=payload.base_version,
                updated_by=principal.operator_id,
            ))
        except SettingsVersionConflict as exc:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Someone else saved the configuration first (version {exc.current_version}). "
                    "Reload to see it, then make your change again."
                ),
            ) from exc

        changed = {
            field: {"from": getattr(before, field), "to": getattr(values, field)}
            for field in ConfigurationValues.model_fields
            if getattr(before, field) != getattr(values, field)
        }
        if changed:
            record_operator_event(principal, category="configuration", action="update",
                                  target="configuration", event_type="configuration_updated",
                                  detail=changed)

        return configuration_in_force()

    @app.get("/api/v1/me/settings", response_model=UserSettings)
    def get_my_settings(request: Request) -> UserSettings:
        principal = require_web_session(request)
        saved = settings_view(lambda: configured_settings_store.get(f"user-settings:{principal.operator_id}"))

        return UserSettings(**saved.document) if saved is not None else UserSettings()

    @app.put("/api/v1/me/settings", response_model=UserSettings)
    def update_my_settings(
        payload: UserSettings,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> UserSettings:
        principal = require_self(request, x_athenasec_csrf)
        settings_view(lambda: configured_settings_store.put(
            f"user-settings:{principal.operator_id}", payload.model_dump(),
            base_version=None, updated_by=principal.operator_id,
        ))

        return payload

    def my_profile(principal) -> ProfileDocument:
        user = user_write(lambda: configured_browser_auth_store.get_user(principal.operator_id)) \
            if hasattr(configured_browser_auth_store, "get_user") else None
        extra = settings_view(lambda: configured_settings_store.get(f"user-profile:{principal.operator_id}"))
        timezone_name = (extra.document.get("timezone") if extra is not None else None) or "Asia/Dubai"

        if user is None:
            return ProfileDocument(user_id=principal.operator_id, role=principal.role,
                                   display_name=principal.name, email=principal.email,
                                   timezone=timezone_name)

        return ProfileDocument(user_id=user.user_id, role=user.role, display_name=user.name,
                               email=user.email, department=user.department, phone=user.phone,
                               timezone=timezone_name)

    @app.get("/api/v1/me/profile", response_model=ProfileDocument)
    def get_my_profile(request: Request) -> ProfileDocument:
        return my_profile(require_web_session(request))

    @app.put("/api/v1/me/profile", response_model=ProfileDocument)
    def update_my_profile(
        payload: ProfileUpdateRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> ProfileDocument:
        principal = require_self(request, x_athenasec_csrf)
        store = configured_browser_auth_store

        if not hasattr(store, "update_user"):
            raise HTTPException(status_code=503, detail="User administration unavailable.")

        before = my_profile(principal)
        user_write(lambda: store.update_user(
            principal.operator_id, name=payload.display_name, email=payload.email,
            role=principal.role, department=payload.department, phone=payload.phone,
        ))
        settings_view(lambda: configured_settings_store.put(
            f"user-profile:{principal.operator_id}", {"timezone": payload.timezone},
            base_version=None, updated_by=principal.operator_id,
        ))
        after = my_profile(principal)
        changed = {
            field: {"from": getattr(before, field), "to": getattr(after, field)}
            for field in ("display_name", "email", "department", "phone", "timezone")
            if getattr(before, field) != getattr(after, field)
        }
        if changed:
            record_operator_event(principal, category="user", action="update",
                                  target=principal.operator_id, event_type="profile_updated",
                                  detail=changed)

        return after

    @app.get("/api/v1/me/activity", response_model=AccountActivityResponse)
    def my_activity(request: Request, response: Response) -> AccountActivityResponse:
        # The signed-in person's own sign-in history (Profile page)
        principal = require_web_session(request)
        response.headers["Cache-Control"] = "no-store"
        store = configured_browser_auth_store

        if not hasattr(store, "list_auth_events"):
            return AccountActivityResponse(items=[])

        return AccountActivityResponse(items=[
            AccountActivityEntry(event_type=event_type, recorded_at=recorded_at)
            for event_type, recorded_at in store.list_auth_events(principal.operator_id, limit=10)
        ])

    @app.post("/api/v1/me/password", status_code=204)
    def change_my_password(
        payload: PasswordChangeRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> Response:
        principal = require_self(request, x_athenasec_csrf)
        store = configured_browser_auth_store

        if not hasattr(store, "change_password"):
            raise HTTPException(status_code=503, detail="User administration unavailable.")

        def change():
            try:
                store.change_password(principal.operator_id, payload.current_password, payload.new_password)
            except InvalidCredentials as exc:
                # A wrong current password, not a malformed request
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        user_write(change)

        record_operator_event(principal, category="user", action="change_password",
                              target=principal.operator_id, event_type="password_changed",
                              detail={})

        return Response(status_code=204)

    # ----- Executed responses (Incident Response page) -----

    def build_response_runs() -> list[ResponseRun]:
        responses = configured_incident_response_store
        latest = {}

        for kind, records, when in (
            ("result", responses.list_action_results(), "recorded_at"),
            ("verification", responses.list_action_verifications(), "verified_at"),
            ("rollback", responses.list_action_rollbacks(), "recorded_at"),
        ):
            for record in records:  # newest first, so the first one seen wins
                latest.setdefault((kind, record.response_action_id), ResponseStep(
                    status=record.status, message=record.message, at=getattr(record, when),
                ))

        runs = []
        roles = {}

        def approver(user_id):
            # (role, name): Administrators approve as SOC lead, Analysts as SOC analyst
            if user_id not in roles:
                user = None
                if hasattr(configured_browser_auth_store, "get_user"):
                    try:
                        user = configured_browser_auth_store.get_user(user_id)
                    except UsersSchemaNotReady:
                        user = None
                roles[user_id] = (None, None) if user is None else (
                    "soc_lead" if user.role == "Administrator" else "soc_analyst", user.name
                )
            return roles[user_id]

        for action in responses.list_response_actions():
            proposed = responses.get_proposed_action(action.proposed_action_id)
            approval = responses.get_approval_request(action.approval_id) if action.approval_id else None
            investigation = (
                store.get_incident_investigation(proposed.investigation_id) if proposed is not None else None
            )
            minutes = proposed.parameters.get("duration_minutes") if proposed is not None else None
            minutes = minutes if isinstance(minutes, int) else None
            started = approval.decided_at if approval is not None and approval.decided_at else action.created_at

            runs.append(ResponseRun(
                response_action_id=action.response_action_id,
                incident_id=action.incident_id,
                alert_id=investigation.primary_alert_id if investigation is not None else None,
                proposed_action_id=action.proposed_action_id,
                approval_id=action.approval_id,
                policy_decision_id=approval.policy_decision_id if approval is not None else None,
                action_type=proposed.action_type if proposed is not None else None,
                target=proposed.target if proposed is not None else None,
                duration_minutes=minutes,
                reason=proposed.reason if proposed is not None else None,
                status=action.status,
                executor=action.executor,
                created_at=action.created_at,
                approved_by=approval.decided_by if approval is not None else None,
                approver_role=approver(approval.decided_by)[0] if approval is not None and approval.decided_by else None,
                approver_name=approver(approval.decided_by)[1] if approval is not None and approval.decided_by else None,
                approved_at=approval.decided_at if approval is not None else None,
                result=latest.get(("result", action.response_action_id)),
                verification=latest.get(("verification", action.response_action_id)),
                rollback=latest.get(("rollback", action.response_action_id)),
                expires_at=started + timedelta(minutes=minutes) if minutes else None,
            ))

        return runs

    @app.get("/api/v1/responses", response_model=ResponseRunListResponse)
    def list_responses(
        request: Request,
        incident_id: str | None = None,
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> ResponseRunListResponse:
        require_approval_identity(authorization, request=request)
        runs = [run for run in build_response_runs() if incident_id is None or run.incident_id == incident_id]

        try:
            page, next_cursor = paginate(
                runs,
                sort_key=lambda run: run.created_at,
                id_key=lambda run: run.response_action_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return ResponseRunListResponse(total=len(runs), items=page, next_cursor=next_cursor)

    @app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
    def dashboard_summary(
        request: Request,
        window: DashboardWindow = "24h",
        role: UserRole | None = None,
        authorization: str | None = Header(default=None),
    ) -> DashboardSummary:
        principal = require_approval_identity(authorization, request=request)
        caller_role = getattr(principal, "role", None)
        view = role or caller_role or "Analyst"

        # The role picks a view; it must not widen what the caller may see.
        if view == "Administrator" and caller_role != "Administrator":
            raise HTTPException(
                status_code=403,
                detail="Administrator permission required for the administrator summary.",
            )

        try:
            return build_dashboard_summary(
                window=window,
                role=view,
                caller_id=principal.operator_id,
                now=dashboard_module.utc_now(),
                investigation_store=store,
                response_store=configured_incident_response_store,
                workflow_store=configured_case_workflow_store,
                runtime_status=build_runtime_status,
            )
        except CaseWorkflowSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Case workflow schema is not migrated. Run alembic upgrade head.",
            ) from exc

    def policy_view(operation):
        try:
            return operation()
        except PolicySchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Response policy schema is not migrated. Run alembic upgrade head.",
            ) from exc

    def current_policy_document():
        return build_policy_document(
            policy_view(configured_response_policy_store.get_current),
            protected_targets=read_protected_targets(
                configured_target_protection_registry
            ),
        )

    @app.get("/api/v1/policies", response_model=PolicyDocument)
    def get_policies(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> PolicyDocument:
        require_approval_identity(authorization, request=request)

        return current_policy_document()

    @app.get("/api/v1/policies/versions", response_model=PolicyVersionListResponse)
    def list_policy_versions(
        request: Request,
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> PolicyVersionListResponse:
        require_approval_identity(authorization, request=request)
        records = policy_view(configured_response_policy_store.list_versions)

        try:
            page, next_cursor = paginate(
                records,
                sort_key=lambda record: record.created_at,
                id_key=lambda record: f"{record.version:010d}",
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return PolicyVersionListResponse(
            total=len(records),
            items=[
                PolicyVersionSummary(
                    version=r.version,
                    created_at=r.created_at,
                    created_by=r.created_by,
                    reason=r.reason,
                    whitelist_count=len(r.whitelist),
                    blacklist_count=len(r.blacklist),
                )
                for r in page
            ],
            next_cursor=next_cursor,
        )

    @app.get("/api/v1/policies/versions/{version}", response_model=PolicyDocument)
    def get_policy_version(
        request: Request,
        version: int = Path(ge=1),
        authorization: str | None = Header(default=None),
    ) -> PolicyDocument:
        require_approval_identity(authorization, request=request)
        record = policy_view(lambda: configured_response_policy_store.get_version(version))

        if record is None:
            raise HTTPException(status_code=404, detail=f"Policy version {version} was not found.")

        return build_policy_document(
            record,
            protected_targets=read_protected_targets(configured_target_protection_registry),
        )

    @app.put("/api/v1/policies", response_model=PolicyDocument)
    def update_policies(
        payload: PolicyUpdateRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> PolicyDocument:
        principal = require_admin(request)

        if not x_athenasec_csrf or not secrets.compare_digest(
            x_athenasec_csrf, principal.csrf_token
        ):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        try:
            record = policy_view(
                lambda: configured_response_policy_store.append_version(
                    base_version=payload.base_version,
                    whitelist=payload.whitelist,
                    blacklist=payload.blacklist,
                    reason=payload.reason,
                    created_by=principal.operator_id,
                )
            )
        except PolicyVersionConflict as exc:
            record_policy_audit(
                principal, result="Failed", target="policy",
                detail={
                    "base_version": payload.base_version,
                    "current_version": exc.current_version,
                    "error": "stale_version",
                },
            )
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Policy version is stale: the latest version is "
                    f"{exc.current_version}, base_version was {payload.base_version}."
                ),
            ) from exc

        record_policy_audit(
            principal, result="Success", target=f"policy-v{record.version}",
            detail={
                "base_version": payload.base_version,
                "version": record.version,
                "whitelist_count": len(record.whitelist),
                "blacklist_count": len(record.blacklist),
                "reason": record.reason,
                "enforced": False,
            },
        )

        return build_policy_document(
            record,
            protected_targets=read_protected_targets(configured_target_protection_registry),
        )

    def action_policy_view(read):
        try:
            return read()
        except ActionPolicySchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Action policy schema is not migrated. Run alembic upgrade head.",
            ) from exc

    @app.get("/api/v1/policies/actions", response_model=ActionPolicyDocument)
    def get_action_policy(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> ActionPolicyDocument:
        # The whitelist and blacklist the agent enforces right now
        require_approval_identity(authorization, request=request)

        return action_policy_view(lambda: current_or_default(configured_action_policy_store))

    @app.get(
        "/api/v1/policies/actions/versions",
        response_model=ActionPolicyVersionListResponse,
    )
    def list_action_policy_versions(
        request: Request,
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
    ) -> ActionPolicyVersionListResponse:
        require_admin(request)
        records = action_policy_view(configured_action_policy_store.list_versions)

        try:
            page, next_cursor = paginate(
                records,
                sort_key=lambda record: record.created_at,
                id_key=lambda record: f"{record.version:010d}",
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return ActionPolicyVersionListResponse(
            total=len(records), items=page, next_cursor=next_cursor
        )

    @app.put("/api/v1/policies/actions", response_model=ActionPolicyDocument)
    def update_action_policy(
        payload: ActionPolicyUpdateRequest,
        request: Request,
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> ActionPolicyDocument:
        principal = require_admin(request)

        if not x_athenasec_csrf or not secrets.compare_digest(
            x_athenasec_csrf, principal.csrf_token
        ):
            raise HTTPException(status_code=403, detail="CSRF token required.")

        content = ActionPolicyContent(
            whitelist=payload.whitelist,
            blacklist=payload.blacklist,
            never_block=payload.never_block,
            never_isolate=payload.never_isolate,
        )
        problems = validate_action_policy(content)

        if problems:
            record_policy_audit(
                principal, result="Failed", target="action-policy",
                event_type="action_policy_updated",
                detail={"base_version": payload.base_version, "error": "invalid", "problems": problems},
            )
            raise HTTPException(status_code=422, detail=problems)

        try:
            record = action_policy_view(
                lambda: configured_action_policy_store.append_version(
                    base_version=payload.base_version,
                    content=content,
                    reason=payload.reason,
                    created_by=principal.operator_id,
                )
            )
        except ActionPolicyVersionConflict as exc:
            record_policy_audit(
                principal, result="Failed", target="action-policy",
                event_type="action_policy_updated",
                detail={
                    "base_version": payload.base_version,
                    "current_version": exc.current_version,
                    "error": "stale_version",
                },
            )
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Action policy version is stale: the latest version is "
                    f"{exc.current_version}, base_version was {payload.base_version}."
                ),
            ) from exc

        record_policy_audit(
            principal, result="Success", target=f"action-policy-v{record.version}",
            event_type="action_policy_updated",
            detail={
                "base_version": payload.base_version,
                "version": record.version,
                "whitelist": [entry.action for entry in record.whitelist],
                "blacklist": [entry.action for entry in record.blacklist],
                "never_block_count": len(record.never_block),
                "never_isolate_count": len(record.never_isolate),
                "reason": record.reason,
                "enforced": True,
            },
        )

        return record

    def record_policy_audit(principal, *, result, target, detail, event_type="policy_updated"):
        try:
            configured_operator_audit_store.append_event(
                actor_id=principal.operator_id,
                actor_role=principal.role,
                category="policy",
                action="update",
                target=target,
                result=result,
                event_type=event_type,
                detail=detail,
            )
        except OperatorAuditSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail=(
                    "The policy change was stored but its audit event could not be "
                    "recorded: operator audit schema is not migrated. "
                    "Run alembic upgrade head."
                ),
            ) from exc

    def health_probes_in_use():
        nonlocal default_health_probes

        if health_probes is not None:
            return health_probes

        if default_health_probes is None:
            default_health_probes = default_probes()

        return default_health_probes

    @app.get("/api/v1/system/health", response_model=SystemHealth)
    def system_health(
        request: Request,
        response: Response,
        authorization: str | None = Header(default=None),
    ) -> SystemHealth:
        require_approval_identity(authorization, request=request)
        response.headers["Cache-Control"] = "no-store"

        return build_system_health(
            probes=health_probes_in_use(),
            event_store=configured_health_event_store,
            now=health_module.utc_now(),
            started_at=health_started_at,
            version=app.version,
            response_mode=build_runtime_status()["response_mode"],
            persistence_backend=os.getenv(
                "ATHENASEC_PERSISTENCE_BACKEND", "postgres"
            ).strip().lower(),
            evidence_provider=os.getenv(
                "ATHENASEC_EVIDENCE_PROVIDER", "mock"
            ).strip().lower(),
        )

    @app.get("/api/v1/system/events", response_model=HealthEventListResponse)
    def system_health_events(
        request: Request,
        severity: HealthSeverity | None = None,
        source: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> HealthEventListResponse:
        require_approval_identity(authorization, request=request)

        if since is not None:
            since = as_utc(since)
        if until is not None:
            until = as_utc(until)
        if since is not None and until is not None and since > until:
            raise HTTPException(status_code=400, detail="since must not be after until.")

        try:
            entries = configured_health_event_store.list_events(
                severity=severity, source=source, since=since, until=until,
            )
        except HealthSchemaNotReady as exc:
            raise HTTPException(
                status_code=503,
                detail="Health event schema is not migrated. Run alembic upgrade head.",
            ) from exc

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda event: event.occurred_at,
                id_key=lambda event: f"{event.event_id:020d}",
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return HealthEventListResponse(total=len(entries), items=page, next_cursor=next_cursor)

    @app.get(
        "/api/v1/runtime/status"
    )
    def runtime_status():
        return build_runtime_status()

    @app.put(
        "/api/v1/runtime/control"
    )
    def update_runtime_control(
        request: RuntimeControlUpdateRequest,
        x_athenasec_operator_key: (
            str | None
        ) = Header(
            default=None
        ),
    ):
        require_operator_control_key(
            x_athenasec_operator_key
        )

        try:
            runtime_controls.update(
                response_mode=(
                    request.response_mode
                ),
                operator_execution_enabled=(
                    request
                    .operator_execution_enabled
                ),
                changed_by=(
                    request.changed_by
                ),
                reason=request.reason,
            )

        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

        return build_runtime_status()

    @app.get(
        "/api/v1/runtime/control/history"
    )
    def runtime_control_history(
        x_athenasec_operator_key: (
            str | None
        ) = Header(
            default=None
        ),
    ):
        require_operator_control_key(
            x_athenasec_operator_key
        )

        return (
            configured_runtime_control_store
            .list_changes()
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
        request: Request,
        authorization: str | None = Header(default=None),
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> InvestigationResponse:
        # Submitting an alert starts an investigation that can propose containment,
        # so it needs a signed-in person: a browser session (with the CSRF token,
        # as for every change) or an operator bearer token for scripts. Wazuh
        # uses its own route and ingest key.
        if SESSION_COOKIE_NAME in request.cookies:
            principal = require_web_session(request)

            if not x_athenasec_csrf or not secrets.compare_digest(
                x_athenasec_csrf, principal.csrf_token
            ):
                raise HTTPException(status_code=403, detail="CSRF token required.")

            if not principal.can_read_approvals:
                raise HTTPException(status_code=403, detail="Read permission required.")
        else:
            require_approval_identity(authorization)

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

        # Known Wazuh housekeeping events (manager startup) are recorded without ML or the
        # agent, and never lead to a response (Daniel, semi-main)
        operational_reason = operational_event_reason(alert)

        if operational_reason is not None:
            investigation = build_operational_event_investigation(
                alert=alert,
                reason=operational_reason,
            )
            store.save(investigation)
            save_audit_event(
                alert_id=alert.alert_id,
                event_type="investigation_created",
                message="Wazuh operational event handled without ML.",
                details={
                    "operational_reason": operational_reason,
                    "rule_id": alert.metadata.get("rule_id"),
                    "decision_source": "deterministic",
                    "ml_inference_skipped": True,
                    "response_allowed": False,
                },
            )
            return investigation

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
                # The administrator's correlation window (Configuration page)
                window=timedelta(minutes=configuration_in_force().correlation_window_minutes),
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
        "/api/v1/alerts",
        response_model=AlertListResponse,
    )
    def list_alerts(
        request: Request,
        status: str | None = None,
        classification: AttackClassification | None = None,
        since: datetime | None = None,
        limit: int = Query(
            default=DEFAULT_LIST_LIMIT,
            ge=1,
            le=MAX_LIST_LIMIT,
        ),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> AlertListResponse:
        require_approval_identity(authorization, request=request)

        entries = store.list_alerts(
            status=status,
            classification=classification,
            since=since,
        )

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda entry: entry.observed_at,
                id_key=lambda entry: entry.alert_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        return AlertListResponse(
            total=len(entries),
            items=with_alert_workflow(page),
            next_cursor=next_cursor,
        )

    @app.get(
        "/api/v1/alerts/{alert_id}",
        response_model=AlertDetail,
    )
    def get_alert(
        alert_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> AlertDetail:
        require_approval_identity(authorization, request=request)

        return alert_detail(alert_id)

    def alert_detail(alert_id: str) -> AlertDetail:
        investigation = store.get(alert_id)

        if investigation is None:
            raise HTTPException(
                status_code=404,
                detail=f"Alert {alert_id} was not found.",
            )

        alert_record = store.get_incident_alert(alert_id)

        entry = with_alert_workflow(build_alert_list(
            [
                (
                    investigation,
                    (
                        None
                        if alert_record is None
                        else alert_record.observed_at
                    ),
                )
            ]
        ))[0]

        return AlertDetail(
            **entry.model_dump(),
            normalized_event=investigation.normalized_event,
            event_text=(
                None
                if alert_record is None
                else alert_record.event_text
            ),
            ml_error=investigation.ml_error,
            misp_enrichment=investigation.misp_enrichment,
            misp_error=investigation.misp_error,
        )

    @app.get(
        "/api/v1/investigations",
        response_model=InvestigationListResponse,
    )
    def list_investigations(
        request: Request,
        status: str | None = None,
        incident_id: str | None = None,
        limit: int = Query(
            default=DEFAULT_LIST_LIMIT,
            ge=1,
            le=MAX_LIST_LIMIT,
        ),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> InvestigationListResponse:
        require_approval_identity(authorization, request=request)

        entries = store.list_investigations(
            status=status,
            incident_id=incident_id,
        )

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda entry: entry.started_at,
                id_key=lambda entry: entry.investigation_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        return InvestigationListResponse(
            total=len(entries),
            items=page,
            next_cursor=next_cursor,
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
            record = store.get_incident_investigation(
                alert_id
            )

            if record is not None:
                investigation = store.get(
                    record.primary_alert_id
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
        "/api/v1/approvals",
        response_model=ApprovalListResponse,
    )
    def list_approvals(
        request: Request,
        status: str | None = None,
        incident_id: str | None = None,
        limit: int = Query(
            default=DEFAULT_LIST_LIMIT,
            ge=1,
            le=MAX_LIST_LIMIT,
        ),
        cursor: str | None = None,
        authorization: str | None = Header(default=None),
    ) -> ApprovalListResponse:
        require_approval_identity(authorization, request=request)

        entries = [
            approval
            for approval in (
                configured_incident_response_store
                .list_approval_requests(status=status)
            )
            if incident_id is None or approval.incident_id == incident_id
        ]

        try:
            page, next_cursor = paginate(
                entries,
                sort_key=lambda entry: entry.requested_at,
                id_key=lambda entry: entry.approval_id,
                limit=limit,
                cursor=cursor,
            )
        except InvalidCursor as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        return ApprovalListResponse(
            total=len(entries),
            items=page,
            next_cursor=next_cursor,
        )

    @app.get(
        "/api/v1/approvals/{approval_id}",
        response_model=(
            ApprovalRequestRecord
        ),
    )
    def get_approval_request(
        approval_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> ApprovalRequestRecord:
        require_approval_identity(authorization, request=request)
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

    @app.get(
        "/api/v1/approvals/{approval_id}/action",
        response_model=ApprovalActionDetail,
    )
    def get_approval_action(approval_id: str, request: Request,
                            authorization: str | None = Header(default=None)):
        # The approval record holds only ids; approvers need the action itself.
        require_approval_identity(authorization, request=request)
        store = configured_incident_response_store
        approval = store.get_approval_request(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval request was not found.")
        return ApprovalActionDetail(
            approval=approval,
            proposed_action=store.get_proposed_action(approval.proposed_action_id),
            policy_decision=store.get_policy_decision(approval.policy_decision_id),
        )

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
        http_request: Request,
        authorization: str | None = Header(default=None),
        x_athenasec_csrf: str | None = Header(default=None),
    ) -> ApprovalRequestRecord:
        principal = require_approval_identity(
            authorization, allow_decision=True,
            request=http_request, csrf=x_athenasec_csrf,
        )
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
                        principal.operator_id
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
            and structured_runtime_reachable()
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
