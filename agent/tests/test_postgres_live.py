import os
from uuid import uuid4

import pytest

from app.schemas import (
    AlertAnalysis,
    AuditRecord,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    CaseRecord,
    ResponseExecutionResult,
)
from app.services.audit_store import (
    PostgresAuditStore,
)
from app.services.investigation_store import (
    PostgresInvestigationStore,
)
from app.services.persistence_config import (
    build_persistence_stores_from_env,
)


def get_database_url():
    database_url = os.getenv(
        "ATHENASEC_TEST_DATABASE_URL"
    )

    if not database_url:
        pytest.skip(
            "ATHENASEC_TEST_DATABASE_URL "
            "is not configured."
        )

    return database_url


def test_postgres_stores_persist_real_records():
    database_url = get_database_url()

    investigation_store = (
        PostgresInvestigationStore(
            database_url
        )
    )

    audit_store = PostgresAuditStore(
        database_url
    )

    unique_id = uuid4().hex

    alert_id = (
        f"ALT-POSTGRES-{unique_id}"
    )

    audit_id = (
        f"AUD-POSTGRES-{unique_id}"
    )

    investigation = InvestigationResponse(
        alert_id=alert_id,
        source="integration-test",
        status="complete",
        normalized_event=(
            "SSH failures detected."
        ),
        analysis=AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "SSH brute force detected."
            ),
            evidence_refs=[
                "E001",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        ),
        evidence_records=[
            EvidenceRecord(
                evidence_id="E001",
                source="alert",
                content=(
                    "SSH failures detected."
                ),
            ),
        ],
        risk_assessment=RiskAssessment(
            score=75,
            band="high",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id="POL-BF-HIGH",
            policy_name=(
                "High-Risk Brute Force"
            ),
            matched=True,
            response_allowed=False,
            actions=[],
            reason=(
                "Automatic containment "
                "is not permitted."
            ),
        ),
        response_plan=ResponsePlan(
            policy_id="POL-BF-HIGH",
            actions=[],
            response_allowed=False,
            status="create_case",
            reason=(
                "Automatic containment "
                "is not permitted."
            ),
        ),
        investigation_iteration=1,
    )

    investigation_store.save(
        investigation
    )

    loaded_investigation = (
        investigation_store.get(
            alert_id
        )
    )

    assert loaded_investigation is not None
    assert (
        loaded_investigation.alert_id
        == alert_id
    )

    execution_plan = (
        investigation.response_plan.model_copy(
            update={
                "response_allowed": True,
                "status": "ready_for_execution",
                "actions": [
                    "block_ip",
                ],
            }
        )
    )

    investigation_store.update_response_plan(
        alert_id,
        execution_plan,
    )

    updated_investigation = (
        investigation_store.get(
            alert_id
        )
    )

    assert updated_investigation is not None
    assert (
        updated_investigation.response_plan.status
        == "ready_for_execution"
    )
    assert (
        updated_investigation.response_plan.actions
        == ["block_ip"]
    )

    execution_result = (
        ResponseExecutionResult(
            policy_id="POL-BF-HIGH",
            executor="cortex",
            status="completed",
            action_results=[],
        )
    )

    investigation_store.update_execution_result(
        alert_id,
        execution_result,
    )

    executed_investigation = (
        investigation_store.get(
            alert_id
        )
    )

    assert executed_investigation is not None
    assert (
        executed_investigation.execution_result
        is not None
    )
    assert (
        executed_investigation.execution_result.status
        == "completed"
    )

    case_id = (
        f"CASE-POSTGRES-{unique_id}"
    )

    case = CaseRecord(
        case_id=case_id,
        alert_id=alert_id,
        policy_id="POL-BF-HIGH",
        classification="brute_force",
        risk_score=75,
        risk_band="high",
        status="open",
        reason=(
            "PostgreSQL case persistence "
            "integration test."
        ),
    )

    investigation_store.save_case(
        case
    )

    loaded_case = (
        investigation_store.get_case(
            case_id
        )
    )

    assert loaded_case is not None
    assert loaded_case.case_id == case_id

    alert_case = (
        investigation_store.get_case_by_alert_id(
            alert_id
        )
    )

    assert alert_case is not None
    assert alert_case.case_id == case_id

    audit_record = AuditRecord(
        audit_id=audit_id,
        alert_id=alert_id,
        event_type=(
            "investigation_created"
        ),
        message=(
            "Real PostgreSQL persistence "
            "was verified."
        ),
        details={
            "database": "postgresql",
        },
    )

    audit_store.save(
        audit_record
    )

    loaded_audit = audit_store.get(
        audit_id
    )

    assert loaded_audit is not None
    assert loaded_audit.audit_id == audit_id

    alert_audits = (
        audit_store.list_by_alert_id(
            alert_id
        )
    )

    assert len(alert_audits) == 1
    assert (
        alert_audits[0].event_type
        == "investigation_created"
    )

def test_production_persistence_builder_uses_real_postgres(
    monkeypatch,
):
    database_url = get_database_url()

    monkeypatch.delenv(
        "ATHENASEC_PERSISTENCE_BACKEND",
        raising=False,
    )

    monkeypatch.setenv(
        "ATHENASEC_DATABASE_URL",
        database_url,
    )

    (
        investigation_store,
        audit_store,
    ) = build_persistence_stores_from_env()

    assert isinstance(
        investigation_store,
        PostgresInvestigationStore,
    )

    assert isinstance(
        audit_store,
        PostgresAuditStore,
    )