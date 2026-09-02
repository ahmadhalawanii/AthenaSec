import pytest

from app.schemas import (
    AlertAnalysis,
    ResponseExecutionResult,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
)

from app.services.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
)


def make_investigation() -> InvestigationResponse:
    return InvestigationResponse(
        alert_id="ALT-STORE-001",
        source="manual",
        status="complete",
        normalized_event="SSH failures detected.",
        analysis=AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary="SSH brute force detected.",
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
                content="SSH failures detected.",
            ),
        ],
        risk_assessment=RiskAssessment(
            score=75,
            band="high",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id="POL-BF-HIGH",
            policy_name="High-Risk Brute Force",
            matched=True,
            response_allowed=False,
            actions=[],
            reason=(
                "Automatic containment is not permitted."
            ),
        ),
        response_plan=ResponsePlan(
            policy_id="POL-BF-HIGH",
            actions=[],
            response_allowed=False,
            status="create_case",
            reason=(
                "Automatic containment is not permitted."
            ),
        ),
        investigation_iteration=1,
    )


def test_store_saves_and_retrieves_investigation():
    store = InMemoryInvestigationStore()

    investigation = make_investigation()

    store.save(
        investigation
    )

    stored = store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert (
        stored.alert_id
        == "ALT-STORE-001"
    )

    assert (
        stored.response_plan.status
        == "create_case"
    )


def test_store_updates_response_plan():
    store = InMemoryInvestigationStore()

    investigation = make_investigation()

    store.save(
        investigation
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

    updated = store.update_response_plan(
        "ALT-STORE-001",
        execution_plan,
    )

    assert (
        updated.response_plan.status
        == "ready_for_execution"
    )

    assert (
        updated.response_plan.response_allowed
        is True
    )

    stored = store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert (
        stored.response_plan.status
        == "ready_for_execution"
    )

    assert (
        stored.response_plan.response_allowed
        is True
    )


def test_updating_missing_investigation_fails():
    store = InMemoryInvestigationStore()

    plan = make_investigation().response_plan

    with pytest.raises(
        KeyError,
        match="ALT-MISSING",
    ):
        store.update_response_plan(
            "ALT-MISSING",
            plan,
        )


def test_store_updates_execution_result():
    store = InMemoryInvestigationStore()

    investigation = make_investigation()

    store.save(
        investigation
    )

    execution = ResponseExecutionResult(
        policy_id="POL-BF-HIGH",
        executor="cortex",
        status="completed",
        action_results=[],
    )

    updated = store.update_execution_result(
        "ALT-STORE-001",
        execution,
    )

    assert updated.execution_result is not None

    assert (
        updated.execution_result.status
        == "completed"
    )

    stored = store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert stored.execution_result is not None

    assert (
        stored.execution_result.status
        == "completed"
    )


def test_sqlite_store_persists_across_instances(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-test.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    investigation = make_investigation()

    first_store.save(
        investigation
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    stored = second_store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert (
        stored.alert_id
        == "ALT-STORE-001"
    )

    assert (
        stored.response_plan.status
        == "create_case"
    )


def test_sqlite_store_persists_response_plan_update(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-test.db"
    )

    store = SQLiteInvestigationStore(
        database_path
    )

    investigation = make_investigation()

    store.save(
        investigation
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

    store.update_response_plan(
        "ALT-STORE-001",
        execution_plan,
    )

    restarted_store = SQLiteInvestigationStore(
        database_path
    )

    stored = restarted_store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert (
        stored.response_plan.status
        == "ready_for_execution"
    )

    assert (
        stored.response_plan.response_allowed
        is True
    )


def test_sqlite_store_persists_execution_result(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-test.db"
    )

    store = SQLiteInvestigationStore(
        database_path
    )

    investigation = make_investigation()

    store.save(
        investigation
    )

    execution = ResponseExecutionResult(
        policy_id="POL-BF-HIGH",
        executor="cortex",
        status="completed",
        action_results=[],
    )

    store.update_execution_result(
        "ALT-STORE-001",
        execution,
    )

    restarted_store = SQLiteInvestigationStore(
        database_path
    )

    stored = restarted_store.get(
        "ALT-STORE-001"
    )

    assert stored is not None

    assert stored.execution_result is not None

    assert (
        stored.execution_result.status
        == "completed"
    )