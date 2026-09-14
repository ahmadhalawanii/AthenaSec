import pytest

from app.schemas import (
    AlertAnalysis,
    CaseRecord,
    ResponseExecutionResult,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
)

from app.services.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
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

def test_postgres_store_initializes_required_tables():
    from unittest.mock import MagicMock

    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connect.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    assert (
        "CREATE TABLE IF NOT EXISTS investigations"
        in executed_sql
    )

    assert (
        "CREATE TABLE IF NOT EXISTS cases"
        in executed_sql
    )

def test_postgres_store_saves_investigation():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    investigation = make_investigation()

    result = store.save(
        investigation
    )

    assert result == investigation

    assert (
        connection.execute.call_count
        == 1
    )

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "INSERT INTO investigations"
        in sql
    )

    assert (
        "ON CONFLICT (alert_id)"
        in sql
    )

    assert parameters[0] == (
        "ALT-STORE-001"
    )

    assert parameters[1] == (
        investigation.model_dump_json()
    )

def test_postgres_store_gets_investigation():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    investigation = make_investigation()

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        investigation.model_dump_json(),
    )

    stored = store.get(
        "ALT-STORE-001"
    )

    assert stored == investigation

    assert (
        connection.execute.call_count
        == 1
    )

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "SELECT payload"
        in sql
    )

    assert (
        "FROM investigations"
        in sql
    )

    assert parameters == (
        "ALT-STORE-001",
    )

def test_postgres_store_updates_execution_result():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    investigation = make_investigation()

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        investigation.model_dump_json(),
    )

    execution = ResponseExecutionResult(
        policy_id="POL-BF-HIGH",
        executor="cortex",
        status="completed",
        action_results=[],
    )

    updated = (
        store.update_execution_result(
            "ALT-STORE-001",
            execution,
        )
    )

    assert (
        updated.execution_result
        is not None
    )

    assert (
        updated.execution_result.status
        == "completed"
    )

def test_postgres_store_saves_case():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    investigation = make_investigation()

    case = CaseRecord(
        case_id="CASE-STORE-001",
        alert_id=investigation.alert_id,
        policy_id=(
            investigation.policy_decision.policy_id
        ),
        classification=(
            investigation.analysis.classification
        ),
        risk_score=(
            investigation.risk_assessment.score
        ),
        risk_band=(
            investigation.risk_assessment.band
        ),
        status="open",
        reason=(
            investigation.response_plan.reason
        ),
    )

    result = store.save_case(
        case
    )

    assert result == case

    assert (
        connection.execute.call_count
        == 1
    )

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "INSERT INTO cases"
        in sql
    )

    assert (
        "ON CONFLICT (case_id)"
        in sql
    )

    assert parameters[0] == (
        "CASE-STORE-001"
    )

    assert parameters[1] == (
        "ALT-STORE-001"
    )

    assert parameters[2] == (
        case.model_dump_json()
    )

def test_postgres_store_gets_case():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    case = CaseRecord(
        case_id="CASE-STORE-001",
        alert_id="ALT-STORE-001",
        policy_id="POL-BF-HIGH",
        classification="brute_force",
        risk_score=75,
        risk_band="high",
        status="open",
        reason=(
            "Automatic containment is not permitted."
        ),
    )

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        case.model_dump_json(),
    )

    stored = store.get_case(
        "CASE-STORE-001"
    )

    assert stored == case

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "SELECT payload"
        in sql
    )

    assert (
        "FROM cases"
        in sql
    )

    assert (
        "WHERE case_id = %s"
        in sql
    )

    assert parameters == (
        "CASE-STORE-001",
    )

def test_postgres_store_gets_case_by_alert_id():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    connection.execute.reset_mock()

    case = CaseRecord(
        case_id="CASE-STORE-001",
        alert_id="ALT-STORE-001",
        policy_id="POL-BF-HIGH",
        classification="brute_force",
        risk_score=75,
        risk_band="high",
        status="open",
        reason=(
            "Automatic containment is not permitted."
        ),
    )

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        case.model_dump_json(),
    )

    stored = store.get_case_by_alert_id(
        "ALT-STORE-001"
    )

    assert stored == case

    sql = (
        connection
        .execute
        .call_args
        .args[0]
    )

    parameters = (
        connection
        .execute
        .call_args
        .args[1]
    )

    assert (
        "SELECT payload"
        in sql
    )

    assert (
        "FROM cases"
        in sql
    )

    assert (
        "WHERE alert_id = %s"
        in sql
    )

    assert parameters == (
        "ALT-STORE-001",
    )

def test_postgres_store_updates_response_plan():
    from unittest.mock import MagicMock

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    investigation = make_investigation()

    (
        connection
        .execute
        .return_value
        .fetchone
        .return_value
    ) = (
        investigation.model_dump_json(),
    )

    response_plan = (
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
        response_plan,
    )

    assert (
        updated.response_plan.status
        == "ready_for_execution"
    )

    assert (
        updated.response_plan.response_allowed
        is True
    )

    assert updated.response_plan.actions == [
        "block_ip",
    ]

def test_postgres_investigation_store_uses_psycopg_by_default(
    monkeypatch,
):
    from unittest.mock import MagicMock

    import psycopg

    connection = MagicMock()
    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    monkeypatch.setattr(
        psycopg,
        "connect",
        connect,
    )

    PostgresInvestigationStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )

    connect.assert_called_once_with(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        )
    )