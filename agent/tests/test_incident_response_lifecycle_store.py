from datetime import (
    datetime,
    timedelta,
    timezone,
)
from unittest.mock import MagicMock

from app.schemas import (
    ActionExecutionResultRecord,
    ActionRiskAssessmentRecord,
    ApprovalRequestRecord,
    IncidentAlertRecord,
    IncidentInvestigationRecord,
    IncidentPolicyDecisionRecord,
    IncidentRecord,
    IncidentRiskAssessmentRecord,
    ProposedActionRecord,
    ResponseActionRecord,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)
from app.services.investigation_store import (
    SQLiteInvestigationStore,
)


BASE_TIME = datetime(
    2026,
    10,
    7,
    16,
    0,
    tzinfo=timezone.utc,
)


def make_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-001",
        title="SSH brute-force activity",
        status="open",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_alert() -> IncidentAlertRecord:
    return IncidentAlertRecord(
        incident_id="INC-001",
        alert_id="ALT-WAZUH-001",
        source="wazuh",
        event_text="Repeated SSH authentication failures.",
        metadata={},
        observed_at=(
            BASE_TIME
            + timedelta(minutes=1)
        ),
    )


def make_investigation() -> IncidentInvestigationRecord:
    timestamp = (
        BASE_TIME
        + timedelta(minutes=2)
    )

    return IncidentInvestigationRecord(
        investigation_id="INV-001",
        incident_id="INC-001",
        primary_alert_id="ALT-WAZUH-001",
        status="investigating",
        started_at=timestamp,
        updated_at=timestamp,
    )


def make_incident_risk() -> IncidentRiskAssessmentRecord:
    return IncidentRiskAssessmentRecord(
        risk_assessment_id="IRISK-001",
        incident_id="INC-001",
        investigation_id="INV-001",
        score=88,
        band="critical",
        factors=[],
        assessed_at=(
            BASE_TIME
            + timedelta(minutes=3)
        ),
    )


def make_proposed_action() -> ProposedActionRecord:
    return ProposedActionRecord(
        proposed_action_id="PA-001",
        incident_id="INC-001",
        investigation_id="INV-001",
        action_type="block_ip",
        target_type="ip",
        target="203.0.113.10",
        parameters={
            "ip": "203.0.113.10",
            "duration_seconds": 600,
        },
        reversible=True,
        rollback_action_type="unblock_ip",
        rollback_parameters={
            "ip": "203.0.113.10",
        },
        reason="Contain confirmed brute-force source.",
        proposed_at=(
            BASE_TIME
            + timedelta(minutes=4)
        ),
    )


def make_action_risk() -> ActionRiskAssessmentRecord:
    return ActionRiskAssessmentRecord(
        action_risk_id="ARISK-001",
        proposed_action_id="PA-001",
        score=25,
        band="low",
        blast_radius="single",
        reversible=True,
        protected_target=False,
        requires_approval=False,
        reasons=[
            "Single external IP.",
            "Temporary and reversible.",
        ],
        assessed_at=(
            BASE_TIME
            + timedelta(minutes=5)
        ),
    )


def make_policy_decision() -> IncidentPolicyDecisionRecord:
    return IncidentPolicyDecisionRecord(
        decision_id="PDEC-001",
        incident_id="INC-001",
        proposed_action_id="PA-001",
        policy_id="POL-TEMP-IP-BLOCK",
        outcome="AUTO_ALLOWED",
        reason=(
            "Low-risk reversible containment "
            "is permitted automatically."
        ),
        decided_at=(
            BASE_TIME
            + timedelta(minutes=6)
        ),
    )


def make_approval() -> ApprovalRequestRecord:
    return ApprovalRequestRecord(
        approval_id="APR-001",
        incident_id="INC-001",
        proposed_action_id="PA-001",
        policy_decision_id="PDEC-001",
        action_fingerprint="sha256:test-action",
        status="PENDING",
        requested_by="athenasec-policy",
        requested_at=(
            BASE_TIME
            + timedelta(minutes=7)
        ),
        expires_at=(
            BASE_TIME
            + timedelta(minutes=17)
        ),
    )


def make_response_action() -> ResponseActionRecord:
    return ResponseActionRecord(
        response_action_id="ACT-001",
        incident_id="INC-001",
        proposed_action_id="PA-001",
        approval_id=None,
        executor="cortex",
        status="planned",
        created_at=(
            BASE_TIME
            + timedelta(minutes=8)
        ),
    )


def make_action_result() -> ActionExecutionResultRecord:
    return ActionExecutionResultRecord(
        action_result_id="ARES-001",
        response_action_id="ACT-001",
        status="completed",
        message="Cortex accepted the action.",
        details={
            "job_id": "CORTEX-001",
        },
        recorded_at=(
            BASE_TIME
            + timedelta(minutes=9)
        ),
    )


def test_in_memory_store_persists_response_lifecycle():
    store = InMemoryIncidentResponseStore()

    records = [
        (
            store.save_incident_risk,
            store.get_incident_risk,
            make_incident_risk(),
            "IRISK-001",
        ),
        (
            store.save_proposed_action,
            store.get_proposed_action,
            make_proposed_action(),
            "PA-001",
        ),
        (
            store.save_action_risk,
            store.get_action_risk,
            make_action_risk(),
            "ARISK-001",
        ),
        (
            store.save_policy_decision,
            store.get_policy_decision,
            make_policy_decision(),
            "PDEC-001",
        ),
        (
            store.save_approval_request,
            store.get_approval_request,
            make_approval(),
            "APR-001",
        ),
        (
            store.save_response_action,
            store.get_response_action,
            make_response_action(),
            "ACT-001",
        ),
        (
            store.save_action_result,
            store.get_action_result,
            make_action_result(),
            "ARES-001",
        ),
    ]

    for save, get, record, record_id in records:
        assert save(record) == record

        assert (
            get(record_id)
            == record
        )


def test_approval_binds_exact_proposed_action():
    store = InMemoryIncidentResponseStore()

    approval = make_approval()

    store.save_approval_request(
        approval
    )

    stored = store.get_approval_request(
        "APR-001"
    )

    assert stored is not None

    assert (
        stored.proposed_action_id
        == "PA-001"
    )

    assert (
        stored.action_fingerprint
        == "sha256:test-action"
    )


def test_sqlite_store_persists_response_lifecycle(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-response-test.db"
    )

    parent_store = SQLiteInvestigationStore(
        database_path
    )

    parent_store.save_incident(
        make_incident()
    )

    parent_store.save_incident_alert(
        make_alert()
    )

    parent_store.save_incident_investigation(
        make_investigation()
    )

    store = SQLiteIncidentResponseStore(
        database_path
    )

    store.save_incident_risk(
        make_incident_risk()
    )

    store.save_proposed_action(
        make_proposed_action()
    )

    store.save_action_risk(
        make_action_risk()
    )

    store.save_policy_decision(
        make_policy_decision()
    )

    store.save_approval_request(
        make_approval()
    )

    store.save_response_action(
        make_response_action()
    )

    store.save_action_result(
        make_action_result()
    )

    restarted = SQLiteIncidentResponseStore(
        database_path
    )

    assert (
        restarted.get_incident_risk(
            "IRISK-001"
        )
        == make_incident_risk()
    )

    assert (
        restarted.get_proposed_action(
            "PA-001"
        )
        == make_proposed_action()
    )

    assert (
        restarted.get_approval_request(
            "APR-001"
        )
        == make_approval()
    )

    assert (
        restarted.get_action_result(
            "ARES-001"
        )
        == make_action_result()
    )


def test_postgres_store_initializes_response_tables():
    connection = MagicMock()

    connection.__enter__.return_value = (
        connection
    )

    connect = MagicMock(
        return_value=connection
    )

    PostgresIncidentResponseStore(
        (
            "postgresql://"
            "athenasec:test@localhost/"
            "athenasec"
        ),
        connect=connect,
    )

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    for table in [
        "incident_risk_assessments",
        "proposed_actions",
        "action_risk_assessments",
        "incident_policy_decisions",
        "approval_requests",
        "response_actions",
        "action_results",
    ]:
        assert (
            f"CREATE TABLE IF NOT EXISTS {table}"
            in executed_sql
        )


def test_postgres_store_saves_parameter_bound_action():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresIncidentResponseStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=connect,
    )

    connection.execute.reset_mock()

    action = make_proposed_action()

    assert (
        store.save_proposed_action(action)
        == action
    )

    sql = connection.execute.call_args.args[0]
    parameters = connection.execute.call_args.args[1]

    assert "INSERT INTO proposed_actions" in sql
    assert "ON CONFLICT (proposed_action_id)" in sql

    assert parameters[0] == "PA-001"
    assert parameters[1] == "INC-001"
    assert parameters[2] == "INV-001"


def test_postgres_store_saves_new_policy_outcome():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresIncidentResponseStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=connect,
    )

    connection.execute.reset_mock()

    decision = make_policy_decision()

    store.save_policy_decision(
        decision
    )

    sql = connection.execute.call_args.args[0]
    parameters = connection.execute.call_args.args[1]

    assert "INSERT INTO incident_policy_decisions" in sql

    assert (
        parameters[3]
        == "AUTO_ALLOWED"
    )


def test_postgres_store_saves_approval_binding():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresIncidentResponseStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=connect,
    )

    connection.execute.reset_mock()

    approval = make_approval()

    store.save_approval_request(
        approval
    )

    sql = connection.execute.call_args.args[0]
    parameters = connection.execute.call_args.args[1]

    assert "INSERT INTO approval_requests" in sql

    assert parameters[0] == "APR-001"
    assert parameters[2] == "PA-001"
    assert (
        parameters[4]
        == "sha256:test-action"
    )


def test_postgres_store_saves_execution_result():
    connection = MagicMock()
    connection.__enter__.return_value = connection

    connect = MagicMock(
        return_value=connection
    )

    store = PostgresIncidentResponseStore(
        "postgresql://athenasec:test@localhost/athenasec",
        connect=connect,
    )

    connection.execute.reset_mock()

    result = make_action_result()

    store.save_action_result(
        result
    )

    sql = connection.execute.call_args.args[0]
    parameters = connection.execute.call_args.args[1]

    assert "INSERT INTO action_results" in sql

    assert parameters[0] == "ARES-001"
    assert parameters[1] == "ACT-001"
    assert parameters[2] == "completed"