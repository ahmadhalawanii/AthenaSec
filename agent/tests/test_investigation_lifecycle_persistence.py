from datetime import (
    datetime,
    timedelta,
    timezone,
)
from unittest.mock import MagicMock

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AlertAnalysis,
    AnalysisVerificationResult,
    EvidenceObservation,
    EvidenceRecord,
    EvidenceSufficiencyAssessment,
    IncidentAlertRecord,
    IncidentRecord,
    InvestigationResponse,
    InvestigationTraceStep,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)
from app.services.investigation_lifecycle import (
    build_investigation_id,
    persist_investigation_lifecycle,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
    PostgresInvestigationStore,
    SQLiteInvestigationStore,
)


BASE_TIME = datetime(
    2026,
    10,
    8,
    8,
    0,
    tzinfo=timezone.utc,
)


def make_incident() -> IncidentRecord:
    return IncidentRecord(
        incident_id="INC-001",
        title="Brute force activity",
        status="open",
        created_at=BASE_TIME,
        updated_at=BASE_TIME,
    )


def make_incident_alert() -> IncidentAlertRecord:
    return IncidentAlertRecord(
        incident_id="INC-001",
        alert_id="ALT-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
        metadata={
            "timestamp": (
                BASE_TIME.isoformat()
            ),
            "source_ip": "203.0.113.10",
            "target_user": "root",
        },
        observed_at=BASE_TIME,
    )


def make_response() -> InvestigationResponse:
    sufficiency = (
        EvidenceSufficiencyAssessment(
            classification="brute_force",
            sufficient=True,
            required_evidence=[
                "authentication_history",
                "source_endpoint_context",
            ],
            satisfied_evidence=[
                "authentication_history",
                "source_endpoint_context",
            ],
            missing_evidence=[],
        )
    )

    verification = (
        AnalysisVerificationResult(
            verified=True,
            classification_consistent=True,
            evidence_sufficient=True,
            checked_evidence_refs=[
                "E001",
                "E002",
            ],
            blocking_issues=[],
            warnings=[],
        )
    )

    trace = [
        InvestigationTraceStep(
            sequence=1,
            step_type="analysis",
            status="analyzed",
            details={
                "classification": (
                    "brute_force"
                ),
            },
            recorded_at=(
                BASE_TIME
                + timedelta(seconds=1)
            ),
        ),
        InvestigationTraceStep(
            sequence=2,
            step_type=(
                "evidence_sufficiency"
            ),
            status="needs_evidence",
            details={
                "sufficient": False,
            },
            recorded_at=(
                BASE_TIME
                + timedelta(seconds=2)
            ),
        ),
        InvestigationTraceStep(
            sequence=3,
            step_type=(
                "evidence_gathering"
            ),
            status="evidence_gathered",
            details={
                "requested_evidence": [
                    "authentication_history",
                    "source_endpoint_context",
                ],
            },
            recorded_at=(
                BASE_TIME
                + timedelta(seconds=3)
            ),
        ),
        InvestigationTraceStep(
            sequence=4,
            step_type=(
                "analysis_verification"
            ),
            status="analysis_verified",
            details={
                "verified": True,
            },
            recorded_at=(
                BASE_TIME
                + timedelta(seconds=4)
            ),
        ),
    ]

    return InvestigationResponse(
        alert_id="ALT-001",
        incident_id="INC-001",
        source="wazuh",
        alert_metadata={
            "timestamp": (
                BASE_TIME.isoformat()
            ),
        },
        status="complete",
        normalized_event=(
            "Repeated SSH authentication "
            "failures."
        ),
        analysis=AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "SSH brute-force activity "
                "was detected."
            ),
            evidence_refs=[
                "E001",
                "E002",
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
                evidence_type="alert",
                content=(
                    "Repeated SSH authentication "
                    "failures."
                ),
            ),
            EvidenceRecord(
                evidence_id="E002",
                source="wazuh",
                evidence_type=(
                    "authentication_history"
                ),
                content=(
                    "Authentication history "
                    "was reviewed."
                ),
            ),
        ],
        evidence_sufficiency=sufficiency,
        analysis_verification=verification,
        investigation_budget_exhausted=False,
        investigation_trace=trace,
        risk_assessment=RiskAssessment(
            score=75,
            band="high",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id="POL-TEST",
            policy_name="Test Policy",
            matched=True,
            response_allowed=False,
            actions=[],
            reason="Case required.",
        ),
        response_plan=ResponsePlan(
            policy_id="POL-TEST",
            actions=[],
            response_allowed=False,
            status="create_case",
            reason="Case required.",
        ),
        investigation_iteration=1,
    )


def test_investigation_id_is_deterministic():
    first = build_investigation_id(
        incident_id="INC-001",
        alert_id="ALT-001",
    )

    second = build_investigation_id(
        incident_id="INC-001",
        alert_id="ALT-001",
    )

    assert first == second

    assert first.startswith(
        "INV-"
    )


def test_in_memory_persists_complete_lifecycle():
    store = InMemoryInvestigationStore()

    response = make_response()

    record = (
        persist_investigation_lifecycle(
            store=store,
            investigation=response,
            completed_at=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
        )
    )

    assert record is not None

    assert (
        record.incident_id
        == "INC-001"
    )

    assert (
        record.primary_alert_id
        == "ALT-001"
    )

    assert (
        record.status
        == "complete"
    )

    assert (
        record.iteration_count
        == 1
    )

    assert (
        record.evidence_sufficient
        is True
    )

    assert (
        record.analysis_verified
        is True
    )

    assert (
        record.budget_exhausted
        is False
    )

    evidence = (
        store.list_investigation_evidence(
            record.investigation_id
        )
    )

    assert len(evidence) == 2

    assert (
        evidence[1].evidence_type
        == "authentication_history"
    )

    steps = (
        store.list_investigation_steps(
            record.investigation_id
        )
    )

    assert [
        step.sequence
        for step in steps
    ] == [
        1,
        2,
        3,
        4,
    ]

    assert [
        step.step_type
        for step in steps
    ] == [
        "analysis",
        "evidence_sufficiency",
        "evidence_gathering",
        "analysis_verification",
    ]


def test_sqlite_lifecycle_survives_restart(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-lifecycle.db"
    )

    first = SQLiteInvestigationStore(
        database_path
    )

    first.save_incident(
        make_incident()
    )

    first.save_incident_alert(
        make_incident_alert()
    )

    record = (
        persist_investigation_lifecycle(
            store=first,
            investigation=make_response(),
            completed_at=(
                BASE_TIME
                + timedelta(minutes=1)
            ),
        )
    )

    assert record is not None

    second = SQLiteInvestigationStore(
        database_path
    )

    stored = (
        second.get_incident_investigation(
            record.investigation_id
        )
    )

    assert stored is not None

    assert stored.analysis_verified is True

    evidence = (
        second.list_investigation_evidence(
            record.investigation_id
        )
    )

    assert len(evidence) == 2

    steps = (
        second.list_investigation_steps(
            record.investigation_id
        )
    )

    assert len(steps) == 4

    assert (
        steps[-1].step_type
        == "analysis_verification"
    )


def test_postgres_initializes_investigation_steps_table():
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

    executed_sql = " ".join(
        call.args[0]
        for call in (
            connection
            .execute
            .call_args_list
        )
    )

    normalized_sql = " ".join(
        executed_sql.split()
    )

    assert (
        "CREATE TABLE IF NOT EXISTS "
        "investigation_steps"
        in normalized_sql
    )

    assert (
        "idx_investigation_steps_investigation_id"
        in normalized_sql
    )


def test_real_graph_builds_ordered_investigation_trace():
    analyzer_calls = []

    def analyzer(
        context: str,
    ) -> AlertAnalysis:
        analyzer_calls.append(
            context
        )

        return AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="high",
            summary=(
                "Suspicious authentication "
                "activity was detected."
            ),
            evidence_refs=[
                "E001",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        )

    def provider(
        alert,
        requests,
    ):
        return [
            EvidenceObservation(
                source="wazuh",
                evidence_type=(
                    "authentication_history"
                ),
                content=(
                    "Authentication history reviewed."
                ),
            ),
            EvidenceObservation(
                source="wazuh",
                evidence_type=(
                    "source_endpoint_context"
                ),
                content=(
                    "Source endpoint context reviewed."
                ),
            ),
        ]

    graph = build_investigation_graph(
        analyzer=analyzer,
        evidence_provider=provider,
    )

    result = graph.invoke(
        {
            "alert": SecurityAlertInput(
                alert_id="ALT-TRACE-001",
                source="wazuh",
                event_text=(
                    "Repeated SSH authentication "
                    "failures."
                ),
                metadata={
                    "failed_attempts": 10,
                    "source_ip": (
                        "203.0.113.10"
                    ),
                    "target_user": "root",
                },
            ),
            "status": "received",
        }
    )

    trace = result[
        "investigation_trace"
    ]

    assert [
        step.sequence
        for step in trace
    ] == list(
        range(
            1,
            len(trace) + 1,
        )
    )

    assert [
        step.step_type
        for step in trace
    ] == [
        "analysis",
        "evidence_sufficiency",
        "evidence_gathering",
        "analysis",
        "evidence_sufficiency",
        "analysis_verification",
    ]

    assert (
        result[
            "analysis_verification"
        ].verified
        is True
    )