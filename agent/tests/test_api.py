from fastapi.testclient import TestClient
import app.services.cortex_config as cortex_config
from app.main import create_app
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
    CaseRecord,
    ActionExecutionResult,
    ResponseExecutionResult,
    AttackPrediction,
    MISPEnrichment,
    MISPMatch,
)

from app.services.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
)
from app.services.audit_store import (
    InMemoryAuditStore,
)

class FakeFailingResponseExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        investigation,
    ):
        self.calls.append(
            investigation.alert_id
        )

        raise RuntimeError(
            "Cortex execution failed."
        )


class FakeInvestigationGraph:
    def invoke(
        self,
        state: dict,
    ) -> dict:
        alert: SecurityAlertInput = state["alert"]

        return {
            "alert": alert,
            "normalized_event": alert.event_text,
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    content=alert.event_text,
                ),
            ],
            "analysis": AlertAnalysis(
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
            "risk_assessment": RiskAssessment(
                score=75,
                band="high",
                factors=[],
            ),
            "policy_decision": PolicyDecision(
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
            "response_plan": ResponsePlan(
                policy_id="POL-BF-HIGH",
                actions=[],
                response_allowed=False,
                status="create_case",
                reason=(
                    "Automatic containment "
                    "is not permitted."
                ),
            ),
            "investigation_iteration": 0,
            "status": "complete",
        }


class FakeCriticalInvestigationGraph:
    def invoke(
        self,
        state,
    ):
        return {
            "alert": state["alert"],
            "normalized_event": (
                "Critical SSH brute force "
                "against root."
            ),
            "analysis": AlertAnalysis(
                classification="brute_force",
                confidence=0.95,
                severity_assessment="critical",
                summary=(
                    "Critical SSH brute force detected."
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
            "evidence_records": [
                EvidenceRecord(
                    evidence_id="E001",
                    source="alert",
                    content=(
                        "Successful authentication "
                        "followed critical brute force."
                    ),
                ),
            ],
            "risk_assessment": RiskAssessment(
                score=92,
                band="critical",
                factors=[],
            ),
            "policy_decision": PolicyDecision(
                policy_id="POL-BF-CRITICAL",
                policy_name=(
                    "Critical Brute Force Containment"
                ),
                matched=True,
                response_allowed=True,
                actions=[
                    "block_ip",
                ],
                reason=(
                    "Critical brute-force activity "
                    "met the autonomous containment "
                    "threshold."
                ),
            ),
            "response_plan": ResponsePlan(
                policy_id="POL-BF-CRITICAL",
                actions=[
                    "block_ip",
                ],
                response_allowed=True,
                status="ready_for_execution",
                reason=(
                    "Critical brute-force activity "
                    "met the autonomous containment "
                    "threshold."
                ),
            ),
            "investigation_iteration": 1,
            "status": "complete",
        }


class FakeMLInvestigationGraph(
    FakeInvestigationGraph
):
    def invoke(
        self,
        state: dict,
    ) -> dict:
        result = super().invoke(
            state
        )

        result["ml_prediction"] = (
            AttackPrediction(
                classification="brute_force",
                confidence=0.97,
                model_version="fake-ml-v1",
            )
        )

        return result

class FakeFailedMLInvestigationGraph(
    FakeInvestigationGraph
):
    def invoke(
        self,
        state: dict,
    ) -> dict:
        result = super().invoke(
            state
        )

        result["ml_prediction"] = (
            AttackPrediction(
                classification="unknown",
                confidence=0.0,
                model_version="unavailable",
            )
        )

        result["ml_error"] = (
            "ML model unavailable"
        )

        result["policy_decision"] = (
            result[
                "policy_decision"
            ].model_copy(
                update={
                    "response_allowed": False,
                    "actions": [],
                    "reason": (
                        "Autonomous response denied "
                        "because ML classification "
                        "failed."
                    ),
                }
            )
        )

        result["response_plan"] = (
            result[
                "response_plan"
            ].model_copy(
                update={
                    "response_allowed": False,
                    "actions": [],
                    "status": "create_case",
                    "reason": (
                        "Autonomous response denied "
                        "because ML classification "
                        "failed."
                    ),
                }
            )
        )

        return result


class FakeSuccessfulResponseExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        investigation,
    ):
        self.calls.append(
            investigation.alert_id
        )

        return ResponseExecutionResult(
            policy_id=(
                investigation.policy_decision.policy_id
            ),
            executor="cortex",
            status="completed",
            action_results=[
                ActionExecutionResult(
                    action="block_ip",
                    status="completed",
                    message=(
                        "Source IP was blocked."
                    ),
                ),
            ],
        )

class FakeMISPInvestigationGraph(
    FakeMLInvestigationGraph
):
    def invoke(
        self,
        state: dict,
    ) -> dict:
        result = super().invoke(
            state
        )

        result["misp_enrichment"] = (
            MISPEnrichment(
                queried_indicators=[
                    "203.0.113.10",
                ],
                matches=[
                    MISPMatch(
                        indicator_type="ip-src",
                        indicator_value=(
                            "203.0.113.10"
                        ),
                        event_id="42",
                        event_info=(
                            "Known brute-force "
                            "infrastructure"
                        ),
                        threat_level="high",
                    )
                ],
            )
        )

        result["misp_error"] = None

        return result

def test_ml_failure_creates_case_without_cortex_execution():
    store = InMemoryInvestigationStore()
    audit_store = InMemoryAuditStore()
    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeFailedMLInvestigationGraph()
        ),
        investigation_store=store,
        audit_store=audit_store,
        response_executor=executor,
        autonomous_response_enabled=True,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["ml_prediction"]["classification"]
        == "unknown"
    )

    assert (
        body["ml_prediction"]["confidence"]
        == 0.0
    )

    assert (
        body["ml_error"]
        == "ML model unavailable"
    )

    assert (
        body["policy_decision"]["response_allowed"]
        is False
    )

    assert (
        body["response_plan"]["status"]
        == "create_case"
    )

    assert (
        body["response_plan"]["response_allowed"]
        is False
    )

    assert (
        body["response_plan"]["actions"]
        == []
    )

    assert executor.calls == []

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

    case_response = client.get(
        (
            "/api/v1/investigations/"
            "ALT-API-001/case"
        )
    )

    assert (
        case_response.status_code
        == 200
    )

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "ml_classification_failed"
        in event_types
    )

    assert (
        "case_created"
        in event_types
    )

    assert (
        "cortex_execution_started"
        not in event_types
    )

    assert (
        "cortex_execution_completed"
        not in event_types
    )

def make_client() -> TestClient:
    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=store,
    )

    return TestClient(app)


def submit_investigation(
    client: TestClient,
):
    return client.post(
        "/api/v1/analyze",
        json={
            "alert_id": "ALT-API-001",
            "source": "manual",
            "event_text": (
                "148 failed SSH login attempts "
                "against root."
            ),
            "metadata": {
                "failed_attempts": 148,
                "privileged_target": True,
                "asset_criticality": "medium",
            },
        },
    )


def test_health_endpoint():
    client = make_client()

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "service": "athenasec-agent",
    }


def test_analyze_endpoint_returns_investigation():
    client = make_client()

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["alert_id"]
        == "ALT-API-001"
    )

    assert (
        data["analysis"]["classification"]
        == "brute_force"
    )

    assert (
        data["risk_assessment"]["score"]
        == 75
    )

    assert (
        data["policy_decision"]["policy_id"]
        == "POL-BF-HIGH"
    )

    assert (
        data["policy_decision"]["response_allowed"]
        is False
    )

    assert (
        data["response_plan"]["status"]
        == "create_case"
    )

    assert (
        data["response_plan"]["response_allowed"]
        is False
    )


def test_analyzed_investigation_can_be_retrieved():
    client = make_client()

    submit_response = submit_investigation(
        client
    )

    assert submit_response.status_code == 200

    response = client.get(
        "/api/v1/investigations/ALT-API-001"
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["alert_id"]
        == "ALT-API-001"
    )

    assert (
        data["response_plan"]["status"]
        == "create_case"
    )


def test_missing_investigation_returns_404():
    client = make_client()

    response = client.get(
        "/api/v1/investigations/ALT-MISSING"
    )

    assert response.status_code == 404


def test_analyst_decision_endpoint_does_not_exist():
    client = make_client()

    submit_investigation(
        client
    )

    response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/decision"
        ),
        json={
            "decision": "approve",
            "analyst_id": "analyst-001",
            "reason": "Approve containment.",
        },
    )

    assert response.status_code == 404


def test_manual_execute_endpoint_does_not_exist():
    client = make_client()

    submit_investigation(
        client
    )

    response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/execute"
        )
    )

    assert response.status_code == 404


def test_sqlite_investigation_survives_app_restart(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-api.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    first_app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=first_store,
    )

    first_client = TestClient(
        first_app
    )

    response = submit_investigation(
        first_client
    )

    assert response.status_code == 200

    second_store = SQLiteInvestigationStore(
        database_path
    )

    second_app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=second_store,
    )

    second_client = TestClient(
        second_app
    )

    stored_response = second_client.get(
        "/api/v1/investigations/ALT-API-001"
    )

    assert stored_response.status_code == 200

    stored_data = stored_response.json()

    assert (
        stored_data["alert_id"]
        == "ALT-API-001"
    )

    assert (
        stored_data["response_plan"]["status"]
        == "create_case"
    )

def test_analyze_creates_case_automatically():
    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

    assert (
        case.alert_id
        == "ALT-API-001"
    )

    assert (
        case.policy_id
        == "POL-BF-HIGH"
    )

    assert case.status == "open"

    assert case.risk_score == 75

def test_case_can_be_retrieved_by_alert_id():
    client = make_client()

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    case_response = client.get(
        (
            "/api/v1/investigations/"
            "ALT-API-001/case"
        )
    )

    assert case_response.status_code == 200

    data = case_response.json()

    assert (
        data["alert_id"]
        == "ALT-API-001"
    )

    assert (
        data["policy_id"]
        == "POL-BF-HIGH"
    )

    assert data["risk_score"] == 75

    assert data["risk_band"] == "high"

    assert data["status"] == "open"

    assert data["case_id"]


def test_missing_case_returns_404():
    client = make_client()

    response = client.get(
        (
            "/api/v1/investigations/"
            "ALT-MISSING/case"
        )
    )

    assert response.status_code == 404


class FakeSuccessfulResponseExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        investigation,
    ):
        self.calls.append(
            investigation.alert_id
        )

        return ResponseExecutionResult(
            policy_id=(
                investigation.policy_decision.policy_id
            ),
            executor="cortex",
            status="completed",
            action_results=[
                ActionExecutionResult(
                    action="block_ip",
                    status="completed",
                    message=(
                        "Source IP was blocked."
                    ),
                ),
            ],
        )


def test_sqlite_case_survives_app_restart(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-case-api.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    first_app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=first_store,
    )

    first_client = TestClient(
        first_app
    )

    response = submit_investigation(
        first_client
    )

    assert response.status_code == 200

    first_case_response = first_client.get(
        (
            "/api/v1/investigations/"
            "ALT-API-001/case"
        )
    )

    assert (
        first_case_response.status_code
        == 200
    )

    first_case_id = (
        first_case_response.json()[
            "case_id"
        ]
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    second_app = create_app(
        investigation_graph=FakeInvestigationGraph(),
        investigation_store=second_store,
    )

    second_client = TestClient(
        second_app
    )

    restarted_case_response = second_client.get(
        (
            "/api/v1/investigations/"
            "ALT-API-001/case"
        )
    )

    assert (
        restarted_case_response.status_code
        == 200
    )

    restarted_case = (
        restarted_case_response.json()
    )

    assert (
        restarted_case["case_id"]
        == first_case_id
    )

    assert (
        restarted_case["alert_id"]
        == "ALT-API-001"
    )

    assert (
        restarted_case["status"]
        == "open"
    )

def test_api_executes_allowed_response_when_enabled():
    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
        response_executor=executor,
        autonomous_response_enabled=True,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == [
        "ALT-API-001",
    ]

    stored = store.get(
        "ALT-API-001"
    )

    assert stored is not None

    assert (
        stored.execution_result
        is not None
    )

    assert (
        stored.execution_result.status
        == "completed"
    )

    assert (
        stored.execution_result.executor
        == "cortex"
    )

def test_autonomous_response_env_true_enables_execution(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "true",
    )

    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
        response_executor=executor,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == [
        "ALT-API-001",
    ]


def test_autonomous_response_env_false_blocks_execution(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "false",
    )

    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
        response_executor=executor,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == []

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

def test_investigation_preserves_alert_metadata():
    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
    )

    client = TestClient(
        app
    )

    response = client.post(
        "/api/v1/analyze",
        json={
            "alert_id": "ALT-TARGET-001",
            "source": "wazuh",
            "event_text": (
                "Critical SSH brute force "
                "against root."
            ),
            "metadata": {
                "source_ip": "203.0.113.50",
                "target_user": "root",
                "failed_attempts": 148,
                "privileged_target": True,
                "asset_criticality": "high",
            },
        },
    )

    assert response.status_code == 200

    stored = store.get(
        "ALT-TARGET-001"
    )

    assert stored is not None

    assert (
        stored.alert_metadata["source_ip"]
        == "203.0.113.50"
    )

    assert (
        stored.alert_metadata["target_user"]
        == "root"
    )

def test_api_builds_cortex_executor_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "true",
    )

    monkeypatch.setenv(
        "CORTEX_URL",
        "http://cortex:9001",
    )

    monkeypatch.setenv(
        "CORTEX_API_KEY",
        "secret-api-key",
    )

    monkeypatch.setenv(
        "CORTEX_BLOCK_IP_RESPONDER_ID",
        "BlockIp_1_0",
    )

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
    )

    client = TestClient(
        app
    )

    assert app is not None

    assert client is not None


def test_api_uses_environment_built_cortex_executor(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "true",
    )

    executor = FakeSuccessfulResponseExecutor()

    monkeypatch.setattr(
        cortex_config,
        "build_cortex_response_executor_from_env",
        lambda: executor,
    )

    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == [
        "ALT-API-001",
    ]

    stored = store.get(
        "ALT-API-001"
    )

    assert stored is not None

    assert (
        stored.execution_result
        is not None
    )

    assert (
        stored.execution_result.executor
        == "cortex"
    )

def test_environment_built_cortex_respects_kill_switch(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "false",
    )

    executor = FakeSuccessfulResponseExecutor()

    monkeypatch.setattr(
        cortex_config,
        "build_cortex_response_executor_from_env",
        lambda: executor,
    )

    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == []

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

    assert case.status == "open"


def test_api_creates_case_when_cortex_execution_fails(
    monkeypatch,
):
    monkeypatch.setenv(
        "AUTONOMOUS_RESPONSE_ENABLED",
        "true",
    )

    executor = FakeFailingResponseExecutor()

    monkeypatch.setattr(
        cortex_config,
        "build_cortex_response_executor_from_env",
        lambda: executor,
    )

    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == [
        "ALT-API-001",
    ]

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

    assert case.status == "open"

    stored = store.get(
        "ALT-API-001"
    )

    assert stored is not None

    assert (
        stored.execution_result
        is None
    )

def test_api_records_core_audit_events():
    investigation_store = (
        InMemoryInvestigationStore()
    )

    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeInvestigationGraph()
        ),
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = audit_store.list_by_alert_id(
        "ALT-API-001"
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "investigation_created"
        in event_types
    )

    assert (
        "policy_evaluated"
        in event_types
    )

    assert (
        "case_created"
        in event_types
    )

def test_api_records_cortex_execution_audit_events():
    investigation_store = (
        InMemoryInvestigationStore()
    )

    audit_store = InMemoryAuditStore()

    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
        response_executor=executor,
        autonomous_response_enabled=True,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = audit_store.list_by_alert_id(
        "ALT-API-001"
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "cortex_execution_started"
        in event_types
    )

    assert (
        "cortex_execution_completed"
        in event_types
    )

    assert (
        "cortex_execution_failed"
        not in event_types
    )

    assert (
        "autonomous_response_blocked"
        not in event_types
    )

def test_api_records_kill_switch_block_audit_event():
    investigation_store = (
        InMemoryInvestigationStore()
    )

    audit_store = InMemoryAuditStore()

    executor = FakeSuccessfulResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
        response_executor=executor,
        autonomous_response_enabled=False,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    assert executor.calls == []

    records = audit_store.list_by_alert_id(
        "ALT-API-001"
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "autonomous_response_blocked"
        in event_types
    )

    assert (
        "cortex_execution_started"
        not in event_types
    )

    assert (
        "cortex_execution_completed"
        not in event_types
    )

    assert (
        "case_created"
        in event_types
    )


def test_api_records_cortex_failure_audit_event():
    investigation_store = (
        InMemoryInvestigationStore()
    )

    audit_store = InMemoryAuditStore()

    executor = FakeFailingResponseExecutor()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
        response_executor=executor,
        autonomous_response_enabled=True,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = audit_store.list_by_alert_id(
        "ALT-API-001"
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "cortex_execution_started"
        in event_types
    )

    assert (
        "cortex_execution_failed"
        in event_types
    )

    assert (
        "cortex_execution_completed"
        not in event_types
    )

    assert (
        "case_created"
        in event_types
    )

def test_api_returns_investigation_audit_history():
    investigation_store = (
        InMemoryInvestigationStore()
    )

    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeInvestigationGraph()
        ),
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    audit_response = client.get(
        (
            "/api/v1/investigations/"
            "ALT-API-001/audit"
        )
    )

    assert (
        audit_response.status_code
        == 200
    )

    records = audit_response.json()

    assert len(
        records
    ) >= 3

    assert (
        records[0]["event_type"]
        == "investigation_created"
    )

    event_types = [
        record["event_type"]
        for record in records
    ]

    assert (
        "policy_evaluated"
        in event_types
    )

    assert (
        "case_created"
        in event_types
    )

    assert (
        records[0]["timestamp"]
        is not None
    )

def test_api_returns_empty_audit_history_for_unknown_alert():
    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = client.get(
        (
            "/api/v1/investigations/"
            "ALT-UNKNOWN/audit"
        )
    )

    assert response.status_code == 200

    assert response.json() == []

def test_api_persists_ml_prediction():
    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeMLInvestigationGraph()
        ),
        investigation_store=store,
        audit_store=InMemoryAuditStore(),
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["ml_prediction"][
            "classification"
        ]
        == "brute_force"
    )

    assert (
        body["ml_prediction"][
            "confidence"
        ]
        == 0.97
    )

    assert (
        body["ml_prediction"][
            "model_version"
        ]
        == "fake-ml-v1"
    )

    stored = store.get(
        "ALT-API-001"
    )

    assert stored is not None

    assert (
        stored.ml_prediction.classification
        == "brute_force"
    )

    assert (
        stored.ml_prediction.confidence
        == 0.97
    )

    assert (
        stored.ml_prediction.model_version
        == "fake-ml-v1"
    )

def test_api_records_ml_classification_completed_audit_event():
    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeMLInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    ml_records = [
        record
        for record in records
        if (
            record.event_type
            == "ml_classification_completed"
        )
    ]

    assert len(ml_records) == 1

    record = ml_records[0]

    assert (
        record.details[
            "classification"
        ]
        == "brute_force"
    )

    assert (
        record.details[
            "confidence"
        ]
        == 0.97
    )

    assert (
        record.details[
            "model_version"
        ]
        == "fake-ml-v1"
    )


def test_api_records_ml_classification_failed_audit_event():
    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeFailedMLInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    failed_records = [
        record
        for record in records
        if (
            record.event_type
            == "ml_classification_failed"
        )
    ]

    assert len(
        failed_records
    ) == 1

    record = failed_records[0]

    assert (
        record.details["error"]
        == "ML model unavailable"
    )

    assert (
        record.details[
            "classification"
        ]
        == "unknown"
    )

    assert (
        record.details[
            "confidence"
        ]
        == 0.0
    )

    assert (
        record.details[
            "model_version"
        ]
        == "unavailable"
    )

def test_create_app_builds_default_graph_with_live_ml_classifier(
    monkeypatch,
):
    captured = {}

    class FakeLiveClassifier:
        def classify(
            self,
            alert,
        ):
            raise RuntimeError(
                "not used in this test"
            )

    fake_classifier = FakeLiveClassifier()

    def fake_build_live_ml_classifier():
        return fake_classifier

    def fake_build_investigation_graph(
        *,
        ml_classifier=None,
        misp_client=None,
    ):
        captured[
            "ml_classifier"
        ] = ml_classifier

        class FakeGraph:
            def invoke(
                self,
                state,
            ):
                return state

        return FakeGraph()

    monkeypatch.setattr(
        "app.main.build_live_ml_classifier",
        fake_build_live_ml_classifier,
    )

    monkeypatch.setattr(
        "app.main.build_investigation_graph",
        fake_build_investigation_graph,
    )

    create_app()

    assert (
        captured["ml_classifier"]
        is fake_classifier
    )

def test_create_app_builds_default_graph_with_live_misp_client(
    monkeypatch,
):
    captured = {}

    class FakeLiveClassifier:
        def classify(
            self,
            alert,
        ):
            raise RuntimeError(
                "not used in this test"
            )

    class FakeLiveMISPClient:
        def enrich(
            self,
            indicators,
        ):
            raise RuntimeError(
                "not used in this test"
            )

    fake_classifier = FakeLiveClassifier()
    fake_misp_client = FakeLiveMISPClient()

    def fake_build_live_ml_classifier():
        return fake_classifier

    def fake_build_live_misp_client():
        return fake_misp_client

    def fake_build_investigation_graph(
        *,
        ml_classifier=None,
        misp_client=None,
    ):
        captured[
            "ml_classifier"
        ] = ml_classifier

        captured[
            "misp_client"
        ] = misp_client

        class FakeGraph:
            def invoke(
                self,
                state,
            ):
                return state

        return FakeGraph()

    monkeypatch.setattr(
        "app.main.build_live_ml_classifier",
        fake_build_live_ml_classifier,
    )

    monkeypatch.setattr(
        "app.main.build_live_misp_client",
        fake_build_live_misp_client,
    )

    monkeypatch.setattr(
        "app.main.build_investigation_graph",
        fake_build_investigation_graph,
    )

    create_app()

    assert (
        captured["ml_classifier"]
        is fake_classifier
    )

    assert (
        captured["misp_client"]
        is fake_misp_client
    )

def test_api_creates_case_when_cortex_executor_is_unavailable():
    store = InMemoryInvestigationStore()
    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeCriticalInvestigationGraph()
        ),
        investigation_store=store,
        audit_store=audit_store,
        response_executor=None,
        autonomous_response_enabled=True,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["response_plan"]["status"]
        == "ready_for_execution"
    )

    case = store.get_case_by_alert_id(
        "ALT-API-001"
    )

    assert case is not None

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    event_types = [
        record.event_type
        for record in records
    ]

    assert (
        "case_created"
        in event_types
    )

    assert (
        "cortex_execution_started"
        not in event_types
    )

    assert (
        "cortex_execution_completed"
        not in event_types
    )

def test_api_persists_misp_enrichment():
    store = InMemoryInvestigationStore()

    app = create_app(
        investigation_graph=(
            FakeMISPInvestigationGraph()
        ),
        investigation_store=store,
        audit_store=InMemoryAuditStore(),
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["misp_enrichment"]
        ["queried_indicators"]
        == [
            "203.0.113.10",
        ]
    )

    assert (
        body["misp_enrichment"]
        ["matches"][0]
        ["threat_level"]
        == "high"
    )

    assert (
        body["misp_enrichment"]
        ["matches"][0]
        ["event_id"]
        == "42"
    )

    assert (
        body["misp_error"]
        is None
    )

    stored = store.get(
        "ALT-API-001"
    )

    assert stored is not None

    assert (
        stored.misp_enrichment
        is not None
    )

    assert (
        stored.misp_enrichment
        .matches[0]
        .event_id
        == "42"
    )

def test_api_records_misp_enrichment_completed_audit_event():
    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeMISPInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    completed_records = [
        record
        for record in records
        if (
            record.event_type
            == "misp_enrichment_completed"
        )
    ]

    assert len(
        completed_records
    ) == 1

    record = completed_records[0]

    assert (
        record.details["match_count"]
        == 1
    )

    assert (
        record.details[
            "queried_indicators"
        ]
        == [
            "203.0.113.10",
        ]
    )


def test_api_records_misp_enrichment_failed_audit_event():
    class FakeFailedMISPInvestigationGraph(
        FakeMISPInvestigationGraph
    ):
        def invoke(
            self,
            state: dict,
        ) -> dict:
            result = super().invoke(
                state
            )

            result["misp_enrichment"] = (
                MISPEnrichment(
                    queried_indicators=[
                        "203.0.113.10",
                    ],
                    matches=[],
                )
            )

            result["misp_error"] = (
                "MISP unavailable"
            )

            return result

    audit_store = InMemoryAuditStore()

    app = create_app(
        investigation_graph=(
            FakeFailedMISPInvestigationGraph()
        ),
        investigation_store=(
            InMemoryInvestigationStore()
        ),
        audit_store=audit_store,
    )

    client = TestClient(
        app
    )

    response = submit_investigation(
        client
    )

    assert response.status_code == 200

    records = (
        audit_store.list_by_alert_id(
            "ALT-API-001"
        )
    )

    failed_records = [
        record
        for record in records
        if (
            record.event_type
            == "misp_enrichment_failed"
        )
    ]

    assert len(
        failed_records
    ) == 1

    record = failed_records[0]

    assert (
        record.details["error"]
        == "MISP unavailable"
    )

    assert (
        record.details[
            "queried_indicators"
        ]
        == [
            "203.0.113.10",
        ]
    )