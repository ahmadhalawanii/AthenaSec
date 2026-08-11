from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
)

from app.services.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
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
                    "High-Risk Brute Force Review"
                ),
                matched=True,
                approval_type="analyst",
                execution_mode="dry_run",
                actions=[
                    "block_ip",
                    "notify_administrator",
                    "create_case",
                ],
                reason="Analyst approval required.",
            ),
            "response_plan": ResponsePlan(
                policy_id="POL-BF-HIGH",
                actions=[
                    "block_ip",
                    "notify_administrator",
                    "create_case",
                ],
                approval_type="analyst",
                execution_mode="dry_run",
                status="pending_approval",
                reason="Analyst approval required.",
            ),
            "investigation_iteration": 0,
            "status": "complete",
        }


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
        data["response_plan"]["status"]
        == "pending_approval"
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
        == "pending_approval"
    )


def test_analyst_can_approve_investigation():
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
            "reason": (
                "Evidence supports containment."
            ),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert (
        data["response_plan"]["status"]
        == "approved"
    )

    stored_response = client.get(
        "/api/v1/investigations/ALT-API-001"
    )

    assert stored_response.status_code == 200

    assert (
        stored_response.json()[
            "response_plan"
        ]["status"]
        == "approved"
    )


def test_missing_investigation_returns_404():
    client = make_client()

    response = client.get(
        "/api/v1/investigations/ALT-MISSING"
    )

    assert response.status_code == 404


def test_second_analyst_decision_is_rejected():
    client = make_client()

    submit_investigation(
        client
    )

    first_response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/decision"
        ),
        json={
            "decision": "approve",
            "analyst_id": "analyst-001",
            "reason": "Approved.",
        },
    )

    assert first_response.status_code == 200

    second_response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/decision"
        ),
        json={
            "decision": "reject",
            "analyst_id": "analyst-002",
            "reason": "Reject after approval.",
        },
    )

    assert second_response.status_code == 409

def test_approved_investigation_can_execute_dry_run():
    client = make_client()

    submit_investigation(
        client
    )

    approval_response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/decision"
        ),
        json={
            "decision": "approve",
            "analyst_id": "analyst-001",
            "reason": "Containment approved.",
        },
    )

    assert approval_response.status_code == 200

    response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/execute"
        )
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "completed"

    assert (
        data["execution_mode"]
        == "dry_run"
    )

    assert len(
        data["action_results"]
    ) == 3

    assert all(
        result["status"] == "simulated"
        for result in data["action_results"]
    )

    stored_response = client.get(
        "/api/v1/investigations/ALT-API-001"
    )

    assert stored_response.status_code == 200

    stored_data = stored_response.json()

    assert (
        stored_data["execution_result"]["status"]
        == "completed"
    )


def test_pending_investigation_cannot_execute():
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

    assert response.status_code == 409


def test_missing_investigation_cannot_execute():
    client = make_client()

    response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-MISSING/execute"
        )
    )

    assert response.status_code == 404


def test_repeated_execute_returns_saved_result():
    client = make_client()

    submit_investigation(
        client
    )

    client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/decision"
        ),
        json={
            "decision": "approve",
            "analyst_id": "analyst-001",
            "reason": "Approved.",
        },
    )

    first_response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/execute"
        )
    )

    second_response = client.post(
        (
            "/api/v1/investigations/"
            "ALT-API-001/execute"
        )
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    assert (
        second_response.json()
        == first_response.json()
    )

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

    assert (
        stored_response.json()["alert_id"]
        == "ALT-API-001"
    )