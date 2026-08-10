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
    app = create_app(
        investigation_graph=FakeInvestigationGraph()
    )

    return TestClient(app)


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

    response = client.post(
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