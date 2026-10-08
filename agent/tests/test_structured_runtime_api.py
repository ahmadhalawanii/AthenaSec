from datetime import (
    datetime,
    timezone,
)

from fastapi.testclient import (
    TestClient,
)

from app.graph.graph import (
    build_investigation_graph,
)
from app.main import create_app
from app.schemas import (
    AlertAnalysis,
    AttackPrediction,
    ResponseActionProposal,
    StructuredResponseProposal,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
)
from app.services.audit_store import (
    InMemoryAuditStore,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
)


RAW_ALERT = {
    "timestamp": (
        "2026-10-09T12:00:00+00:00"
    ),
    "rule": {
        "level": 10,
        "description": (
            "Multiple SSH failures."
        ),
        "id": "5712",
        "frequency": 8,
        "groups": [
            "authentication_failures",
            "sshd",
        ],
    },
    "agent": {
        "id": "007",
        "name": "workstation-07",
    },
    "id": "M6-RUNTIME-001",
    "full_log": (
        "Failed password for root from "
        "203.0.113.10 port 55122 ssh2"
    ),
    "data": {
        "srcip": "203.0.113.10",
        "dstuser": "root",
        "srcport": "55122",
        "dstport": "22",
    },
    "location": "/var/log/auth.log",
}


class FakeClassifier:
    def classify(
        self,
        alert,
    ):
        return AttackPrediction(
            classification="brute_force",
            confidence=0.98,
            model_version="m6-test",
        )


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        action,
    ):
        self.calls.append(action)

        return StructuredExecutorResult(
            message="Blocked.",
            details={},
        )


class FakeVerifier:
    def __init__(
        self,
        status="SUCCESS",
    ):
        self.status = status
        self.calls = []

    def verify(
        self,
        action,
        action_result,
    ):
        self.calls.append(
            action
        )

        return StructuredVerificationObservation(
            status=self.status,
            message="Verified.",
            details={},
        )


class FakeRollback:
    def __init__(self):
        self.calls = []

    def rollback(
        self,
        action,
    ):
        self.calls.append(action)

        return StructuredExecutorResult(
            message="Rolled back.",
            details={},
        )


def make_analysis():
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.98,
        severity_assessment="high",
        summary="Brute force verified.",
        evidence_refs=["E001"],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_proposal(
    duration_minutes,
):
    return StructuredResponseProposal(
        summary="Contain source.",
        actions=[
            ResponseActionProposal(
                action_type="block_ip",
                target_type="ip",
                target="203.0.113.10",
                duration_minutes=(
                    duration_minutes
                ),
                reason="Contain source.",
                evidence_refs=["E001"],
            )
        ],
    )


def make_runtime(
    *,
    duration_minutes=30,
    verification_status="SUCCESS",
    include_verifier=True,
    autonomous_response_enabled=True,
    response_mode="SUPERVISED",
):
    graph = build_investigation_graph(
        analyzer=lambda context: (
            make_analysis()
        ),
        response_proposer=(
            lambda context: (
                make_proposal(
                    duration_minutes
                )
            )
        ),
        action_policy_clock=(
            lambda: datetime.now(
                timezone.utc
            )
        ),
    )

    investigation_store = (
        InMemoryInvestigationStore()
    )

    response_store = (
        InMemoryIncidentResponseStore()
    )

    audit_store = (
        InMemoryAuditStore()
    )

    executor = FakeExecutor()

    verifier = (
        FakeVerifier(
            verification_status
        )
        if include_verifier
        else None
    )

    rollback = FakeRollback()

    app = create_app(
        investigation_graph=graph,
        investigation_store=(
            investigation_store
        ),
        audit_store=audit_store,
        incident_response_store=(
            response_store
        ),
        ml_classifier=FakeClassifier(),
        wazuh_ingest_key="m6-key",
        autonomous_response_enabled=(
            autonomous_response_enabled
        ),
        response_mode=response_mode,
        structured_action_executor=(
            executor
        ),
        structured_action_verifier=(
            verifier
        ),
        structured_rollback_executor=(
            rollback
        ),
    )

    return (
        TestClient(app),
        response_store,
        audit_store,
        executor,
        verifier,
        rollback,
    )


def submit(client):
    return client.post(
        "/api/v1/integrations/wazuh/alerts",
        headers={
            "X-AthenaSec-Integration-Key": (
                "m6-key"
            )
        },
        json=RAW_ALERT,
    )


def test_auto_allowed_runtime_executes_and_verifies():
    (
        client,
        response_store,
        audit_store,
        executor,
        verifier,
        rollback,
    ) = make_runtime()

    response = submit(client)

    assert response.status_code == 200

    incident_id = (
        response.json()["incident_id"]
    )

    assert len(executor.calls) == 1
    assert len(verifier.calls) == 1
    assert rollback.calls == []

    assert (
        response_store
        .list_incident_cases(
            incident_id
        )
        == []
    )

    events = {
        item.event_type
        for item
        in audit_store
        .list_by_incident_id(
            incident_id
        )
    }

    assert (
        "structured_cortex_execution_completed"
        in events
    )

    assert (
        "action_verification_completed"
        in events
    )


def test_failed_verification_rolls_back_and_opens_case():
    (
        client,
        response_store,
        audit_store,
        executor,
        verifier,
        rollback,
    ) = make_runtime(
        verification_status="FAILED"
    )

    response = submit(client)

    assert response.status_code == 200

    incident_id = (
        response.json()["incident_id"]
    )

    assert len(executor.calls) == 1
    assert len(verifier.calls) == 1
    assert len(rollback.calls) == 1

    assert len(
        response_store
        .list_incident_cases(
            incident_id
        )
    ) == 1

    events = {
        item.event_type
        for item
        in audit_store
        .list_by_incident_id(
            incident_id
        )
    }

    assert (
        "action_rollback_completed"
        in events
    )

    assert "case_created" in events


def test_approved_action_enters_same_structured_runtime():
    (
        client,
        _,
        _,
        executor,
        verifier,
        rollback,
    ) = make_runtime(
        duration_minutes=480
    )

    initial = submit(client)

    assert initial.status_code == 200

    body = initial.json()

    approval_id = (
        body["approval_requests"][0]
        ["approval_id"]
    )

    assert executor.calls == []

    decision = client.post(
        (
            "/api/v1/approvals/"
            f"{approval_id}/decision"
        ),
        json={
            "decision": "APPROVED",
            "decided_by": "analyst-001",
            "reason": (
                "Approved temporary "
                "containment."
            ),
        },
    )

    assert decision.status_code == 200

    assert (
        decision.json()["status"]
        == "APPROVED"
    )

    assert len(executor.calls) == 1
    assert len(verifier.calls) == 1
    assert rollback.calls == []


def test_missing_verifier_fails_closed_before_cortex():
    (
        client,
        response_store,
        _,
        executor,
        _,
        rollback,
    ) = make_runtime(
        include_verifier=False
    )

    response = submit(client)

    assert response.status_code == 200

    incident_id = (
        response.json()["incident_id"]
    )

    assert executor.calls == []
    assert rollback.calls == []

    assert len(
        response_store
        .list_incident_cases(
            incident_id
        )
    ) == 1


def test_shadow_mode_does_not_execute_cortex():
    (
        client,
        response_store,
        audit_store,
        executor,
        verifier,
        rollback,
    ) = make_runtime(
        response_mode="SHADOW"
    )

    response = submit(
        client
    )

    assert response.status_code == 200

    incident_id = (
        response.json()["incident_id"]
    )

    assert executor.calls == []
    assert verifier.calls == []
    assert rollback.calls == []

    assert (
        response_store
        .list_incident_cases(
            incident_id
        )
        == []
    )

    events = {
        item.event_type
        for item
        in audit_store
        .list_by_incident_id(
            incident_id
        )
    }

    assert (
        "structured_response_shadowed"
        in events
    )


def test_runtime_status_reports_mode_and_kill_switch():
    (
        client,
        _,
        _,
        _,
        _,
        _,
    ) = make_runtime(
        response_mode="SHADOW",
        autonomous_response_enabled=False,
    )

    response = client.get(
        "/api/v1/runtime/status"
    )

    assert response.status_code == 200

    assert response.json() == {
        "response_mode": "SHADOW",
        "autonomous_response_enabled": False,
        "structured_runtime_configured": True,
        "cortex_execution_possible": False,
    }
