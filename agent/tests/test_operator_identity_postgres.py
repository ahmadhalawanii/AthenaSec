"""M8 PostgreSQL acceptance tests for the AthenaSec human-approval identity gate.

Run ONLY with ATHENASEC_TEST_PG_URL pointing at a disposable PostgreSQL
instance on loopback with database named athenasec_test.
These tests create dedicated random test operators and expire/revoke only those
credentials; never run against an existing production database.
"""

from __future__ import annotations

import hashlib
import os
from urllib.parse import urlparse
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit_store import InMemoryAuditStore
from app.services.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigation_store import InMemoryInvestigationStore
from app.services.operator_identity import PostgresOperatorIdentityStore
from tests.test_operator_identity_gate import UnusedGraph, seed


@pytest.fixture(scope="module")
def pg_store():
    url = os.getenv("ATHENASEC_TEST_PG_URL")
    if not url:
        pytest.skip("ATHENASEC_TEST_PG_URL is not configured")

    parsed = urlparse(url)
    if parsed.hostname not in {"localhost", "127.0.0.1"} or parsed.path != "/athenasec_test":
        pytest.fail(
            "Refusing to exercise operator credentials outside an isolated "
            "loopback athenaSec_test database"
        )
    return PostgresOperatorIdentityStore(url)


def _operator() -> str:
    return "m8-test-" + uuid4().hex


def test_postgres_credentials_store_only_digests_and_enforce_permissions(pg_store):
    operator = _operator()
    token = pg_store.provision(operator_id=operator, can_approve=False, ttl_hours=1)

    assert token.startswith("aso_")
    principal = pg_store.resolve(token)
    assert principal is not None
    assert principal.operator_id == operator
    assert principal.can_read_approvals is True
    assert principal.can_decide_approvals is False
    assert pg_store.resolve("aso_invalid-token") is None

    with psycopg.connect(pg_store.database_url) as connection:
        digest, stored_id = connection.execute(
            "SELECT token_digest, operator_id FROM athenasec_operator_credentials "
            "WHERE operator_id=%s",
            (operator,),
        ).fetchone()
    assert stored_id == operator
    assert digest == hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert token != digest


def test_postgres_reprovision_revokes_prior_credentials_and_disable(pg_store):
    operator = _operator()
    original = pg_store.provision(operator_id=operator, can_approve=True, ttl_hours=1)
    assert pg_store.resolve(original).can_decide_approvals is True

    replacement = pg_store.provision(operator_id=operator, can_approve=False, ttl_hours=1)
    assert pg_store.resolve(original) is None
    assert pg_store.resolve(replacement).can_decide_approvals is False

    pg_store.disable(operator)
    assert pg_store.resolve(replacement) is None


def test_postgres_expiry_is_checked_on_each_request(pg_store):
    operator = _operator()
    token = pg_store.provision(operator_id=operator, can_approve=True, ttl_hours=1)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    assert pg_store.resolve(token) is not None

    with psycopg.connect(pg_store.database_url) as connection:
        connection.execute(
            "UPDATE athenasec_operator_credentials "
            "SET expires_at=CURRENT_TIMESTAMP - INTERVAL '1 second' "
            "WHERE token_digest=%s",
            (digest,),
        )
    assert pg_store.resolve(token) is None


def test_postgres_operator_identity_controls_real_approval_endpoint(pg_store):
    response_store = InMemoryIncidentResponseStore()
    audit_store = InMemoryAuditStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=InMemoryInvestigationStore(),
        incident_response_store=response_store,
        audit_store=audit_store,
        operator_control_key="test-operator-control-key",
        operator_identity_store=pg_store,
        autonomous_response_enabled=False,
    )
    approval = seed(response_store)
    endpoint = f"/api/v1/approvals/{approval.approval_id}/decision"
    client = TestClient(app)
    body = {
        "decision": "REJECTED",
        "reason": "Containment not justified by the evidence",
        "decided_by": "spoofed-administrator",
    }

    assert client.post(endpoint, json=body, headers={
        "X-AthenaSec-Operator-Key": "test-operator-control-key"
    }).status_code == 401
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"

    reader = pg_store.provision(operator_id=_operator(), can_approve=False, ttl_hours=1)
    assert client.post(endpoint, json=body, headers={
        "Authorization": "Bearer " + reader
    }).status_code == 403
    assert response_store.get_approval_request(approval.approval_id).status == "PENDING"

    operator = _operator()
    approver = pg_store.provision(operator_id=operator, can_approve=True, ttl_hours=1)
    response = client.post(endpoint, json=body, headers={
        "Authorization": "Bearer " + approver
    })
    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert response.json()["decided_by"] == operator
    assert response_store.get_approval_request(approval.approval_id).decided_by == operator
    assert len(response_store.list_incident_cases(approval.incident_id)) == 1
