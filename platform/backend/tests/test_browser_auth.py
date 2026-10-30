"""M9 RED: browser sessions must not trust client roles or CSRF-free mutations."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import IncidentPolicyDecisionRecord, ProposedActionRecord
from app.services.approvals.action_approval import create_approval_request
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.auth.web_auth import (
    BrowserPrincipal, InvalidCredentials, _totp, _totp_counter, _password_hash,
)


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError('No investigation required')


class FakeBrowserStore:
    def __init__(self, *, can_approve=True, active=True):
        self.active = active
        self.can_approve = can_approve
        self.principal = BrowserPrincipal('user-7', 'user@example.test', 'Test User',
                                          'Analyst', True, can_approve, 'csrf-random-token')
        self.revoked = False

    def begin_login(self, email, password):
        if email != 'user@example.test' or password != 'CorrectPasswordForTest':
            raise InvalidCredentials('Invalid email or password')
        return 'unique-mfa-challenge-for-the-test-client-12345'

    def complete_mfa(self, challenge, code):
        if challenge != 'unique-mfa-challenge-for-the-test-client-12345' or code != '742581':
            raise InvalidCredentials('Invalid or expired authentication challenge')
        return 'session-test-opaque-secret', self.principal

    def resolve_session(self, session):
        if self.active and not self.revoked and session == 'session-test-opaque-secret':
            return self.principal
        return None

    def revoke_session(self, session):
        if session == 'session-test-opaque-secret':
            self.revoked = True


def make_client(monkeypatch, store=None):
    monkeypatch.setenv('ATHENASEC_COOKIE_SECURE', 'false')
    response_store = InMemoryIncidentResponseStore()
    app = create_app(
        investigation_graph=UnusedGraph(),
        investigation_store=InMemoryInvestigationStore(),
        audit_store=InMemoryAuditStore(),
        incident_response_store=response_store,
        browser_auth_store=store or FakeBrowserStore(),
        autonomous_response_enabled=False,
        operator_control_key='test-operator-key',
    )
    return TestClient(app), response_store


def seed_approval(store):
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    action = ProposedActionRecord(
        proposed_action_id='PACT-M9', incident_id='INC-M9', investigation_id='INV-M9',
        action_type='block_ip', target_type='ip', target='203.0.113.10',
        parameters={'duration_minutes': 480}, reversible=True,
        rollback_action_type='unblock_ip', rollback_parameters={},
        reason='Test approval', proposed_at=now,
    )
    policy = IncidentPolicyDecisionRecord(
        decision_id='PDEC-M9', incident_id=action.incident_id,
        proposed_action_id=action.proposed_action_id, policy_id='POL-M9',
        outcome='APPROVAL_REQUIRED', reason='Requires human approval', decided_at=now,
    )
    pending = create_approval_request(
        proposed_action=action, policy_decision=policy, requested_at=now,
        expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
    )
    store.save_proposed_action(action)
    store.save_policy_decision(policy)
    store.save_approval_request(pending)
    return pending


def login(client):
    result = client.post('/api/v1/auth/login', json={
        'email': 'user@example.test', 'password': 'CorrectPasswordForTest',
    })
    assert result.status_code == 200
    assert result.json()['challenge']
    result = client.post('/api/v1/auth/mfa', json={
        'challenge': result.json()['challenge'], 'code': '742581',
    })
    assert result.status_code == 200
    return result.json()['csrf_token']


def test_browser_login_requires_password_and_mfa(monkeypatch):
    client, _ = make_client(monkeypatch)
    assert client.get('/api/v1/auth/me').status_code == 401
    wrong = client.post('/api/v1/auth/login', json={
        'email': 'user@example.test', 'password': 'bad-password',
    })
    assert wrong.status_code == 401
    login(client)
    me = client.get('/api/v1/auth/me')
    assert me.status_code == 200
    assert me.json()['user']['role'] == 'Analyst'
    assert me.json()['user']['email'] == 'user@example.test'
    assert me.json()['csrf_token'] == 'csrf-random-token'
    assert 'HttpOnly' in client.post('/api/v1/auth/mfa', json={
        'challenge': 'unique-mfa-challenge-for-the-test-client-12345', 'code': '742581',
    }).headers.get('set-cookie', '')


def test_session_logout_requires_csrf_and_revokes(monkeypatch):
    store = FakeBrowserStore()
    client, _ = make_client(monkeypatch, store)
    csrf = login(client)
    assert client.post('/api/v1/auth/logout').status_code == 403
    assert client.post('/api/v1/auth/logout', headers={'X-AthenaSec-CSRF':'wrong'}).status_code == 403
    assert client.post('/api/v1/auth/logout', headers={'X-AthenaSec-CSRF':csrf}).status_code == 200
    assert client.get('/api/v1/auth/me').status_code == 401


def test_browser_reader_cannot_approve(monkeypatch):
    client, response_store = make_client(monkeypatch, FakeBrowserStore(can_approve=False))
    approval = seed_approval(response_store)
    csrf = login(client)
    url = f'/api/v1/approvals/{approval.approval_id}/decision'
    result = client.post(url, headers={'X-AthenaSec-CSRF':csrf},
                         json={'decision':'APPROVED', 'reason':'Reviewed'})
    assert result.status_code == 403
    assert response_store.get_approval_request(approval.approval_id).status == 'PENDING'


def test_browser_approval_requires_csrf_and_trusted_identity(monkeypatch):
    client, response_store = make_client(monkeypatch)
    approval = seed_approval(response_store)
    csrf = login(client)
    endpoint = f'/api/v1/approvals/{approval.approval_id}/decision'
    assert client.post(endpoint, json={'decision':'APPROVED','reason':'Review'}).status_code == 403
    assert response_store.get_approval_request(approval.approval_id).status == 'PENDING'
    result = client.post(endpoint, headers={'X-AthenaSec-CSRF':csrf},
                         json={'decision':'REJECTED','reason':'Unsafe', 'decided_by':'fake-admin'})
    # Client-supplied decided_by must never override backend identity.
    assert result.status_code == 200
    assert result.json()['decided_by'] == 'user-7'


def test_disabled_session_immediately_invalid(monkeypatch):
    store = FakeBrowserStore()
    client, _ = make_client(monkeypatch, store)
    login(client)
    store.active = False
    assert client.get('/api/v1/auth/me').status_code == 401


def test_known_totp_vector_and_no_replay():
    secret = b'12345678901234567890'
    assert _totp(secret, 1) == '287082'
    now = datetime.fromtimestamp(59, timezone.utc)
    assert _totp_counter(secret, '287082', -1, now) == 1
    assert _totp_counter(secret, '287082', 1, now) is None


def test_password_hash_salted():
    assert _password_hash('long password',b'one') != _password_hash('long password',b'two')
