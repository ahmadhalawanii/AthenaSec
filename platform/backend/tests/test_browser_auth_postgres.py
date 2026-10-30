"""Live, isolated PostgreSQL browser auth acceptance tests. No production DB use."""
import base64
import os
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.auth.web_auth import PostgresBrowserAuthStore, _totp
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore


@pytest.mark.skipif(not os.getenv('ATHENASEC_TEST_PG_URL'), reason='isolated PostgreSQL URL required')
def test_live_browser_password_mfa_cookie_revocation_and_replay(monkeypatch):
    monkeypatch.setenv('ATHENASEC_COOKIE_SECURE','false')
    suffix = uuid4().hex
    store = PostgresBrowserAuthStore(os.environ['ATHENASEC_TEST_PG_URL'], bytes.fromhex('a1'*32))
    uri = store.provision_user(
        user_id='user-'+suffix, email=suffix+'@example.test', name='Test Analyst',
        password='CorrectPassword123456!', role='Analyst', can_read=True,
        can_approve=False,
    )
    encoded = parse_qs(urlparse(uri).query)['secret'][0]
    secret = base64.b32decode(encoded + '=' * (-len(encoded) % 8))
    class UnusedGraph:
        def invoke(self, state):
            raise AssertionError('not used')
    app = create_app(investigation_graph=UnusedGraph(),
                     investigation_store=InMemoryInvestigationStore(),
                     audit_store=InMemoryAuditStore(),
                     incident_response_store=InMemoryIncidentResponseStore(),
                     browser_auth_store=store, autonomous_response_enabled=False)
    client = TestClient(app)
    bad = client.post('/api/v1/auth/login',json={'email':suffix+'@example.test','password':'bad'})
    assert bad.status_code == 401
    started = client.post('/api/v1/auth/login',json={
        'email':suffix+'@example.test','password':'CorrectPassword123456!'})
    assert started.status_code == 200
    challenge = started.json()['challenge']
    assert client.post('/api/v1/auth/mfa',json={
        'challenge':challenge,'code':'abcdef'}).status_code == 401
    otp = _totp(secret, int(time.time()//30))
    completed = client.post('/api/v1/auth/mfa',json={'challenge':challenge,'code':otp})
    assert completed.status_code == 200
    assert 'HttpOnly' in completed.headers['set-cookie']
    assert client.get('/api/v1/auth/me').status_code == 200
    assert client.post('/api/v1/auth/mfa',json={'challenge':challenge,'code':otp}).status_code == 401
    csrf = completed.json()['csrf_token']
    assert client.post('/api/v1/auth/logout',headers={'X-AthenaSec-CSRF':'wrong'}).status_code == 403
    assert client.post('/api/v1/auth/logout',headers={'X-AthenaSec-CSRF':csrf}).status_code == 200
    assert client.get('/api/v1/auth/me').status_code == 401
    started = client.post('/api/v1/auth/login',json={
        'email':suffix+'@example.test','password':'CorrectPassword123456!'})
    assert started.status_code == 200
    assert client.post('/api/v1/auth/mfa',json={
        'challenge':started.json()['challenge'],'code':otp}).status_code == 401
    store.disable_user('user-'+suffix)
    assert client.post('/api/v1/auth/login',json={
        'email':suffix+'@example.test','password':'CorrectPassword123456!'}).status_code == 401
