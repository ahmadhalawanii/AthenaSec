import pytest
"""POST /api/v1/analyze needs a signed-in operator."""

from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from tests.conftest import ANALYZE_HEADERS
from tests.test_api import FakeInvestigationGraph

# POST /api/v1/analyze needs an operator: these apps get the test identity store
pytestmark = pytest.mark.usefixtures("operator_identity_for_tests")

ALERT = {"alert_id": "ALT-AUTH-1", "source": "manual", "event_text": "Failed SSH logins.",
         "metadata": {}}


class Sessions:
    principals = {
        "reader": BrowserPrincipal("u-1", "a@x.test", "A", "Analyst", True, False, "csrf-1"),
        "noread": BrowserPrincipal("u-2", "b@x.test", "B", "Analyst", False, False, "csrf-2"),
    }

    def resolve_session(self, session):
        return self.principals.get(session)


def client(session=None):
    app = create_app(investigation_graph=FakeInvestigationGraph(),
                     investigation_store=InMemoryInvestigationStore(),
                     audit_store=InMemoryAuditStore(),
                     browser_auth_store=Sessions())
    c = TestClient(app)
    if session:
        c.cookies.set(SESSION_COOKIE_NAME, session)
    return c


def test_anonymous_request_is_refused():
    assert client().post("/api/v1/analyze", json=ALERT).status_code == 401


def test_wrong_bearer_token_is_refused():
    response = client().post("/api/v1/analyze", json=ALERT,
                             headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401


def test_operator_bearer_token_is_accepted():
    assert client().post("/api/v1/analyze", json=ALERT, headers=ANALYZE_HEADERS).status_code == 200


def test_browser_session_needs_csrf():
    assert client("reader").post("/api/v1/analyze", json=ALERT).status_code == 403
    ok = client("reader").post("/api/v1/analyze", json=ALERT,
                               headers={"X-AthenaSec-CSRF": "csrf-1"})
    assert ok.status_code == 200


def test_browser_session_without_read_permission_is_refused():
    response = client("noread").post("/api/v1/analyze", json=ALERT,
                                     headers={"X-AthenaSec-CSRF": "csrf-2"})
    assert response.status_code == 403
