"""Configuration (admin), personal settings, profile and password change."""

import os
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.audit.operator_audit_store import InMemoryOperatorAuditStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, InvalidCredentials
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.runtime.settings_store import (
    InMemorySettingsStore,
    SettingsVersionConflict,
    SQLiteSettingsStore,
)
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from tests.test_user_admin import FakeAccounts, UnusedGraph

ADMIN = {"X-AthenaSec-CSRF": "csrf-admin"}
ANALYST = {"X-AthenaSec-CSRF": "csrf-analyst"}


class Accounts(FakeAccounts):
    def __init__(self):
        super().__init__()
        self.passwords = {"analyst-1": "OldPassword-123456"}

    def change_password(self, user_id, current, new):
        if self.passwords.get(user_id) != current:
            raise InvalidCredentials("The current password is not correct.")
        if len(new) < 14:
            raise ValueError("The new password must be at least 14 characters.")
        self.passwords[user_id] = new


class Harness:
    def __init__(self, session="admin"):
        self.accounts = Accounts()
        self.settings = InMemorySettingsStore()
        self.audit = InMemoryOperatorAuditStore()
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            operator_audit_store=self.audit,
            browser_auth_store=self.accounts,
            settings_store=self.settings,
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)
        self.client.cookies.set(SESSION_COOKIE_NAME, session)


def configuration(**changes):
    body = {
        "organization": "AthenaSec SOC", "workspace": "Production",
        "correlation_window_minutes": 15, "critical_risk_threshold": 90,
        "logging_destination": "OpenSearch", "logging_mode": "Realtime",
        "hot_storage_days": 30, "audit_retention_days": 365,
        "critical_alert_notification": "Email + In-App", "base_version": 0,
    }
    body.update(changes)
    return body


# ---- configuration ---------------------------------------------------------

def test_configuration_starts_on_defaults_for_anyone_signed_in():
    response = Harness("analyst").client.get("/api/v1/configuration")

    assert response.status_code == 200
    assert response.json()["version"] == 0 and response.json()["correlation_window_minutes"] == 15


def test_admin_saves_configuration_and_changes_are_audited():
    h = Harness()

    saved = h.client.put("/api/v1/configuration", headers=ADMIN,
                         json=configuration(correlation_window_minutes=30, workspace="Staging"))

    assert saved.status_code == 200
    assert saved.json()["version"] == 1 and saved.json()["correlation_window_minutes"] == 30
    assert h.client.get("/api/v1/configuration").json()["workspace"] == "Staging"
    event = h.audit.list_events(event_type="configuration_updated")[0]
    assert event.detail == {"workspace": {"from": "Production", "to": "Staging"},
                            "correlation_window_minutes": {"from": 15, "to": 30}}


def test_configuration_rejects_out_of_range_stale_and_non_admin():
    h = Harness()

    assert h.client.put("/api/v1/configuration", headers=ADMIN,
                        json=configuration(critical_risk_threshold=150)).status_code == 422
    h.client.put("/api/v1/configuration", headers=ADMIN, json=configuration())
    assert h.client.put("/api/v1/configuration", headers=ADMIN,
                        json=configuration(base_version=0)).status_code == 409
    assert Harness("analyst").client.put("/api/v1/configuration", headers=ANALYST,
                                         json=configuration()).status_code == 403


def test_saved_correlation_window_reaches_the_correlator(monkeypatch):
    import app.main as main
    seen = {}

    def fake_correlate(**kwargs):
        seen["window"] = kwargs["window"]
        raise RuntimeError("stop here")

    monkeypatch.setattr(main, "correlate_or_create_incident", fake_correlate)

    class Classifier:
        def classify(self, alert):
            from app.schemas import AttackPrediction
            return AttackPrediction(classification="brute_force", confidence=0.9, model_version="t")

    settings = InMemorySettingsStore()
    settings.put("configuration", {"correlation_window_minutes": 42}, base_version=0, updated_by="a")
    app = create_app(investigation_graph=UnusedGraph(), investigation_store=InMemoryInvestigationStore(),
                     audit_store=InMemoryAuditStore(), settings_store=settings,
                     ml_classifier=Classifier(), wazuh_ingest_key="k")
    from tests.test_wazuh_ingestion import RAW_WAZUH_ALERT
    TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/integrations/wazuh/alerts", json=RAW_WAZUH_ALERT,
        headers={"X-AthenaSec-Integration-Key": "k"})

    assert seen["window"] == timedelta(minutes=42)


# ---- personal settings -----------------------------------------------------

def test_settings_are_per_user():
    h = Harness("analyst")

    assert h.client.get("/api/v1/me/settings").json()["theme"] == "Dark Enterprise"
    saved = h.client.put("/api/v1/me/settings", headers=ANALYST,
                         json={**h.client.get("/api/v1/me/settings").json(), "theme": "High Contrast"})
    assert saved.status_code == 200
    assert h.client.get("/api/v1/me/settings").json()["theme"] == "High Contrast"
    other = Harness("admin")
    other.settings._rows = h.settings._rows
    assert other.client.get("/api/v1/me/settings").json()["theme"] == "Dark Enterprise"


def test_settings_need_csrf_and_valid_values():
    h = Harness("analyst")

    assert h.client.put("/api/v1/me/settings", json={"theme": "High Contrast"}).status_code == 403
    assert h.client.put("/api/v1/me/settings", headers=ANALYST,
                        json={"theme": "Neon"}).status_code == 422


# ---- profile and password --------------------------------------------------

def test_profile_reads_and_updates_own_account_only():
    h = Harness("analyst")

    assert h.client.get("/api/v1/me/profile").json()["display_name"] == "Ana Lyst"
    saved = h.client.put("/api/v1/me/profile", headers=ANALYST, json={
        "display_name": "Ana L.", "email": "analyst@x.test", "department": "SOC",
        "phone": "+971", "timezone": "Europe/London"})

    assert saved.status_code == 200
    assert saved.json()["display_name"] == "Ana L." and saved.json()["timezone"] == "Europe/London"
    assert h.accounts.users["analyst-1"].role == "Analyst"
    assert h.audit.list_events(event_type="profile_updated")[0].target == "analyst-1"


def test_profile_email_must_be_unique():
    h = Harness("analyst")

    response = h.client.put("/api/v1/me/profile", headers=ANALYST, json={
        "display_name": "Ana", "email": "admin@x.test"})

    assert response.status_code == 409


def test_change_password():
    h = Harness("analyst")

    wrong = h.client.post("/api/v1/me/password", headers=ANALYST,
                          json={"current_password": "nope", "new_password": "BrandNewPassword-1"})
    short = h.client.post("/api/v1/me/password", headers=ANALYST,
                          json={"current_password": "OldPassword-123456", "new_password": "short"})
    ok = h.client.post("/api/v1/me/password", headers=ANALYST,
                       json={"current_password": "OldPassword-123456", "new_password": "BrandNewPassword-1"})

    assert wrong.status_code == 400 and short.status_code == 422 and ok.status_code == 204
    assert h.accounts.passwords["analyst-1"] == "BrandNewPassword-1"
    assert len(h.audit.list_events(event_type="password_changed")) == 1


# ---- the settings store ----------------------------------------------------

@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemorySettingsStore() if request.param == "memory" else SQLiteSettingsStore(tmp_path / "s.db")


def test_settings_store_versions(store):
    assert store.get("configuration") is None
    first = store.put("configuration", {"a": 1}, base_version=0, updated_by="u")
    second = store.put("configuration", {"a": 2}, base_version=1, updated_by="u")

    assert (first.version, second.version) == (1, 2)
    assert store.get("configuration").document == {"a": 2}
    with pytest.raises(SettingsVersionConflict):
        store.put("configuration", {"a": 3}, base_version=1, updated_by="u")
    assert store.put("user-settings:x", {"b": 1}, base_version=None, updated_by="x").version == 1


@pytest.mark.skipif(not os.getenv("ATHENASEC_TEST_PG_URL"), reason="ATHENASEC_TEST_PG_URL is not configured")
def test_postgres_change_password():
    from app.services.auth.web_auth import PostgresBrowserAuthStore

    accounts = PostgresBrowserAuthStore(os.environ["ATHENASEC_TEST_PG_URL"], bytes.fromhex("b2" * 32))
    user, password, _ = accounts.create_user(name="Pw", email=f"pw-{uuid4().hex[:8]}@x.test", role="Analyst")

    with pytest.raises(InvalidCredentials):
        accounts.change_password(user.user_id, "wrong", "AnotherPassword-123")
    accounts.change_password(user.user_id, password, "AnotherPassword-123")
    accounts.begin_login(user.email, "AnotherPassword-123")
    accounts.delete_user(user.user_id)


def test_activity_lists_only_my_events():
    h = Harness("analyst")
    seen = {}

    def list_auth_events(user_id, *, limit):
        seen["user"] = user_id
        from datetime import datetime, timezone
        return [("mfa_verified_session_started", datetime(2026, 10, 25, tzinfo=timezone.utc))]

    h.accounts.list_auth_events = list_auth_events
    response = h.client.get("/api/v1/me/activity")

    assert response.status_code == 200 and seen["user"] == "analyst-1"
    assert response.json()["items"][0]["event_type"] == "mfa_verified_session_started"


@pytest.mark.skipif(not os.getenv("ATHENASEC_TEST_PG_URL"), reason="ATHENASEC_TEST_PG_URL is not configured")
def test_postgres_auth_events_are_per_user():
    from app.services.auth.web_auth import PostgresBrowserAuthStore

    accounts = PostgresBrowserAuthStore(os.environ["ATHENASEC_TEST_PG_URL"], bytes.fromhex("b2" * 32))
    user, password, _ = accounts.create_user(name="Act", email=f"act-{uuid4().hex[:8]}@x.test", role="Analyst")
    accounts.begin_login(user.email, password)

    events = [event for event, _ in accounts.list_auth_events(user.user_id)]

    assert events[:2] == ["password_accepted", "user_created"]
    accounts.delete_user(user.user_id)
