"""GET /api/v1/system/health, GET /api/v1/system/events and the health event store.

Probes are injected fakes and a fixture blocks real sockets, so nothing here touches the
network. All records are built in these tests; the app ships none.
"""

import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from tests import network_guard
from fastapi.testclient import TestClient

import app.services.health.health_probes as health_module
from app.main import create_app
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.health.health_event_store import (
    HealthSchemaNotReady,
    InMemoryHealthEventStore,
    PostgresHealthEventStore,
    SQLiteHealthEventStore,
    should_record,
)
from app.services.health.health_probes import CATALOG, NOT_PROBED_DETAIL, ProbeResult
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal

START = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
LATER = START + timedelta(hours=1)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    network_guard.install(monkeypatch)


class Clock:
    def __init__(self, now):
        self.now = now


class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by health tests.")


class SessionStore:
    def resolve_session(self, session):
        if session == "analyst":
            return BrowserPrincipal("analyst-1", "n@example.test", "Analyst", "Analyst",
                                    True, False, "csrf")
        return None


PROBED = [d.check_key for d in CATALOG if d.probed]


def all_up(latency=12):
    return {key: (lambda key=key: ProbeResult("up", latency, None, f"https://{key}.internal:443"))
            for key in PROBED}


class Harness:
    def __init__(self, monkeypatch, probes=None, *, event_store=None, auth="bearer",
                 can_read=True, started_at=START, now=LATER):
        self.clock = Clock(started_at)
        monkeypatch.setattr(health_module, "utc_now", lambda: self.clock.now)
        self.events = event_store or InMemoryHealthEventStore()
        self.probes = all_up() if probes is None else probes
        identity = InMemoryOperatorIdentityStore()
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            health_event_store=self.events,
            health_probes=self.probes,
            browser_auth_store=SessionStore(),
            operator_identity_store=identity,
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)
        self.clock.now = now

        if auth == "bearer":
            token = identity.provision(operator_id="analyst-001", can_read=can_read)
            self.client.headers["Authorization"] = "Bearer " + token
        elif auth == "analyst":
            self.client.cookies.set(SESSION_COOKIE_NAME, "analyst")

    def health(self):
        return self.client.get("/api/v1/system/health")

    def events_list(self, query=""):
        return self.client.get("/api/v1/system/events" + query)

    def service(self, key):
        return {s["check_key"]: s for s in self.health().json()["services"]}[key]


SERVICE_FIELDS = {"check_key", "name", "group", "category", "status", "endpoint", "latency_ms",
                  "checked_at", "detail", "uptime_seconds", "uptime_percent", "last_change_at"}
UNPROBED = ["opensearch", "suricata", "langgraph", "docker_engine", "wazuh_dashboard"]


# ---- the ten services; nothing invented -----------------------------------

def test_lists_the_ten_website_services_in_order(monkeypatch):
    body = Harness(monkeypatch).health().json()

    assert [s["check_key"] for s in body["services"]] == [d.check_key for d in CATALOG]
    assert len(body["services"]) == 10
    assert all(set(s) == SERVICE_FIELDS for s in body["services"])
    assert all(s["group"] and s["category"] and s["name"] for s in body["services"])


@pytest.mark.parametrize("key", UNPROBED)
def test_services_the_agent_does_not_probe_are_unconfigured_with_nothing_invented(monkeypatch, key):
    service = Harness(monkeypatch).service(key)

    assert service["status"] == "unconfigured" and service["detail"] == NOT_PROBED_DETAIL
    for field in ("endpoint", "latency_ms", "checked_at", "uptime_seconds", "uptime_percent",
                  "last_change_at"):
        assert service[field] is None


def test_unprobed_services_stay_unconfigured_even_if_a_probe_is_injected_for_them(monkeypatch):
    probes = all_up()
    probes["suricata"] = lambda: ProbeResult("up", 1)

    assert Harness(monkeypatch, probes).service("suricata")["status"] == "unconfigured"


def test_uptime_fields_are_always_null_even_for_healthy_services(monkeypatch):
    for service in Harness(monkeypatch).health().json()["services"]:
        assert service["uptime_seconds"] is None and service["uptime_percent"] is None


def test_probed_service_reports_what_the_probe_returned(monkeypatch):
    service = Harness(monkeypatch).service("ollama")

    assert service["status"] == "up" and service["latency_ms"] == 12
    assert service["endpoint"] == "https://ollama.internal:443"
    assert service["checked_at"].startswith("2026-09-01T09:00")
    assert service["name"] == "Ollama"


def test_a_probed_service_with_no_probe_is_unconfigured_not_invented(monkeypatch):
    probes = all_up()
    del probes["misp"]

    service = Harness(monkeypatch, probes).service("misp")

    assert service["status"] == "unconfigured" and service["detail"] == "No probe is configured."


def test_summary_counts_every_status(monkeypatch):
    probes = all_up()
    probes["postgres"] = lambda: ProbeResult("down", None, "Connection failed.")
    probes["ollama"] = lambda: ProbeResult("degraded", 90, "Slow.")
    probes["cortex"] = lambda: ProbeResult("unconfigured", None, "off")

    summary = Harness(monkeypatch, probes).health().json()["summary"]

    assert summary == {"up": 2, "degraded": 1, "down": 1, "starting": 0, "unconfigured": 6}
    assert sum(summary.values()) == 10


def test_down_right_after_start_is_reported_as_starting(monkeypatch):
    probes = all_up()
    probes["postgres"] = lambda: ProbeResult("down", None, "Connection failed.")

    h = Harness(monkeypatch, probes, now=START + timedelta(seconds=20))

    assert h.service("postgres")["status"] == "starting"


def test_slow_probe_is_degraded(monkeypatch):
    h = Harness(monkeypatch, {**all_up(), "ollama": lambda: ProbeResult("up", 5000)})

    assert h.service("ollama")["status"] == "degraded"


def test_a_probe_that_raises_does_not_break_the_page(monkeypatch):
    def broken():
        raise RuntimeError("secret internals")

    h = Harness(monkeypatch, {**all_up(), "misp": broken})
    response = h.health()

    assert response.status_code == 200
    assert h.service("misp")["status"] == "down" and h.service("misp")["detail"] == "Probe failed."
    assert "secret internals" not in response.text


def test_metrics(monkeypatch):
    body = Harness(monkeypatch).health().json()

    assert body["metrics"]["process_uptime_seconds"] == 3600
    assert body["metrics"]["version"] == "0.5.0"
    assert body["metrics"]["response_mode"] in {"SHADOW", "SUPERVISED", "AUTONOMOUS"}
    assert set(body["metrics"]) == {"process_uptime_seconds", "version", "response_mode",
                                    "persistence_backend", "evidence_provider"}
    assert body["generated_at"].startswith("2026-09-01T09:00") and body["event_log"] == "ok"


def test_health_is_not_cached(monkeypatch):
    assert Harness(monkeypatch).health().headers["cache-control"] == "no-store"


# ---- events: written only on change ---------------------------------------

def test_first_up_or_unconfigured_observation_records_nothing(monkeypatch):
    h = Harness(monkeypatch)

    h.health()

    assert h.events.list_events() == []
    assert h.events_list().json() == {"total": 0, "items": [], "next_cursor": None}


def test_repeated_checks_of_an_unchanged_service_record_one_event_only(monkeypatch):
    probes = all_up()
    probes["postgres"] = lambda: ProbeResult("down", None, "Connection failed.")
    h = Harness(monkeypatch, probes)

    for _ in range(4):
        h.health()

    (event,) = h.events.list_events()
    assert (event.source, event.status, event.severity) == ("postgres", "down", "Critical")
    assert event.message == "PostgreSQL is down: Connection failed."


def test_down_then_recovery_then_degraded_are_recorded_with_severities(monkeypatch):
    state = {"result": ProbeResult("down", None, "Connection failed.")}
    h = Harness(monkeypatch, {**all_up(), "ollama": lambda: state["result"]})

    h.health()
    state["result"] = ProbeResult("up", 5)
    h.clock.now = LATER + timedelta(minutes=5)
    h.health()
    state["result"] = ProbeResult("degraded", 80, "Slow.")
    h.clock.now = LATER + timedelta(minutes=10)
    h.health()

    events = h.events.list_events()
    assert [(e.status, e.severity) for e in events] == [
        ("degraded", "Warning"), ("up", "Info"), ("down", "Critical")]
    assert [e.source for e in events] == ["ollama"] * 3


def test_last_change_at_is_the_time_of_the_event_for_the_current_status(monkeypatch):
    probes = {**all_up(), "cortex": lambda: ProbeResult("down", None, "Connection failed.")}
    h = Harness(monkeypatch, probes)

    assert h.service("cortex")["last_change_at"].startswith("2026-09-01T09:00")
    assert h.service("ollama")["last_change_at"] is None


def test_startup_failure_records_a_starting_event(monkeypatch):
    probes = {**all_up(), "postgres": lambda: ProbeResult("down", None, "Connection failed.")}
    h = Harness(monkeypatch, probes, now=START + timedelta(seconds=5))

    h.health()

    (event,) = h.events.list_events()
    assert (event.status, event.severity) == ("starting", "Info")


def test_unprobed_services_never_create_events(monkeypatch):
    h = Harness(monkeypatch, {})

    h.health()

    assert h.events.list_events() == []


# ---- events route ----------------------------------------------------------

def make_history(h):
    h.events.record_status(source="postgres", status="down", severity="Critical",
                           message="PostgreSQL is down", occurred_at=START)
    h.events.record_status(source="ollama", status="degraded", severity="Warning",
                           message="Ollama is degraded", occurred_at=START + timedelta(minutes=10))
    h.events.record_status(source="postgres", status="up", severity="Info",
                           message="PostgreSQL is up", occurred_at=START + timedelta(minutes=20))


def test_events_newest_first_with_shape(monkeypatch):
    h = Harness(monkeypatch)
    make_history(h)

    body = h.events_list().json()

    assert body["total"] == 3 and body["next_cursor"] is None
    assert [e["message"] for e in body["items"]] == [
        "PostgreSQL is up", "Ollama is degraded", "PostgreSQL is down"]
    assert set(body["items"][0]) == {"event_id", "occurred_at", "severity", "source", "status", "message"}


def test_events_filters(monkeypatch):
    h = Harness(monkeypatch)
    make_history(h)

    def messages(query):
        return [e["message"] for e in h.events_list(query).json()["items"]]

    assert messages("?severity=Critical") == ["PostgreSQL is down"]
    assert messages("?source=ollama") == ["Ollama is degraded"]
    since = (START + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    assert messages(f"?since={since}") == ["PostgreSQL is up", "Ollama is degraded"]
    until = (START + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    assert messages(f"?until={until}") == ["Ollama is degraded", "PostgreSQL is down"]
    assert messages("?severity=Warning&source=postgres") == []


def test_events_paginate_and_reject_bad_input(monkeypatch):
    h = Harness(monkeypatch)
    make_history(h)

    first = h.events_list("?limit=2").json()
    second = h.events_list("?limit=2&cursor=" + first["next_cursor"]).json()

    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert {e["event_id"] for e in first["items"]} | {e["event_id"] for e in second["items"]} == {1, 2, 3}
    assert h.events_list("?cursor=nope").status_code == 400
    assert h.events_list("?since=2026-09-02T00:00:00Z&until=2026-09-01T00:00:00Z").status_code == 400
    for query in ("?severity=Fatal", "?limit=0", "?limit=201", "?since=yesterday"):
        assert h.events_list(query).status_code == 422


# ---- access ----------------------------------------------------------------

PATHS = ["/api/v1/system/health", "/api/v1/system/events"]


@pytest.mark.parametrize("path", PATHS)
def test_requires_credentials(monkeypatch, path):
    assert Harness(monkeypatch, auth=None).client.get(path).status_code == 401


@pytest.mark.parametrize("path", PATHS)
def test_invalid_token_is_401(monkeypatch, path):
    h = Harness(monkeypatch, auth=None)

    assert h.client.get(path, headers={"Authorization": "Bearer aso_invalid"}).status_code == 401


@pytest.mark.parametrize("path", PATHS)
def test_requires_the_read_permission(monkeypatch, path):
    assert Harness(monkeypatch, can_read=False).client.get(path).status_code == 403


@pytest.mark.parametrize("path", PATHS)
def test_browser_session_can_read(monkeypatch, path):
    assert Harness(monkeypatch, auth="analyst").client.get(path).status_code == 200


def test_a_denied_request_runs_no_probes_and_records_nothing(monkeypatch):
    calls = []
    probes = {k: (lambda k=k: calls.append(k) or ProbeResult("down")) for k in PROBED}
    h = Harness(monkeypatch, probes, can_read=False)

    h.health()

    assert calls == [] and h.events.list_events() == []


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("path", PATHS)
def test_routes_take_no_writes(monkeypatch, method, path):
    assert Harness(monkeypatch).client.request(method, path, json={}).status_code == 405


# ---- event log not migrated ------------------------------------------------

class UnmigratedEventStore(InMemoryHealthEventStore):
    def _fail(self, *args, **kwargs):
        raise HealthSchemaNotReady("migrate")

    record_status = list_events = _fail


def test_health_still_works_when_the_event_log_is_not_migrated(monkeypatch):
    h = Harness(monkeypatch, event_store=UnmigratedEventStore())

    response = h.health()

    assert response.status_code == 200
    assert response.json()["event_log"] == "unavailable"
    assert h.service("ollama")["status"] == "up" and h.service("ollama")["last_change_at"] is None


def test_events_route_is_503_when_the_event_log_is_not_migrated(monkeypatch):
    response = Harness(monkeypatch, event_store=UnmigratedEventStore()).events_list()

    assert response.status_code == 503
    assert "alembic upgrade head" in response.json()["detail"]


# ---- event store, three backends ------------------------------------------

@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryHealthEventStore()

    return SQLiteHealthEventStore(tmp_path / "health.db")


def record(store, source, status, minutes=0, severity="Info"):
    return store.record_status(source=source, status=status, severity=severity,
                               message=f"{source} {status}", occurred_at=START + timedelta(minutes=minutes))


@pytest.mark.parametrize("previous,status,expected", [
    (None, "up", False), (None, "unconfigured", False), (None, "down", True),
    (None, "degraded", True), (None, "starting", True),
    ("up", "up", False), ("down", "down", False), ("down", "up", True),
    ("up", "unconfigured", True), ("unconfigured", "down", True),
])
def test_should_record_rules(previous, status, expected):
    assert should_record(previous, status) is expected


def test_store_records_only_changes_per_source(store):
    assert record(store, "a", "up") is None
    assert record(store, "a", "down", 1, "Critical").status == "down"
    assert record(store, "a", "down", 2, "Critical") is None
    assert record(store, "b", "down", 3, "Critical").source == "b"
    assert record(store, "a", "up", 4).status == "up"

    assert [(e.source, e.status) for e in store.list_events()] == [
        ("a", "up"), ("b", "down"), ("a", "down")]


def test_store_filters_and_ids_increase(store):
    record(store, "a", "down", 0, "Critical")
    record(store, "b", "degraded", 5, "Warning")
    record(store, "a", "up", 10)

    events = store.list_events()

    assert [e.event_id for e in events] == sorted((e.event_id for e in events), reverse=True)
    assert [e.source for e in store.list_events(source="a")] == ["a", "a"]
    assert [e.severity for e in store.list_events(severity="Warning")] == ["Warning"]
    assert [e.source for e in store.list_events(since=START + timedelta(minutes=5))] == ["a", "b"]
    assert [e.source for e in store.list_events(until=START + timedelta(minutes=5))] == ["b", "a"]
    assert store.list_events(source="zzz") == []


def test_store_empty(store):
    assert store.list_events() == []


def test_concurrent_checks_record_a_change_once(store):
    results = []

    def worker():
        results.append(record(store, "a", "down", 0, "Critical"))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for r in results if r is not None) == 1
    assert len(store.list_events()) == 1


def test_sqlite_state_survives_reopening(tmp_path):
    path = tmp_path / "h.db"
    record(SQLiteHealthEventStore(path), "a", "down", 0, "Critical")

    reopened = SQLiteHealthEventStore(path)

    assert record(reopened, "a", "down", 1, "Critical") is None
    assert len(reopened.list_events()) == 1


def test_sqlite_rejects_unknown_status_or_severity(tmp_path):
    path = tmp_path / "h.db"
    SQLiteHealthEventStore(path)

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO health_events (occurred_at, severity, source, status, message) "
                "VALUES ('t', 'Fatal', 'a', 'down', 'm')")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO health_events (occurred_at, severity, source, status, message) "
                "VALUES ('t', 'Info', 'a', 'on fire', 'm')")


class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class PgConnection:
    def __init__(self, log, script, error):
        self.log, self.script, self.error = log, script, error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params=None):
        text = " ".join(str(statement).split())
        self.log.append((text, params))
        if self.error is not None:
            raise self.error
        for needle, rows in self.script:
            if needle in text:
                return Result(rows)
        return Result([])


def pg(script=(), error=None):
    log = []
    return PostgresHealthEventStore(
        "postgresql://test/test", connect=lambda url: PgConnection(log, list(script), error)), log


def test_postgres_constructor_creates_no_tables():
    assert pg()[1] == []


def test_postgres_records_a_change_under_a_lock():
    store, log = pg(script=[("SELECT status FROM health_events", [("up",)]),
                            ("RETURNING event_id", [(7,)])])

    event = record(store, "ollama", "down", 0, "Critical")

    statements = [text for text, _ in log]
    assert "pg_advisory_xact_lock" in statements[0]
    assert "WHERE source = %s ORDER BY event_id DESC LIMIT 1" in statements[1]
    assert statements[2].startswith("INSERT INTO health_events")
    assert event.event_id == 7 and event.status == "down"
    assert log[2][1][1:4] == ("Critical", "ollama", "down")


def test_postgres_unchanged_status_inserts_nothing():
    store, log = pg(script=[("SELECT status FROM health_events", [("down",)])])

    assert record(store, "ollama", "down", 0, "Critical") is None
    assert not any(text.startswith("INSERT") for text, _ in log)


def test_postgres_first_up_inserts_nothing():
    store, log = pg()

    assert record(store, "ollama", "up") is None
    assert not any(text.startswith("INSERT") for text, _ in log)


def test_postgres_list_binds_filters():
    store, log = pg()

    store.list_events(severity="Critical", source="x'; DROP TABLE y;--", since=START)

    text, params = log[-1]
    assert "severity = %s" in text and "source = %s" in text and "occurred_at >= %s" in text
    assert params == ("Critical", "x'; DROP TABLE y;--", START)
    assert text.endswith("ORDER BY event_id DESC") and "DROP TABLE" not in text


def test_postgres_missing_table_raises_schema_not_ready():
    store, _ = pg(error=psycopg.errors.UndefinedTable("missing"))

    with pytest.raises(HealthSchemaNotReady):
        store.list_events()
    with pytest.raises(HealthSchemaNotReady):
        record(store, "a", "down", 0, "Critical")
