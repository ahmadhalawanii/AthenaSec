"""Health probes. No real network: HTTP uses httpx.MockTransport, Postgres and Wazuh are faked,
and a fixture makes any real socket connection fail the test."""

import socket
import threading
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from tests import network_guard

import app.services.health.health_probes as probes_module
from app.services.health.health_probes import (
    CATALOG,
    DEGRADED_LATENCY_MS,
    ProbeResult,
    default_probes,
    probe_cortex,
    probe_misp,
    probe_ollama,
    probe_postgres,
    probe_wazuh_indexer,
    public_endpoint,
    run_probes,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    network_guard.install(monkeypatch)


def client_for(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def ok(request):
    return httpx.Response(200, json={"ok": True})


# ---- catalog ---------------------------------------------------------------

def test_catalog_is_the_ten_website_services_and_five_are_probed():
    assert [d.check_key for d in CATALOG] == [
        "postgres", "ollama", "misp", "cortex", "wazuh_indexer",
        "opensearch", "suricata", "langgraph", "docker_engine", "wazuh_dashboard"]
    assert [d.check_key for d in CATALOG if d.probed] == [
        "postgres", "ollama", "misp", "cortex", "wazuh_indexer"]
    assert len({d.check_key for d in CATALOG}) == 10


def test_default_probes_cover_exactly_the_probed_services():
    assert set(default_probes()) == {d.check_key for d in CATALOG if d.probed}


# ---- public_endpoint -------------------------------------------------------

@pytest.mark.parametrize("url,expected", [
    ("postgresql://user:secret@db.internal:5432/athena?sslmode=require", "postgresql://db.internal:5432"),
    ("https://token@misp.example.com/path/x?key=1", "https://misp.example.com"),
    ("http://localhost:11434/", "http://localhost:11434"),
    ("https://[2001:db8::1]:9200", "https://[2001:db8::1]:9200"),
    ("not a url", None), ("", None), (None, None),
])
def test_public_endpoint_drops_credentials_path_and_query(url, expected):
    assert public_endpoint(url) == expected


# ---- postgres --------------------------------------------------------------

class FakePgConnection:
    def __init__(self, log, fail):
        self.log, self.fail = log, fail

    def __enter__(self):
        if self.fail:
            raise RuntimeError("FATAL: password authentication failed for user admin")
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        self.log.append(statement)
        return self

    def fetchone(self):
        return (1,)


def pg_env(**overrides):
    env = {"ATHENASEC_PERSISTENCE_BACKEND": "postgres",
           "ATHENASEC_DATABASE_URL": "postgresql://admin:hunter2@db.internal:5432/athena"}
    env.update(overrides)
    return env


def test_postgres_unconfigured_when_backend_is_sqlite_or_url_missing():
    for env in ({"ATHENASEC_PERSISTENCE_BACKEND": "sqlite", "ATHENASEC_DATABASE_URL": "postgresql://x/y"},
                {"ATHENASEC_PERSISTENCE_BACKEND": "postgres"},
                {"ATHENASEC_PERSISTENCE_BACKEND": "postgres", "ATHENASEC_DATABASE_URL": "  "},
                {}):
        result = probe_postgres(environ=env, connect=lambda *a, **k: pytest.fail("must not connect"))
        assert result.status == "unconfigured" and result.latency_ms is None and result.endpoint is None


def test_postgres_up_runs_select_one_with_a_short_timeout():
    log, kwargs = [], {}

    def connect(url, **kw):
        kwargs.update(kw)
        return FakePgConnection(log, fail=False)

    result = probe_postgres(environ=pg_env(), connect=connect)

    assert result.status == "up" and isinstance(result.latency_ms, int)
    assert log == ["SELECT 1"] and kwargs == {"connect_timeout": 3}
    assert result.endpoint == "postgresql://db.internal:5432"


def test_postgres_failure_is_generic_and_leaks_nothing():
    result = probe_postgres(environ=pg_env(), connect=lambda *a, **k: FakePgConnection([], fail=True))

    assert result.status == "down" and result.detail == "Connection failed."
    assert "hunter2" not in repr(result) and "admin" not in repr(result)
    assert result.endpoint == "postgresql://db.internal:5432"


# ---- ollama ----------------------------------------------------------------

def test_ollama_up_probes_api_tags_on_the_configured_base():
    seen = []

    def handler(request):
        seen.append((request.method, str(request.url)))
        return httpx.Response(200, json={"models": []})

    result = probe_ollama(http_client=client_for(handler),
                          environ={"OLLAMA_BASE_URL": "http://ollama.internal:11434/"})

    assert result.status == "up" and isinstance(result.latency_ms, int)
    assert seen == [("GET", "http://ollama.internal:11434/api/tags")]
    assert result.endpoint == "http://ollama.internal:11434"


def test_ollama_uses_the_agent_default_base_when_unset():
    seen = []
    probe_ollama(http_client=client_for(lambda r: seen.append(str(r.url)) or httpx.Response(200)),
                 environ={})

    assert seen == ["http://localhost:11434/api/tags"]


@pytest.mark.parametrize("handler,status,detail", [
    (lambda r: httpx.Response(500), "down", "Unexpected HTTP status 500."),
    (lambda r: httpx.Response(404), "down", "Unexpected HTTP status 404."),
    (lambda r: httpx.Response(403), "degraded", "Reachable; credentials rejected."),
])
def test_ollama_http_outcomes(handler, status, detail):
    result = probe_ollama(http_client=client_for(handler), environ={})

    assert (result.status, result.detail) == (status, detail)


@pytest.mark.parametrize("error,detail", [
    (httpx.ConnectError("secret-host refused"), "Connection failed."),
    (httpx.ReadTimeout("slow"), "Timed out."),
])
def test_ollama_network_errors_are_generic(error, detail):
    def handler(request):
        raise error

    result = probe_ollama(http_client=client_for(handler), environ={})

    assert (result.status, result.detail, result.latency_ms) == ("down", detail, None)
    assert "secret-host" not in repr(result)


# ---- misp and cortex -------------------------------------------------------

def test_misp_unconfigured_unless_url_and_key_are_both_set():
    boom = client_for(lambda r: pytest.fail("must not call"))

    for env in ({}, {"MISP_URL": "https://misp.example.com"}, {"MISP_API_KEY": "k"},
                {"MISP_URL": " ", "MISP_API_KEY": "k"}):
        assert probe_misp(http_client=boom, environ=env).status == "unconfigured"


def test_misp_sends_the_key_only_in_the_header_and_never_reports_it():
    seen = {}

    def handler(request):
        seen["url"], seen["auth"] = str(request.url), request.headers.get("authorization")
        return httpx.Response(200, json={"version": "2.4"})

    result = probe_misp(http_client=client_for(handler),
                        environ={"MISP_URL": "https://misp.example.com/", "MISP_API_KEY": "topsecret"})

    assert seen == {"url": "https://misp.example.com/servers/getVersion", "auth": "topsecret"}
    assert result.status == "up" and result.endpoint == "https://misp.example.com"
    assert "topsecret" not in repr(result)


def test_misp_rejected_key_is_degraded_not_down():
    result = probe_misp(http_client=client_for(lambda r: httpx.Response(401)),
                        environ={"MISP_URL": "https://m", "MISP_API_KEY": "k"})

    assert (result.status, result.detail) == ("degraded", "Reachable; credentials rejected.")


def test_cortex_unconfigured_and_probe_path():
    assert probe_cortex(http_client=client_for(ok), environ={}).status == "unconfigured"
    seen = []

    result = probe_cortex(
        http_client=client_for(lambda r: seen.append(str(r.url)) or httpx.Response(200)),
        environ={"CORTEX_URL": "https://cortex.example.com:9001/"})

    assert seen == ["https://cortex.example.com:9001/api/status"]
    assert result.status == "up" and result.endpoint == "https://cortex.example.com:9001"


# ---- wazuh indexer ---------------------------------------------------------

def wazuh_env(**overrides):
    env = {"ATHENASEC_EVIDENCE_PROVIDER": "wazuh", "WAZUH_INDEXER_URL": "https://wazuh.example.com:9200",
           "WAZUH_INDEXER_USERNAME": "athena_reader", "WAZUH_INDEXER_PASSWORD": "pw-secret"}
    env.update(overrides)
    return env


class FakeIndexer:
    created = []

    def __init__(self, response=None, error=None, **kwargs):
        self.kwargs, self.response, self.error = kwargs, response, error
        FakeIndexer.created.append(kwargs)

    def health(self):
        if self.error:
            raise self.error
        return self.response


def factory(response=None, error=None):
    return lambda **kwargs: FakeIndexer(response=response, error=error, **kwargs)


def test_wazuh_unconfigured_unless_the_agent_uses_it():
    boom = lambda **kw: pytest.fail("must not build a client")

    assert probe_wazuh_indexer(client_factory=boom, environ={}).status == "unconfigured"
    assert probe_wazuh_indexer(client_factory=boom,
                               environ=wazuh_env(ATHENASEC_EVIDENCE_PROVIDER="mock")).status == "unconfigured"
    incomplete = wazuh_env()
    del incomplete["WAZUH_INDEXER_PASSWORD"]
    assert probe_wazuh_indexer(client_factory=boom, environ=incomplete).status == "unconfigured"


@pytest.mark.parametrize("overrides", [
    {"WAZUH_INDEXER_URL": "http://wazuh.example.com:9200"},
    {"WAZUH_INDEXER_URL": "https://user:pw@wazuh.example.com:9200"},
    {"WAZUH_INDEXER_URL": "https://wazuh.example.com:9200/?x=1"},
    {"WAZUH_VERIFY_SSL": "false"},
    {"WAZUH_INDEXER_CA_BUNDLE": "/definitely/not/a/file.pem"},
    {"WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT": "true"},
])
def test_wazuh_invalid_tls_or_url_settings_are_down_and_never_weakened(overrides):
    result = probe_wazuh_indexer(
        client_factory=lambda **kw: pytest.fail("a probe must not weaken TLS rules"),
        environ=wazuh_env(**overrides))

    assert (result.status, result.detail) == ("down", "Configuration is invalid.")
    assert "pw-secret" not in repr(result)


@pytest.mark.parametrize("cluster,status", [
    ({"status": "green"}, "up"), ({"status": "yellow"}, "degraded"),
    ({"status": "red"}, "down"), ({"status": "weird"}, "down"), ({}, "down"), ("nope", "down"),
])
def test_wazuh_cluster_status_maps_to_service_status(cluster, status):
    result = probe_wazuh_indexer(client_factory=factory(response=cluster), environ=wazuh_env())

    assert result.status == status and result.endpoint == "https://wazuh.example.com:9200"


def test_wazuh_client_is_built_strictly_with_a_short_timeout():
    FakeIndexer.created.clear()

    probe_wazuh_indexer(client_factory=factory(response={"status": "green"}), environ=wazuh_env())

    (kwargs,) = FakeIndexer.created
    assert kwargs["verify_ssl"] is True and kwargs["timeout"] == 3.0
    assert kwargs["legacy_ca_compat"] is False and kwargs["username"] == "athena_reader"


def test_wazuh_failure_is_generic():
    result = probe_wazuh_indexer(
        client_factory=factory(error=RuntimeError("401 for athena_reader pw-secret")),
        environ=wazuh_env())

    assert (result.status, result.detail) == ("down", "Connection failed.")
    assert "pw-secret" not in repr(result)


def test_wazuh_uses_a_ca_bundle_when_it_exists(tmp_path):
    bundle = tmp_path / "ca.pem"
    bundle.write_text("x")
    FakeIndexer.created.clear()

    probe_wazuh_indexer(client_factory=factory(response={"status": "green"}),
                        environ=wazuh_env(WAZUH_INDEXER_CA_BUNDLE=str(bundle)))

    assert FakeIndexer.created[0]["verify_ssl"] == str(bundle)


# ---- run_probes ------------------------------------------------------------

def test_slow_but_successful_probe_is_degraded():
    slow = lambda: ProbeResult("up", DEGRADED_LATENCY_MS + 1, None, "http://x")

    result = run_probes({"a": slow}, now=NOW, started_at=NOW - timedelta(hours=1))["a"]

    assert result.status == "degraded" and "Slow response" in result.detail


def test_failure_right_after_start_is_starting_then_down():
    down = lambda: ProbeResult("down", None, "Connection failed.", "http://x")

    early = run_probes({"a": down}, now=NOW, started_at=NOW - timedelta(seconds=10))["a"]
    late = run_probes({"a": down}, now=NOW, started_at=NOW - timedelta(seconds=61))["a"]

    assert early.status == "starting" and late.status == "down"


def test_unconfigured_and_up_are_never_changed_by_startup_grace():
    probes = {"a": lambda: ProbeResult("unconfigured", None, "x"), "b": lambda: ProbeResult("up", 5)}

    results = run_probes(probes, now=NOW, started_at=NOW)

    assert results["a"].status == "unconfigured" and results["b"].status == "up"


def test_a_probe_that_raises_reports_down_without_the_message():
    def broken():
        raise RuntimeError("secret connection string")

    result = run_probes({"a": broken}, now=NOW, started_at=NOW - timedelta(hours=1))["a"]

    assert (result.status, result.detail) == ("down", "Probe failed.")


def test_a_hung_probe_times_out(monkeypatch):
    monkeypatch.setattr(probes_module, "PROBE_DEADLINE_SECONDS", 0.2)
    release = threading.Event()

    result = run_probes({"a": lambda: release.wait(5) or ProbeResult("up", 1)},
                        now=NOW, started_at=NOW - timedelta(hours=1))["a"]
    release.set()

    assert (result.status, result.detail) == ("down", "Timed out.")


def test_probes_run_concurrently():
    barrier = threading.Barrier(3, timeout=2)

    def probe():
        barrier.wait()
        return ProbeResult("up", 1)

    results = run_probes({k: probe for k in "abc"}, now=NOW, started_at=NOW - timedelta(hours=1))

    assert [r.status for r in results.values()] == ["up", "up", "up"]


def test_the_network_guard_refuses_real_services_and_external_hosts():
    for address in (("203.0.113.1", 443), ("example.com", 80), ("127.0.0.1", 11434),
                    ("localhost", 5432), ("127.0.0.1", 9200)):
        with pytest.raises(AssertionError, match="real network"):
            socket.socket().connect(address)

    with pytest.raises(AssertionError, match="real network"):
        socket.create_connection(("127.0.0.1", 9))
