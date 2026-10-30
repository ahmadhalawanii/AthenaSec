"""Live dependency probes for GET /api/v1/system/health.

Ten services are listed, the ones the website shows. The agent only probes five of them
(PostgreSQL, Ollama, MISP, Cortex, Wazuh Indexer). The other five (OpenSearch, Suricata,
LangGraph, Docker Engine, Wazuh Dashboard) have no probe, so they are reported as
"unconfigured" with no latency or endpoint: nothing is invented about them.

Probes only read. They use short timeouts, run concurrently, and report a short generic
detail on failure, never the exception text, a URL with credentials, or a response body.
Per-service uptime is not tracked, so uptime_seconds and uptime_percent stay null.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import psycopg

PROBE_TIMEOUT_SECONDS = 3.0
PROBE_DEADLINE_SECONDS = 6.0
DEGRADED_LATENCY_MS = 1500
STARTUP_GRACE_SECONDS = 60

NOT_PROBED_DETAIL = "Not probed by the agent."


@dataclass(frozen=True)
class ServiceDefinition:
    check_key: str
    name: str
    group: str
    category: str
    probed: bool


# group and category are display labels chosen here; reconcile with the website's.
CATALOG = (
    ServiceDefinition("postgres", "PostgreSQL", "Data", "Database", True),
    ServiceDefinition("ollama", "Ollama", "AI", "LLM runtime", True),
    ServiceDefinition("misp", "MISP", "Intelligence", "Threat intelligence", True),
    ServiceDefinition("cortex", "Cortex", "Response", "Automation", True),
    ServiceDefinition("wazuh_indexer", "Wazuh Indexer", "Detection", "SIEM", True),
    ServiceDefinition("opensearch", "OpenSearch", "Data", "Search", False),
    ServiceDefinition("suricata", "Suricata", "Detection", "IDS", False),
    ServiceDefinition("langgraph", "LangGraph", "AI", "Orchestration", False),
    ServiceDefinition("docker_engine", "Docker Engine", "Platform", "Runtime", False),
    ServiceDefinition("wazuh_dashboard", "Wazuh Dashboard", "Detection", "Dashboard", False),
)


@dataclass(frozen=True)
class ProbeResult:
    status: str  # up | degraded | down | unconfigured
    latency_ms: int | None = None
    detail: str | None = None
    endpoint: str | None = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def public_endpoint(url: str | None) -> str | None:
    """scheme://host[:port] only: no credentials, path or query."""

    if not url:
        return None

    parts = urlsplit(url.strip())

    if not parts.scheme or not parts.hostname:
        return None

    host = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    port = f":{parts.port}" if parts.port else ""

    return f"{parts.scheme}://{host}{port}"


def _configured(value) -> bool:
    return value is not None and bool(str(value).strip())


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _http_probe(client, method, url, *, endpoint, headers=None, ok_detail=None):
    started = time.perf_counter()

    try:
        response = client.request(method, url, headers=headers or {},
                                  timeout=PROBE_TIMEOUT_SECONDS)
    except httpx.TimeoutException:
        return ProbeResult("down", None, "Timed out.", endpoint)
    except httpx.HTTPError:
        return ProbeResult("down", None, "Connection failed.", endpoint)

    latency = _elapsed_ms(started)

    if 200 <= response.status_code < 300:
        return ProbeResult("up", latency, ok_detail, endpoint)

    if response.status_code in (401, 403):
        return ProbeResult("degraded", latency, "Reachable; credentials rejected.", endpoint)

    return ProbeResult("down", latency, f"Unexpected HTTP status {response.status_code}.", endpoint)


def probe_postgres(*, connect=None, environ=None) -> ProbeResult:
    env = os.environ if environ is None else environ
    backend = env.get("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower()
    url = env.get("ATHENASEC_DATABASE_URL")

    if backend != "postgres" or not _configured(url):
        return ProbeResult("unconfigured", None, "PostgreSQL is not the configured backend.")

    endpoint = public_endpoint(url)
    started = time.perf_counter()

    try:
        with (connect or psycopg.connect)(url, connect_timeout=int(PROBE_TIMEOUT_SECONDS)) as connection:
            connection.execute("SELECT 1").fetchone()
    except Exception:
        return ProbeResult("down", None, "Connection failed.", endpoint)

    return ProbeResult("up", _elapsed_ms(started), None, endpoint)


def probe_ollama(*, http_client, environ=None) -> ProbeResult:
    env = os.environ if environ is None else environ
    base = env.get("OLLAMA_BASE_URL", "http://localhost:11434").strip().rstrip("/")

    return _http_probe(http_client, "GET", f"{base}/api/tags", endpoint=public_endpoint(base))


def probe_misp(*, http_client, environ=None) -> ProbeResult:
    env = os.environ if environ is None else environ
    url, key = env.get("MISP_URL"), env.get("MISP_API_KEY")

    if not (_configured(url) and _configured(key)):
        return ProbeResult("unconfigured", None, "MISP_URL and MISP_API_KEY are not both set.")

    base = url.strip().rstrip("/")

    return _http_probe(
        http_client, "GET", f"{base}/servers/getVersion", endpoint=public_endpoint(base),
        headers={"Authorization": key.strip(), "Accept": "application/json"})


def probe_cortex(*, http_client, environ=None) -> ProbeResult:
    env = os.environ if environ is None else environ
    url = env.get("CORTEX_URL")

    if not _configured(url):
        return ProbeResult("unconfigured", None, "CORTEX_URL is not set.")

    base = url.strip().rstrip("/")

    return _http_probe(http_client, "GET", f"{base}/api/status", endpoint=public_endpoint(base))


def probe_wazuh_indexer(*, client_factory=None, environ=None) -> ProbeResult:
    """Only probed when the agent actually uses Wazuh evidence (ATHENASEC_EVIDENCE_PROVIDER=wazuh)."""

    env = os.environ if environ is None else environ

    if env.get("ATHENASEC_EVIDENCE_PROVIDER", "mock").strip().lower() != "wazuh":
        return ProbeResult("unconfigured", None, "Wazuh evidence provider is not enabled.")

    url = env.get("WAZUH_INDEXER_URL")
    user = env.get("WAZUH_INDEXER_USERNAME")
    password = env.get("WAZUH_INDEXER_PASSWORD")

    if not (_configured(url) and _configured(user) and _configured(password)):
        return ProbeResult("unconfigured", None, "Wazuh Indexer settings are incomplete.")

    endpoint = public_endpoint(url)
    parts = urlsplit(url.strip())

    # Same rules the evidence provider enforces: a probe must not weaken them.
    ca_bundle = env.get("WAZUH_INDEXER_CA_BUNDLE", "").strip()
    legacy = env.get("WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT", "false").strip().lower() in {
        "1", "true", "yes", "on"}
    invalid = (
        parts.scheme != "https" or not parts.hostname or parts.username or parts.password
        or parts.query or parts.fragment
        or env.get("WAZUH_VERIFY_SSL", "true").strip().lower() not in {"1", "true", "yes", "on"}
        or (ca_bundle and not Path(ca_bundle).is_file())
        or (legacy and not ca_bundle)
    )

    if invalid:
        return ProbeResult("down", None, "Configuration is invalid.", endpoint)

    if client_factory is None:
        from app.tools.wazuh_indexer import WazuhIndexerClient

        def client_factory(**kwargs):
            return WazuhIndexerClient(**kwargs)

    started = time.perf_counter()

    try:
        client = client_factory(
            base_url=url.strip(), username=user, password=password,
            verify_ssl=ca_bundle if ca_bundle else True, timeout=PROBE_TIMEOUT_SECONDS,
            legacy_ca_compat=legacy)
        cluster = client.health()
    except Exception:
        return ProbeResult("down", None, "Connection failed.", endpoint)

    latency = _elapsed_ms(started)
    cluster_status = cluster.get("status") if isinstance(cluster, dict) else None

    if cluster_status == "green":
        return ProbeResult("up", latency, "Cluster green.", endpoint)

    if cluster_status == "yellow":
        return ProbeResult("degraded", latency, "Cluster yellow.", endpoint)

    return ProbeResult("down", latency, "Cluster red or status unknown.", endpoint)


def default_probes(*, http_client=None, postgres_connect=None, wazuh_client_factory=None):
    """check_key -> zero-argument probe. Environment is read when a probe runs."""

    client = http_client if http_client is not None else httpx.Client()

    return {
        "postgres": lambda: probe_postgres(connect=postgres_connect),
        "ollama": lambda: probe_ollama(http_client=client),
        "misp": lambda: probe_misp(http_client=client),
        "cortex": lambda: probe_cortex(http_client=client),
        "wazuh_indexer": lambda: probe_wazuh_indexer(client_factory=wazuh_client_factory),
    }


def _classify(result: ProbeResult, *, in_startup_grace: bool) -> ProbeResult:
    if result.status == "up" and (result.latency_ms or 0) > DEGRADED_LATENCY_MS:
        return ProbeResult("degraded", result.latency_ms,
                           f"Slow response ({result.latency_ms} ms).", result.endpoint)

    if result.status == "down" and in_startup_grace:
        return ProbeResult("starting", result.latency_ms,
                           "Not reachable yet; the agent started recently.", result.endpoint)

    return result


def run_probes(probes, *, now: datetime, started_at: datetime) -> dict[str, ProbeResult]:
    """Run every configured probe concurrently. A probe that raises or hangs reports down."""

    grace = (now - started_at).total_seconds() < STARTUP_GRACE_SECONDS
    results: dict[str, ProbeResult] = {}
    pool = ThreadPoolExecutor(max_workers=max(1, len(probes)))

    try:
        futures = {key: pool.submit(probe) for key, probe in probes.items()}

        for key, future in futures.items():
            try:
                outcome = future.result(timeout=PROBE_DEADLINE_SECONDS)
            except FutureTimeout:
                outcome = ProbeResult("down", None, "Timed out.")
            except Exception:
                outcome = ProbeResult("down", None, "Probe failed.")

            results[key] = _classify(outcome, in_startup_grace=grace)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    return results
