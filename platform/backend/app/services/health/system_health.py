"""Assembles GET /api/v1/system/health from probe results and the event log.

Live status comes only from the probes. The event log is written when a status changes
(see health_event_store) and read back for last_change_at; if its table is not migrated
the health page still works and reports event_log "unavailable".
"""

from datetime import datetime

from app.schemas import HealthMetrics, HealthService, SystemHealth
from app.services.health.health_event_store import HealthSchemaNotReady
from app.services.health.health_probes import (
    CATALOG,
    NOT_PROBED_DETAIL,
    ProbeResult,
    run_probes,
)

STATUSES = ("up", "degraded", "down", "starting", "unconfigured")
_SEVERITY = {
    "down": "Critical",
    "degraded": "Warning",
    "starting": "Info",
    "up": "Info",
    "unconfigured": "Info",
}


def _message(name: str, result: ProbeResult) -> str:
    text = f"{name} is {result.status}"

    return f"{text}: {result.detail}" if result.detail else text


def build_system_health(
    *,
    probes,
    event_store,
    now: datetime,
    started_at: datetime,
    version: str,
    response_mode: str,
    persistence_backend: str,
    evidence_provider: str,
) -> SystemHealth:
    probed = {d.check_key: probes[d.check_key] for d in CATALOG if d.probed and d.check_key in probes}
    results = run_probes(probed, now=now, started_at=started_at)

    final: dict[str, ProbeResult] = {}

    for definition in CATALOG:
        if not definition.probed:
            final[definition.check_key] = ProbeResult("unconfigured", None, NOT_PROBED_DETAIL)
        else:
            final[definition.check_key] = results.get(
                definition.check_key,
                ProbeResult("unconfigured", None, "No probe is configured."),
            )

    event_log = "ok"
    newest: dict[tuple[str, str], datetime] = {}

    try:
        for definition in CATALOG:
            result = final[definition.check_key]

            if definition.probed:
                event_store.record_status(
                    source=definition.check_key,
                    status=result.status,
                    severity=_SEVERITY[result.status],
                    message=_message(definition.name, result),
                    occurred_at=now,
                )

        for event in event_store.list_events():
            newest.setdefault((event.source, event.status), event.occurred_at)
    except HealthSchemaNotReady:
        event_log = "unavailable"

    services = [
        HealthService(
            check_key=definition.check_key,
            name=definition.name,
            group=definition.group,
            category=definition.category,
            status=final[definition.check_key].status,
            endpoint=final[definition.check_key].endpoint,
            latency_ms=final[definition.check_key].latency_ms,
            checked_at=now if definition.probed else None,
            detail=final[definition.check_key].detail,
            last_change_at=newest.get((definition.check_key, final[definition.check_key].status)),
        )
        for definition in CATALOG
    ]

    summary = {status: 0 for status in STATUSES}

    for service in services:
        summary[service.status] += 1

    return SystemHealth(
        generated_at=now,
        services=services,
        summary=summary,
        metrics=HealthMetrics(
            process_uptime_seconds=max(0, int((now - started_at).total_seconds())),
            version=version,
            response_mode=response_mode,
            persistence_backend=persistence_backend,
            evidence_provider=evidence_provider,
        ),
        event_log=event_log,
    )
