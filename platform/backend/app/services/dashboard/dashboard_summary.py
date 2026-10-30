"""Dashboard summary, computed per request from the existing stores.

Nothing is stored or cached. Event counts (alerts, investigations, decided approvals,
cases opened) cover the chosen window; backlog counts (pending approvals, active cases)
are the current state and ignore the window. Zero is a real answer, not a placeholder.

The role selects the view, not the permissions: the Analyst view adds the caller's own
active cases; the Administrator view adds the response/execution mode.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone

from app.schemas import (
    AlertsSummary,
    ApprovalsSummary,
    CasesSummary,
    DashboardSummary,
    InvestigationsSummary,
    ResponseSummary,
    SeriesPoint,
)
from app.services.dashboard.list_pagination import as_utc

# window -> (bucket count, bucket size)
WINDOWS = {
    "24h": (24, timedelta(hours=1)),
    "7d": (7, timedelta(days=1)),
    "30d": (30, timedelta(days=1)),
}

INACTIVE_CASE_STATUSES = {"resolved", "closed"}
RECENT_ALERT_LIMIT = 5


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _floor(moment: datetime, step: timedelta) -> datetime:
    moment = as_utc(moment)

    if step >= timedelta(days=1):
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)

    return moment.replace(minute=0, second=0, microsecond=0)


def window_bounds(window: str, now: datetime) -> tuple[datetime, list[datetime]]:
    count, step = WINDOWS[window]
    last = _floor(now, step)
    buckets = [last - step * offset for offset in range(count - 1, -1, -1)]

    return buckets[0], buckets


def _counts(values) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def build_dashboard_summary(
    *,
    window: str,
    role: str,
    caller_id: str | None,
    now: datetime,
    investigation_store,
    response_store,
    workflow_store,
    runtime_status,
) -> DashboardSummary:
    now = as_utc(now)
    window_start, buckets = window_bounds(window, now)
    step = WINDOWS[window][1]

    alerts = investigation_store.list_alerts(since=window_start)
    alerts = [a for a in alerts if a.observed_at is not None]

    investigations = [
        i
        for i in investigation_store.list_investigations()
        if as_utc(i.started_at) >= window_start
    ]

    approvals = response_store.list_approval_requests()
    pending = sum(1 for a in approvals if a.status == "PENDING")
    decided = sum(
        1
        for a in approvals
        if a.status != "PENDING"
        and as_utc(a.decided_at or a.requested_at) >= window_start
    )

    cases = response_store.list_all_incident_cases()
    active_cases = [c for c in cases if c.status not in INACTIVE_CASE_STATUSES]

    my_cases = None

    if role == "Analyst" and caller_id is not None:
        my_cases = 0

        for case in active_cases:
            workflow = workflow_store.get_workflow(case.case_id)

            if workflow is not None and workflow.assigned_analyst == caller_id:
                my_cases += 1

    series = []

    if alerts:
        per_bucket = Counter(_floor(a.observed_at, step) for a in alerts)
        series = [
            SeriesPoint(bucket_start=bucket, alerts=per_bucket.get(bucket, 0))
            for bucket in buckets
        ]

    status = runtime_status() if role == "Administrator" else None

    return DashboardSummary(
        window=window,
        role=role,
        generated_at=now,
        window_start=window_start,
        alerts=AlertsSummary(
            total=len(alerts),
            by_classification=_counts(a.classification for a in alerts),
            by_risk_band=_counts(a.risk_assessment.band for a in alerts),
            by_status=_counts(a.status for a in alerts),
        ),
        investigations=InvestigationsSummary(
            total=len(investigations),
            by_status=_counts(i.status for i in investigations),
        ),
        approvals=ApprovalsSummary(pending=pending, decided=decided),
        cases=CasesSummary(
            active=len(active_cases),
            by_status=_counts(c.status for c in cases),
            opened_in_window=sum(
                1 for c in cases if as_utc(c.created_at) >= window_start
            ),
        ),
        my_cases=my_cases,
        response=(
            ResponseSummary(
                response_mode=status["response_mode"],
                operator_execution_enabled=status["operator_execution_enabled"],
                effective_execution_enabled=status["effective_execution_enabled"],
            )
            if status is not None
            else None
        ),
        recent_alerts=alerts[:RECENT_ALERT_LIMIT],
        series=series,
    )
