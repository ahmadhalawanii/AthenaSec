# What the agent backend needs for the website to go live

Based on reading `AthenaSec/backend/app/main.py`, `app/schemas.py` and the stores
(the agent repo was not modified). The placeholder API in this folder already
returns these shapes, so the frontend adapters keep working when the routes move.

## What exists today (`/api/v1`)

`auth/login|mfa|me|logout`, `runtime/status|control|control/history`, `analyze`,
`integrations/wazuh/alerts`, `investigations/{alert_id}` (+ `/case`, `/audit`),
`approvals/{approval_id}` (get and decide), `/health`.

## 1. CORS (blocker for any browser call)

`create_app()` has no `CORSMiddleware`. Add it, driven by an env var:

- `ATHENASEC_CORS_ORIGINS` (comma separated; dev default `http://localhost:5173`)
- `allow_methods=["GET", "POST", "PUT"]`, `allow_headers=["*"]`
- `allow_credentials=True` only with explicit origins (never `*`), because the
  browser login uses a session cookie (`web_auth.py`)

## 2. List endpoints (the stores only have get-by-id today)

All use one envelope: `{"total": int, "items": [...], "next_cursor": str | null}`
with `?limit=` and `?cursor=` (the placeholder API returns `total` + `items`).

| Route | Items | Filters | Store method to add |
|---|---|---|---|
| `GET /api/v1/alerts` | alert + `ml_prediction` + `risk_assessment` + status | `status`, `classification`, `since` | `list_alerts()` (today: `list_incident_alerts(incident_id)` only) |
| `GET /api/v1/investigations` | `IncidentInvestigationRecord` + `classification`, `risk_score`, `risk_band`, `policy_outcome` | `status`, `incident_id` | `list_investigations()` (today: `list_incident_investigations(incident_id)`) |
| `GET /api/v1/cases` | `CaseRecord` (see 3) | `status`, `alert_id` | `list_cases()` (today: `get_case`, `get_case_by_alert_id`) |
| `GET /api/v1/approvals` | approval + proposed action + action risk + policy decision | `status` | `list_approval_requests()` |
| `GET /api/v1/audit` | `IncidentAuditRecord` (+ legacy `AuditRecord` as `alert_events`) | `alert_id`, `incident_id`, `event_type`, `since`, `until` | `list_all()` (today: `list_by_alert_id`, `list_by_incident_id`) |

Detail routes: `GET /api/v1/investigations/{id}` should accept `INV-…` as well as
`alert_id`; add `GET /api/v1/alerts/{alert_id}` and `GET /api/v1/cases/{case_id}`.
Errors should use `{"error": {"code", "message", "details"}}` (FastAPI's default
`{"detail": ...}` makes the frontend parse two shapes).

## 3. Case shape

The agent's `CaseRecord` is `case_id, alert_id, policy_id, classification,
risk_score, risk_band, status ("open" only), reason`. The Cases page also shows
`assigned_analyst, endpoint, source_ip, summary, evidence[], recommended_actions[],
mitre_ids[], timeline[], created_at, updated_at`, and open/closed. Either add these
fields to the stored case or derive them in the list route from the investigation
(`analysis.summary`, `evidence_records`, `proposed_actions`, `investigation_trace`).
Widen `CaseStatus` to `IncidentCaseStatus` (`open, investigating, contained,
resolved, closed`), which already exists in `schemas.py`.

## 4. Fields the pages need that nothing stores yet

- Alert `status` (open/closed) and `assigned_analyst` (analyst actions: assign, close, reopen)
- Source/destination IP, endpoint name: exposed today only inside `alert_metadata`
  (`source_ip`, `destination_ip`, `agent_name`) — keep those keys stable
- `mitre_ids` on the alert (present on the correlation fingerprint)

## 5. Pages that stay mock until the agent changes

- **Dashboard summary**: add `GET /api/v1/dashboard/summary?role=` aggregating the above
  (the frontend currently derives it in the browser)
- **Response policies**: expose the policy as data (`GET /api/v1/policies`); today it is code in `policy_engine.py`.
  The website now writes edits back with `PUT` (`base_version` check, 409 on a stale version, 422 on a broken rule),
  so the agent needs the same: versioned storage, the checks in `app/services/policies.py`, and the website's
  action vocabulary (see 6)
- **System health**: aggregate `runtime/status` plus dependency probes (Postgres, Ollama, MISP, Cortex, Wazuh).
  The website lists 10 services (OpenSearch, Suricata, LangGraph, Docker Engine and the Wazuh Dashboard are not probed
  by the agent yet), each with `group`, `category`, `endpoint`, `uptime_seconds` / `uptime_percent`, `check_key`, and a
  `starting` status
- **Users**: `operator_identity.py` holds operators; a read-only `GET /api/v1/users` would replace the placeholder
- **Notifications**: derive from pending approvals and degraded components, or keep browser-side
- **Audit for admin changes**: the browser writes its own admin and approval-flow events and hash-chains them;
  moving that server-side needs user, role and source IP on `IncidentAuditRecord`

## 6. Action vocabulary

The prototype uses `isolate_host`; the agent's structured actions are `block_ip`,
`lock_account`, `capture_telemetry`. Decide whether the agent gains host isolation
or the frontend policy engine drops it before the approvals page can go live.
