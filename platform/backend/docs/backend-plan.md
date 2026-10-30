# Agent backend plan (no dataset)

Status: **design only. No code, migration or dependency has been changed.** Branch `feature/api-list-endpoints`.
Builds on the finished `GET /api/v1/alerts`, `GET /api/v1/investigations`, CORS and `list_pagination.py`.
It supersedes the endpoint side of `database-plan.md`, which stays as the detailed SQL reference (tables M1 to M7).

**Reconciled** against `../AthenaSec-Ahmed-Website/website/docs/agent-integration.md` (read with your approval). Differences are in
section 6, which overrides the page tables below where they disagree. The page tables are otherwise the pre-read version.

## 0. Ground rules

- **No data in app code.** No seed rows, defaults that look like records, or fixtures outside `tests/`. An empty page is
  `{"total": 0, "items": [], "next_cursor": null}`. Migrations create empty tables only.
- **Error format: keep FastAPI's** `{"detail": "<string>"}` (every existing route uses it, and existing tests assert it).
  Codes: 400 bad cursor/filter, 401 no valid identity, 403 missing permission or CSRF, 404 unknown id, 409 state or
  `version` conflict, 422 FastAPI body/query validation (its default list-shaped `detail`), 503 store unavailable.
  No new envelope, so the frontend and 946 tests are not disturbed.
- **List shape and paging:** reuse `paginate()` (`limit` 1 to 200, default 50, opaque `cursor`, newest first). Filters
  are query params. `total` is the filtered count.
- **Auth, from existing code** (`main.py` `require_approval_identity`, `require_web_session`):
  - `Read` = browser session cookie or operator bearer token with `can_read_approvals`.
  - `Decide` = `can_decide_approvals` plus CSRF header on browser sessions (existing approval decision rule).
  - `Write` (new mutations) = `Read` plus the `X-AthenaSec-CSRF` header, same as `decide_approval`.
  - `Admin` = **new** `require_admin`, browser session only, `role == "Administrator"` (bearer identities have no
    role, so they get 403). Plus CSRF on writes.
  - Operator control key (`/runtime/control`) is untouched.
- **Stores:** every new store has `InMemory`, `SQLite` and `Postgres` classes behind a Protocol, optional in
  `create_app()` with an in-memory default so existing callers and tests keep working. Exception: user data lives in the
  Postgres-only auth store (see 2.7).
- **Migrations:** the repo has **no Alembic** (`database-plan.md` 1.1). Step 0 adds the scaffold. Alembic manages
  Postgres only, with raw SQL; SQLite tables are code-created in the store constructor as today. Constructor DDL for
  existing tables is left alone (tests assert it).
- **Do not touch:** ML, graph nodes, grounding, `risk_engine`, `policy_engine`, `structured_action_policy`, Cortex
  executors. The new routes read their output only.

## 1. Build order

| Step | Page | New table | Depends on |
|---|---|---|---|
| 0 | Alembic scaffold, baseline `0001` (stamp-only on live DBs), `compose.yaml` backend fix | none | none |
| 1 | Users | `ALTER athenasec_web_users` (M3) | 0 |
| 2 | Audit logs | `operator_audit_events` (M7) + writer | 0, 1 |
| 3 | Approvals / incident response | none | 2 (decide already audits; add actor) |
| 4 | Cases | `case_workflow`, `case_actions`, `case_timeline` (M2) | 1, 2 |
| 5 | Dashboard summary | none (computed) | 3, 4 |
| 6 | Response policies | `response_policy_versions` (M5) | 2 |
| 7 | System health | `health_events` (M6) | 2 |
| 8 | Notifications | none (derived); optional `notification_state` (M4) | 3, 7 |

Reasoning: audit comes before the pages that mutate, so every write emits an event from day one. Dashboard waits for
the data it summarises. Alert assign/close (M1 `alert_workflow`, `GET /alerts/{id}`) is **not in your page list**; it is
listed as optional step 4b because the Cases page needs an alert owner. Say if you want it in scope.

---

## 2. Pages

Common to every list: `GET` returns `XListResponse {total:int, items:[X], next_cursor:str|null}`.

### 2.1 Step 1, Users

| | |
|---|---|
| Endpoints | `GET /api/v1/users` (filters `role`, `active`, `q`), `GET /api/v1/users/{user_id}`, `POST /api/v1/users` (create), `PUT /api/v1/users/{user_id}` (name, department, phone, role, permission flags; writes come after audit, users start read-only), `POST /api/v1/users/{user_id}/suspend`, `POST .../reactivate` |
| Response `User` | `user_id, email, name, role (Analyst/Administrator), department, phone, active, mfa_enabled (always true, derived), can_read_approvals, can_decide_approvals, created_at, last_login_at|null`. Never returns password digest, salt or TOTP secret |
| Request | create: `email, name, role, department?, phone?, password`. patch: any subset, plus `version` is not needed (admin-only, low contention) |
| Table | existing `athenasec_web_users` plus 4 columns (M3: `department`, `phone`, `created_at`, `last_login_at`) |
| Exists? | table yes, columns no. `provision_user` and `disable_user` exist; no list, get, update or reactivate |
| Migration | `0002_users_profile_columns`: additive `ADD COLUMN ... DEFAULT`, no data written |
| Permissions | all `Admin`. A user may read their own record through the existing `/auth/me` |
| Errors | 404 unknown id, 409 duplicate email, 409 disabling the last active administrator, 422 bad email/role, 503 when no auth store |
| Storage tiers | Postgres only (auth is Postgres-only today). The route returns 503 on SQLite, same as `/auth/login`. Tests use an in-memory fake that implements the same Protocol. **Decision D2** |
| Writes also | `last_login_at` set in `complete_mfa`; each mutation writes an `operator_audit_events` row (from step 2 on; step 1 ships first without it, see risk R9) |

### 2.2 Step 2, Audit logs

| | |
|---|---|
| Endpoints | `GET /api/v1/audit` (filters `actor`, `category`, `result`, `since`, `until`, `incident_id`, `q`), `GET /api/v1/audit/{event_id}`, `GET /api/v1/audit/verify` (walks the hash chain, returns `{valid, checked, first_broken_seq|null}`) |
| Response `AuditEvent` | `event_id, occurred_at, actor_id, actor_role, category, action, target, result (Success/Failed/Denied), source_ip|null, source ("operator" or "incident"), incident_id|null, detail{}, prev_hash, row_hash` |
| Table | new `operator_audit_events` (M7, hash chain). Existing `incident_audit_events` (per-incident agent events) is **read and merged**, never altered; merged rows carry `source="incident"`, null hashes |
| Exists? | incident side yes (`list_by_incident_id` only; needs a cross-incident `list_incident_events(filters)` on the three backends). Operator side no |
| Migration | `0003_operator_audit_events`: table, indexes, `REVOKE UPDATE, DELETE` for the app role if one is configured |
| Permissions | `Admin` for list, get and verify (audit includes IPs and actor ids). Open **D3**: should Analysts read their own events |
| Writer | `OperatorAuditWriter.append(actor, category, action, target, result, ...)` single serialised append (`pg_advisory_xact_lock`) used by every later mutation. No public POST |
| Errors | 404 unknown event, 400 bad cursor or `since > until`, 422 bad `result` |
| Empty | `{total:0, items:[], next_cursor:null}`; `verify` on empty returns `{valid:true, checked:0}` |

### 2.3 Step 3, Approvals / incident response

| | |
|---|---|
| Endpoints | `GET /api/v1/approvals` (filters `status`, `incident_id`, `since`), existing `GET /api/v1/approvals/{id}` and `POST .../decision` (unchanged contract). Response-action history: `GET /api/v1/incidents/{incident_id}/response` returning proposed actions, policy decision, approval, action results, verifications and rollbacks for one incident. Optional `POST /api/v1/approvals/{id}/rollback` is **out of scope** (touches Cortex/rollback logic) |
| Response `ApprovalListEntry` | `ApprovalRequestRecord` fields plus joined, read-only `action_type, target, risk_score, risk_band, policy_outcome, expires_at` (from the proposed action, risk and policy records, no recompute) |
| Table | none. Reads `approval_requests`, `proposed_actions`, `action_risk_assessments`, `incident_policy_decisions` |
| Exists? | get and decide yes. **No list method** exists on `IncidentResponseStore` (only `list_incident_cases` by incident). Add `list_approval_requests(status, incident_id, since)` on InMemory, SQLite, Postgres (indexed by `status, created_at`; may need an index added in migration `0004`, no data) |
| Migration | `0004_approval_requests_indexes` (index only), or none if payload scan is acceptable at first |
| Permissions | list and get `Read`. decision unchanged (`Decide` + CSRF). The decision route additionally writes an operator audit event with the real actor |
| Errors | 404 unknown id, 409 already decided (existing), 400 bad cursor, 422 bad `status` |
| Risks | the join must not call risk/policy engines, only read stored rows. Missing joined row yields nulls, not a 500 |

### 2.4 Step 4, Cases

| | |
|---|---|
| Endpoints | `GET /api/v1/cases` (filters `status`, `assigned_to`, `incident_id`, `q`), `GET /api/v1/cases/{case_id}`, `PUT /api/v1/cases/{case_id}` (assignee, summary override, status; requires `version`), `POST /api/v1/cases/{case_id}/notes` (timeline note), `PUT /api/v1/cases/{case_id}/actions/{position}` (tick done) |
| Response `Case` | `case_id, incident_id, investigation_id|null, status (IncidentCaseStatus), reason, assigned_to|null, summary, endpoint|null, source_ip|null, mitre[], evidence[], actions[{position,label,done,approval_id|null}], timeline[{seq,occurred_at,title,description,failed,author}], version, created_at, updated_at, closed_at|null`. `summary, endpoint, source_ip, mitre, evidence` are **derived at read time** from the investigation and alert metadata, not copied. Agent steps appear in `timeline` merged with stored analyst notes |
| Table | existing `incident_cases` (base) plus new `case_workflow`, `case_actions`, `case_timeline` (M2). Legacy `cases` is **not** exposed in v1 (decision **D1**) |
| Exists? | `incident_cases` yes with `list_incident_cases(incident_id)` only. Need `list_all_incident_cases(filters)`, `get_incident_case` joined view, and workflow store methods on all three backends |
| Migration | `0005_case_workflow`: three empty tables, FKs `NOT VALID` (risk R4) |
| Permissions | list and get `Read`. PUT, note and tick are `Write` (CSRF); reassigning to another user requires `Admin` |
| Errors | 404 case or action, 409 `version` mismatch (R8), 409 invalid status transition, 422 body |
| Empty | a case with no workflow row reads as unassigned, no notes, derived fields, `version=1`. No backfill |

### 2.5 Step 5, Dashboard summary

| | |
|---|---|
| Endpoint | `GET /api/v1/dashboard/summary?window=24h|7d|30d` |
| Response `DashboardSummary` | `window, generated_at, alerts{total, by_classification{}, by_risk_band{}, open}, investigations{total, by_status{}}, approvals{pending, decided}, cases{open, by_status{}}, response{mode, effective_execution_enabled}, recent_alerts[] (max 5, `AlertListEntry`), series[{bucket_start, alerts}]` |
| Table | none. Computed from existing list store methods (alerts, investigations, approvals, cases, runtime status) |
| Exists? | no |
| Migration | none |
| Permissions | `Read` |
| Errors | 422 bad `window` |
| Empty | all counts 0, dicts empty, `recent_alerts: []`, `series: []`. Zero is real data, not a placeholder |
| Risk | computing from full `list_*` scans is O(n); fine for v1, add `count_*` store methods if slow. Cache is **not** added |

### 2.6 Step 6, Response policies

| | |
|---|---|
| Endpoints | `GET /api/v1/policies/current`, `GET /api/v1/policies/versions` (list), `GET /api/v1/policies/versions/{version}`, `PUT /api/v1/policies/current` (append a new version; requires `base_version`) |
| Response `PolicyDocument` | `version, whitelist[{value,type,note}], blacklist[...], protected_targets[...], created_at, created_by, reason`. `protected_targets` is read from the existing `target_protection_*` store, not duplicated |
| Table | new `response_policy_versions` (M5, append-only) |
| Exists? | no. Policy logic stays in code and is **not** read from this table (display-only, **D4**), so nothing in risk/policy changes |
| Migration | `0006_response_policy_versions` |
| Permissions | GET `Read`. PUT `Admin` + CSRF, writes an audit event |
| Errors | 409 `base_version` stale, 422 bad entry type or empty value, 404 unknown version |
| Empty | `current` returns `{version:0, whitelist:[], blacklist:[], protected_targets:[...from target store...]}` with no row stored |

### 2.7 Step 7, System health

| | |
|---|---|
| Endpoints | `GET /api/v1/system/health` (services, metrics), `GET /api/v1/system/events` (list, filters `severity`, `since`) |
| Response | `services[{name, status (up/degraded/down/unconfigured), latency_ms|null, checked_at, detail}]` for database, Ollama, MISP, Cortex, Wazuh indexer; `metrics{uptime_s, version, response_mode, persistence_backend}`; `events` is a normal list of `{event_id, occurred_at, severity, source, message}` |
| Table | new `health_events` (M6), written only when a probe changes state. Live status is probed per request and **not stored** |
| Exists? | no. `/health` and `/runtime/status` exist and are unchanged |
| Migration | `0007_health_events` |
| Permissions | `Read`. Probe targets and error text are trimmed so no URL or credential leaks |
| Errors | 422 bad `severity`. A failing probe is reported in the body, never a 5xx |
| Empty | services not configured report `unconfigured`; events `[]` |
| Risk | probes must have short timeouts and run concurrently so the endpoint cannot hang |

### 2.8 Step 8, Notifications

| | |
|---|---|
| Endpoints | `GET /api/v1/notifications` (filter `unread`), `POST /api/v1/notifications/{key}/read`, `POST /api/v1/notifications/read-all` |
| Response `Notification` | `key (stable, e.g. approval:APR-1), kind, severity, title, message, created_at, read, link` |
| Table | derived from pending approvals and degraded services. Per-user `read` state in optional `notification_state` (M4) |
| Exists? | no |
| Migration | `0008_notification_state` only if read state must persist (**D5**); otherwise none and the browser keeps read state |
| Permissions | `Read`, scoped to the caller's own state |
| Errors | 404 unknown key, 422 |
| Empty | `[]` |

---

## 3. Per-step test plan (all fixtures inside `tests/`)

For each endpoint: 200 shape (field set, types, `next_cursor`), empty state, filter and pagination (limit, cursor, bad cursor
400), 404, 422, auth (no credential 401, read-only credential on a write 403, missing CSRF 403, Admin gate), 409 where
specified. Store tests: InMemory, SQLite (temp file) and Postgres (`MagicMock` connection, matching the existing style) for
every new method. One opt-in migration test, skipped unless `ATHENASEC_TEST_DATABASE_URL` is set, runs `alembic upgrade head`
on an empty DB and from a `stamp 0001` DB. The 9 existing skips stay at 9 when it is unset.
After each step, from `agent/`: `pytest`, expect **>= 946 passed, 9 skipped**, then report and wait.

## 4. Risks

**To existing data**
- R1 Baseline `0001` must match the live schema; generate it from a `pg_dump --schema-only` and diff. Use `stamp`, never `upgrade`, on live DBs.
- R2 Only the step 1 migration alters an existing table (`athenasec_web_users`), additive with constant defaults, short lock.
- R3 Constructor DDL and Alembic can drift. New Postgres objects live only in Alembic; add a test that every constructor-created table is in the baseline.
- R4 FKs to `incident_cases` / `athenasec_web_users` can hit orphan rows; create them `NOT VALID`.
- R5 Two case tables (`cases`, `incident_cases`); v1 exposes `incident_cases` only (D1).
- R6 Alerts `?status=` currently means pipeline status. If M1 ships, rename or version before changing it.
- R7 Hash chain forks without a single serialised writer; tamper-detect only unless the DB role cannot UPDATE/DELETE.
- R8 Analyst edits racing the agent writing the same case: `version` check, 409 on mismatch.
- R9 Step 1 mutations land before the audit writer (step 2). Either ship step 1 read-only first, or accept an un-audited window. Recommend: step 1 read-only (`GET` only), add writes after step 2.
- R10 Postgres is the default backend; SQLite runs have no auth, so `users`, and every `Write`/`Admin` route, are exercisable only on Postgres or with injected fakes.

**To the 946 passing tests**
- Safe by construction: all new args to `create_app()` optional, no change to existing routes' contracts, no change to constructor DDL.
- Can break: editing `list_alerts` / `list_investigations` SQL (Postgres tests assert `LEFT JOIN incident_alerts`), reordering or rewording constructor DDL, adding a required `create_app` argument, changing CORS (decision 7: PUT and POST only, `test_cors.py` untouched).
- `requirements.txt` gains `alembic` and `sqlalchemy` (D6); install must succeed in the test environment before step 0 is verified.
- Alembic files are not imported by the app, so they cannot affect collection.

## 5. Decisions (answered)

Answered: 1 incident_cases only; 2 users Postgres-only, 503 elsewhere; 3 audit admin-only; 4 policies display-only; 5 notification read state in the browser, no table; 6 Alembic with raw SQL, no ORM models; 7 PUT/POST only, CORS and `test_cors.py` untouched; 8 no alert assign/close; 9 notes read (section 6). Original questions, for the record:

1. **D1** Cases v1 on `incident_cases` only (recommended), or also legacy `cases`?
2. **D2** Users on Postgres only with 503 elsewhere (recommended), or build a SQLite auth store too?
3. **D3** Audit read: Admin only (recommended), or Analysts see their own events?
4. **D4** Policies display-only for now (recommended, nothing in risk/policy changes), or should they drive the agent later?
5. **D5** Notification read state: browser-only (recommended) or a table?
6. **D6** Alembic + SQLAlchemy dependency with raw-SQL migrations (recommended), or a small hand-rolled numbered-SQL runner?
7. Add `PATCH` to CORS (needed for steps 1, 4), or use `POST`/`PUT` only? Recommend `PUT`/`POST` to leave CORS untouched.
8. Include optional alert assign/close (step 4b)?
9. Copy `agent-integration.md` into `agent/` (or approve reading it from `../AthenaSec-Ahmed-Website/website/docs/`) so schemas can be reconciled before step 0.

## 6. Reconciliation with `agent-integration.md`

The notes are the website team's view. Items marked **OPEN** need your decision before the page they affect is built.

| # | Topic | `agent-integration.md` says | This plan said | Effect |
|---|---|---|---|---|
| 1 | **Error format** | `{"error": {"code","message","details"}}` so the frontend parses one shape | Keep FastAPI `{"detail": ...}` | **OPEN, affects every page.** Switching changes existing routes and any test asserting `detail`. Options: (a) keep `detail`, frontend adapts; (b) new envelope on new routes only (two shapes in one API); (c) global exception handlers for the new envelope and update the existing tests |
| 2 | Case source | `GET /cases` over legacy `CaseRecord` (filters `status`, `alert_id`); widen `CaseStatus` to `IncidentCaseStatus` | `incident_cases` only (your answer 1); filters `status, assigned_to, incident_id, q` | Add an `alert_id` filter resolved through the investigation. Response is `IncidentCaseRecord` plus derived fields, not `CaseRecord`; `policy_id, classification, risk_score, risk_band` are derived from the stored policy decision and risk records |
| 3 | Case field names | `assigned_analyst, endpoint, source_ip, summary, evidence[], recommended_actions[], mitre_ids[], timeline[]` | `assigned_to, ..., actions[], mitre[]` | **Rename to the website names** (`assigned_analyst`, `recommended_actions`, `mitre_ids`) so adapters need no mapping |
| 4 | Detail routes | `GET /investigations/{id}` accepts `INV-...` and `alert_id`; add `GET /alerts/{alert_id}` and `GET /cases/{case_id}` | only `GET /cases/{id}` | **Add** `GET /alerts/{alert_id}` (read-only, no assign/close) and let investigation get accept both ids. The second edits an existing route, so it needs a regression test |
| 5 | Alert `status` / `assigned_analyst` | assign, close, reopen | out of scope (answer 8) | Alert list keeps the pipeline `status`; the website's open/closed and assignee stay mock |
| 6 | Audit | `GET /audit`: `IncidentAuditRecord` plus legacy `AuditRecord` as `alert_events`; filters `alert_id, incident_id, event_type, since, until`; store `list_all()` | merged `AuditEvent`; filters `actor, category, result, since, until, incident_id, q` | Add filters `alert_id`, `event_type`; return legacy records as `alert_events`. Admin-only (answer 3) |
| 7 | Admin audit events | extend `IncidentAuditRecord` with user, role, source IP | separate `operator_audit_events` table | **OPEN.** Recommend keeping the separate table: `incident_audit_events.incident_id` is NOT NULL, login and user events have no incident, and the hash chain should not alter agent history |
| 8 | Approvals list | approval + proposed action + action risk + policy decision; filter `status` | same join, more filters | Matches |
| 9 | Dashboard | `GET /dashboard/summary?role=` | `?window=` | Support both: `role` (default from the caller) and `window` |
| 10 | Policies | `GET /api/v1/policies`; website **writes** with `PUT` + `base_version`, 409 stale, 422 broken rule; checks in `app/services/policies.py`; website action vocabulary | `/policies/current` + versions; display-only (answer 4) | Use `/api/v1/policies` for GET and PUT. **Conflict:** answer 4 says read-only but the notes say the website writes. **OPEN:** either PUT stores a versioned document that the agent never reads (risk/policy logic untouched), or the policies page becomes read-only |
| 11 | Action vocabulary | prototype uses `isolate_host`; agent has `block_ip`, `lock_account`, `capture_telemetry` | not addressed | **OPEN, blocks the approvals page going live.** Not a backend change I can make (it touches policy). Needs a decision by you and the website team |
| 12 | System health | 10 services, each with `group, category, endpoint, uptime_seconds/uptime_percent, check_key`, statuses incl. `starting`; five (OpenSearch, Suricata, LangGraph, Docker Engine, Wazuh Dashboard) not probed by the agent | 5 probes, statuses up/degraded/down/unconfigured, no group/category | Widen the schema to the website's fields and add `starting`. Unprobed services report `unconfigured` with null uptime; nothing invented |
| 13 | Users | `operator_identity.py` holds operators; read-only `GET /users` | `athenasec_web_users` (browser accounts) | **OPEN.** Two stores: `athenasec_operator_identities` (bearer tokens, read/decide flags, no name/email/role) and `athenasec_web_users` (name, email, role). The website's fields fit the web users table, so I plan read-only `GET /users` over it. Confirm |
| 14 | Notifications | derive, or keep browser-side | derived; read state in the browser (answer 5) | Matches. Drop `POST .../read` and `read-all` and the optional table |
| 15 | List envelope, CORS, alerts, investigations | `{total, items, next_cursor}`, `limit`, `cursor`; CORS `GET, POST, PUT` | same | Matches (already built) |

Net changes to the plan from this read: rename case fields (3); add `GET /alerts/{id}` and dual-id investigation get (4); audit filters and
`alert_events` (6); `role` param on the dashboard (9); `/api/v1/policies` path (10); wider health schema (12); drop notification write endpoints (14).
**Open items needing you: 1, 7, 10, 11, 13.**

## 7. Decisions on the open items (recorded)

| # | Decision |
|---|---|
| 1 Error format | Keep FastAPI `{"detail": ...}` on all routes. The website adapter must map it. |
| 2 Operator audit | Separate `operator_audit_events` table. `incident_audit_events` is not altered. |
| 3 Response policies | **DISPLAY / STORAGE ONLY. THE AGENT NEVER READS THIS DOCUMENT.** `PUT /api/v1/policies` appends a versioned document (`base_version` check, 409 stale, 422 invalid). Nothing in `risk_engine`, `policy_engine`, `structured_action_policy` or Cortex reads it, so saving a policy changes no agent behaviour. The API and UI must say so (response field `enforced: false`). Making it enforced is a separate, future change to policy logic. |
| 4 Action vocabulary | `isolate_host` vs `block_ip` / `lock_account` / `capture_telemetry` is **unresolved**. |
| 5 Users | Read-only `GET /api/v1/users` over `athenasec_web_users`. |

### Blocked items

- **Approvals / incident response page, live wiring: BLOCKED** on the action vocabulary decision (item 4). The read-only `GET /api/v1/approvals` list can be built, but the page is not wired live until the decision is made. In the build order, step 3 is skipped for the live page until then.

### Step status

| Step | Status |
|---|---|
| 0 Alembic scaffold, baseline `0001`, compose fix | Done |
| 1 Users (read-only): `GET /api/v1/users`, `GET /api/v1/users/{user_id}`, migration `0002` | Done, awaiting OK |
| 2 Audit logs | Next |
| 3 Approvals | Blocked for live wiring (decision 4) |
| 4 to 8 | Not started |

Users notes: writes (create, update, suspend) are not built; they come after the audit writer (step 2). `last_login_at` and `created_at` are read
from the columns when set and otherwise from `athenasec_web_auth_events`; nothing writes the new columns yet.

### Step 2 (Audit logs): done, awaiting OK

Routes (admin only, browser session): `GET /api/v1/audit`, `GET /api/v1/audit/{event_id}`, `GET /api/v1/audit/verify`. Migration `0003_operator_audit_events` (empty table, indexes, append-only triggers; no downgrade).
Differences from the M7 sketch: `detail` and `source_ip` are TEXT (canonical JSON / normalised address), not JSONB / INET, so the hashed bytes are the bytes read back; tamper protection is by triggers on UPDATE, DELETE and TRUNCATE rather than only a REVOKE.
`alert_id` filters items by target and also fills `alert_events` with the legacy per-alert records (empty otherwise). `incident_id` excludes operator events, which have no incident.
Nothing in the app writes operator events yet; `append_event()` is the single writer for later steps. Truncation of the newest rows is not detectable from the log alone: `verify` returns `head_hash` for an external monitor to pin.

### Step 4 (Cases, read-only): done, awaiting OK

Routes (`Read` access: browser session of either role, or bearer token, with the read permission): `GET /api/v1/cases`, `GET /api/v1/cases/{case_id}`. Migration `0004_case_workflow` creates `case_workflow`, `case_actions`, `case_timeline` empty (no downgrade).
Source is `incident_cases` only. Fields use the website names (`assigned_analyst`, `recommended_actions`, `mitre_ids`). Derived at read time from the investigation: summary (analyst override wins), evidence, endpoint (`agent_name`), source IP, MITRE ids (correlation profile, else alert metadata), classification, risk, policy id, agent timeline. Default `recommended_actions` come from proposed actions; stored `case_actions` override them.
Differences from the M2 sketch: `case_actions` has `proposed_action_id` instead of `run_id`; the assignee column is `assigned_analyst`; no foreign key from `assigned_analyst` to users (the tables must work where the users table does not exist).
Store write methods exist (workflow upsert, replace actions, append note) for later steps and tests, but no route writes. The list builds every case from several lookups, which is fine at current scale; add counts or a lighter list entry if it gets slow.

### Step 5 (Dashboard summary): done, awaiting OK

Route (`Read` access): `GET /api/v1/dashboard/summary?window=24h|7d|30d&role=Analyst|Administrator`. No table, no migration; computed per request, nothing cached.
Event counts (alerts, investigations, decided approvals, cases opened) cover the window; backlog counts (pending approvals, active cases) are current and ignore it. Series is hourly for 24h and daily for 7d/30d, zero-filled, and `[]` when the window has no alerts.
`role` selects the view and cannot widen access: the Analyst view adds `my_cases` (active cases assigned to the caller); the Administrator view adds `response` (mode and execution flags). Requesting the Administrator view without an Administrator browser session is 403. Default is the caller's own role, Analyst for bearer tokens.
Differences from the sketch: `alerts.open` is replaced by `alerts.by_status` (pipeline status; open/closed alert workflow is out of scope); `cases.open` is `cases.active` (not resolved or closed) to avoid clashing with the `open` status. The integration notes do not define what `role` changes, so the view above is a proposal to confirm with the website team.
Adds one additive store method, `IncidentResponseStore.list_approval_requests(status=None)`, because no approval listing existed. It is a read and does not wire the approvals page, which stays blocked on the `isolate_host` decision.

### Step 6 (Response policies): done, awaiting OK

**STORED DOCUMENT ONLY. THE AGENT NEVER READS IT; every response carries `enforced: false` (a `Literal[False]`, so it cannot be true) and an `enforcement_note`.** No risk, policy, graph or Cortex code was changed. A test fails if any agent module imports the policy store.
Routes: `GET /api/v1/policies` (current; `Read` access), `GET /api/v1/policies/versions`, `GET /api/v1/policies/versions/{version}`, `PUT /api/v1/policies` (Administrator browser session plus CSRF; `base_version` check, 409 when stale, 422 when invalid; writes an operator audit event). Migration `0005_response_policy_versions` creates the empty append-only table (triggers block UPDATE, DELETE, TRUNCATE; no downgrade).
Document: `whitelist` and `blacklist` entries `{value, type: ip|cidr|hostname|account, note}`, validated and normalised. 422 for: bad IP/CIDR (host bits set or `/0` rejected)/hostname/account, duplicates, an entry in both lists, over 1000 entries, empty or over-long reason, unknown or extra fields. `protected_targets` is a read-only view of the agent's real target-protection state (which IS enforced) and is rejected if sent in a PUT.
Open: the entry schema above is my design; the website's real rule format and its action vocabulary (`isolate_host`) are not reconciled, so entries carry no actions. Reconcile before wiring the Policies page.

### Step 7 (System health): done, awaiting OK

Routes (`Read` access): `GET /api/v1/system/health`, `GET /api/v1/system/events` (filters `severity`, `source`, `since`, `until`; paged). Migration `0006_health_events` creates the empty table (no downgrade); it adds a `status` column to the first sketch, which change detection needs. No append-only triggers: this is an operational log, not an audit log.
Ten services in the website's order. Five are probed (PostgreSQL, Ollama, MISP, Cortex, Wazuh Indexer, each read-only with a 3 s timeout, run concurrently); OpenSearch, Suricata, LangGraph, Docker Engine and Wazuh Dashboard have no probe and are reported `unconfigured` with null latency, endpoint and check time. Statuses: up, degraded (slow over 1.5 s, credentials rejected, Wazuh cluster yellow), down, starting (a failure in the first 60 s after the agent started), unconfigured. `uptime_seconds` and `uptime_percent` are always null because the agent does not track uptime. Probe failures report a fixed generic detail, never exception text; endpoints are `scheme://host:port` only.
`group` and `category` labels, and the `check_key` values, are my choice; reconcile with the website's. The one write: `GET /system/health` appends a `health_events` row when a probed service's status differs from the last recorded one (a first `up` or `unconfigured` records nothing). If that table is not migrated the page still works and reports `event_log: "unavailable"`.
