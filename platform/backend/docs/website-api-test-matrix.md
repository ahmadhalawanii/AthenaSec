# Website API test matrix

Status: **documentation only. No code, test or existing doc was changed.**
Sources: `backend/app/main.py` (route handlers, lines 2040-3250), `backend/tests/*.py` (read by test name, status-code asserts and fixtures), `backend/test-output.txt`, `backend/postgres-migration-verification.md`, `backend/api-identifier-mapping.md`.
No test was run to write this document (see "Unverified"). Every status code below comes from a handler or from an assert in the named test file.

## 1. Auth levels used in the table

| Level | What the code does | Failure statuses |
|---|---|---|
| **Read** | `require_approval_identity(authorization, request=request)`. Accepts a browser session cookie (needs `can_read_approvals`) or an operator `Authorization: Bearer ...` token (needs `can_read_approvals`). | 401 no/invalid credential. 403 no read permission. 503 when no operator identity store is configured (bearer path) or no browser store (cookie path). |
| **Admin session** | `require_admin`: browser session cookie whose role is `Administrator`. A bearer token is not accepted. | 401 no or forged session (and bearer-only). 403 analyst session. 503 when no browser auth store. |
| **Admin + CSRF** | Admin session, plus header `X-AthenaSec-CSRF` equal to the session's CSRF token. | As Admin session, plus 403 for a missing or wrong CSRF token. |
| **Decide** | `require_approval_identity(..., allow_decision=True)`: bearer needs `can_decide_approvals`; a cookie session needs CSRF and `can_decide_approvals`. | 401, 403 (no decide permission or no CSRF), 503. |
| **None** | The handler takes no auth argument. | n/a |

Shared behaviour on list routes: `limit` is 1..200 (`MAX_LIST_LIMIT`; 0, -1, 201 and non-numeric give **422**). A bad `cursor` gives **400**. Envelope is `{total, items, next_cursor}`. Error bodies are FastAPI `{"detail": "..."}`.

## 2. Route matrix

All paths are under `/api/v1`. "Empty state" is what the route returns when the backing store holds no rows, as asserted by the test (or read from the handler where marked *code*).

| # | Method and path | Auth | Success | Error statuses | Empty-state behaviour | Test file(s) |
|---|---|---|---|---|---|---|
| 1 | `GET /alerts` | Read | 200 | 400 bad cursor; 401; 403; 422 bad `limit` or `classification` | 200 `{total:0, items:[], next_cursor:null}` | `test_list_endpoints.py` (store-level: `test_investigation_list_stores.py`) |
| 2 | `GET /alerts/{alert_id}` | Read | 200 (`AlertDetail`) | 401; 403; 404 `"Alert {id} was not found."`; 405 for other methods | No list. Unknown id is 404. `event_text` is null when no incident alert record exists (*code*) | `test_alert_detail_and_dual_id.py` (fixture runs InMemory **and** SQLite) |
| 3 | `GET /investigations` | Read | 200 | 400; 401; 403; 422 | 200 `{total:0, items:[], next_cursor:null}`. Unknown `incident_id` filter also gives an empty list (*per mapping doc*) | `test_list_endpoints.py` (store-level: `test_investigation_list_stores.py`) |
| 4 | `GET /investigations/{id}` (alert id **or** `INV-...` id) | **None** | 200 | 404 `"Investigation {id} was not found."` (also for an `INV-` id with no stored summary) | No list. Unknown id is 404 | `test_alert_detail_and_dual_id.py` (InMemory + SQLite, pins "stays unauthenticated"); `test_list_endpoints.py` (list route does not shadow it); `test_api.py` (lookup after `/analyze`, 404, restart on SQLite) |
| 5 | `GET /investigations/{alert_id}/case` | **None** | 200 (legacy `CaseRecord`) | 404 `"Case for investigation {id} was not found."` | 404 when there is no case | `test_api.py` (found, 404, SQLite restart) |
| 6 | `GET /investigations/{alert_id}/audit` | **None** | 200 (list) | none defined | **200 `[]`** for an unknown alert, no existence check | `test_api.py` (`test_api_returns_investigation_audit_history`, `test_api_returns_empty_audit_history_for_unknown_alert`) |
| 7 | `GET /cases` | Read | 200 | 400; 401; 403; 422; 503 when migration 0004 tables are missing | 200 `{total:0, items:[], next_cursor:null}` | `test_cases_endpoints.py` |
| 8 | `GET /cases/{case_id}` | Read | 200 | 401; 403; 404 `"Case {id} was not found."`; 503 (same as 7) | No list. Unknown id is 404 | `test_cases_endpoints.py` |
| 9 | `GET /approvals` | Read | 200 | 400; 401; 403; 405 other methods; 422 | 200 `{total:0, items:[], next_cursor:null}` | `test_approval_list.py` (store-level `list_approval_requests`: `test_dashboard_summary.py`) |
| 9a | `GET /approvals/{approval_id}` (not in the request list, included because it shares the path) | Read | 200 | 401; 403; 404 `"Approval request was not found."`; 503 when no identity store is configured | No list. Unknown id is 404, not echoed | `test_approval_api.py`; also references the path: `test_operator_identity_gate.py`, `test_browser_auth.py`, `test_structured_runtime_api.py` |
| 9b | `POST /approvals/{approval_id}/decision` (same reason as 9a) | Decide | 200 | 401; 403; 404; 409 already decided or modified action; 503 | n/a | `test_approval_api.py` (404, 409 twice, 401, 503, 200 approve and reject), `test_operator_identity_gate.py`, `test_operator_identity_postgres.py` (**live Postgres identity store**; the approval and response stores in that test are InMemory) |
| 10 | `GET /audit` | Admin session | 200 | 400 bad cursor, or `since` after `until`; 401; 403; 422; 503 when the operator audit table is missing | 200 `{total:0, items:[], next_cursor:null, alert_events:[]}` | `test_audit_endpoints.py` |
| 10a | `GET /audit/verify` | Admin session | 200 | 401; 403; 503 | `test_empty_verify` asserts 200 on an empty chain | `test_audit_endpoints.py` (intact chain, tampering, not shadowed by `/audit/{event_id}`) |
| 10b | `GET /audit/{event_id}` | Admin session | 200 (operator `OPAUD-` id, else incident `AUD-` id) | 401; 403; 404 `"Audit event {id} was not found."`; 503 | No list. Unknown id is 404 | `test_audit_endpoints.py` |
| 11 | `GET /policies` | Read | 200 | 401; 403; 503 when the policy table is missing | 200 version-0 document: empty `whitelist`, `blacklist`, `protected_targets`, `enforced:false`, null `created_at`/`created_by`/`reason` | `test_response_policies.py` |
| 11a | `GET /policies/versions` | Read | 200 | 400; 401; 403; 422; 503 | 200 `{total:0, items:[], next_cursor:null}` | `test_response_policies.py` |
| 11b | `GET /policies/versions/{version}` | Read | 200 | 401; 403; 404 `"Policy version {n} was not found."`; 422 version < 1; 503 | Unknown version is 404 | `test_response_policies.py` |
| 11c | `PUT /policies` | Admin + CSRF | 200 (new version) | 401 no credentials or bearer token; 403 analyst, or missing/wrong CSRF; 409 stale `base_version`; 422 invalid policy; 503 policy or audit table missing | First save needs `base_version` 0 (a non-zero base is 409). Empty lists are a valid policy | `test_response_policies.py` |
| 12 | `GET /system/health` | Read | 200 | 401; 403 | Not applicable: always lists the ten website services in order. Services the agent does not probe are `unconfigured`, uptime fields are null. Still 200 when the event log is not migrated. Response is `Cache-Control: no-store` | `test_system_health.py` |
| 12a | `GET /system/events` | Read | 200 | 400 bad cursor, or `since` after `until`; 401; 403; 422; 503 when the health event table is missing | 200 `{total:0, items:[], next_cursor:null}` | `test_system_health.py` |
| 13 | `GET /users` | Admin session | 200 | 400; 401; 403; 422; 503 (no browser store, store without directory support, or users columns not migrated) | 200 `{total:0, items:[], next_cursor:null}` | `test_users_endpoints.py` (store-level SQL: `test_users_store.py`) |
| 13a | `GET /users/{user_id}` | Admin session | 200 | 401; 403; 404 `"User {id} was not found."`; 503 | Unknown id is 404 | `test_users_endpoints.py` |
| 14 | `GET /dashboard/summary` | Read | 200 | 401; 403 no read permission, or a non-administrator asking `role=Administrator`; 422 bad `window`/`role`; 503 when case workflow tables are missing | 200 with every count 0, `my_cases` 0, `response` null, `recent_alerts` `[]`, `series` `[]` ("all zeros, not missing") | `test_dashboard_summary.py` |

Read-only checks: tests assert that 405 is returned for write methods on the audit, users, system, dashboard and case routes, and that reading writes no state (`test_audit_endpoints.py`, `test_users_endpoints.py`, `test_system_health.py`, `test_dashboard_summary.py`, `test_cases_endpoints.py`).

Routes outside the requested families (auth, runtime, `/analyze`, Wazuh ingest, `/health`) are not in this matrix.

## 3. Routes with no test coverage, or only in-memory/SQLite coverage

### 3.1 Routes with no HTTP test

By searching `backend/tests` for each path string, **every route in section 2 has at least one HTTP test.** No route is entirely untested at the HTTP level.

### 3.2 Postgres is not tested at the HTTP level for any website route

`postgres-migration-verification.md` (item "Not verified") states: "The full HTTP routes against the migrated database. The suite uses the stores directly or mocks." That is still the position. Every route test above builds the app with InMemory stores, a fake store, or SQLite, and sends requests through `TestClient`.

What each route's backing store is exercised with, from test names and fixtures:

| Route(s) | Store call behind the route | HTTP test backend | Postgres coverage of that store call |
|---|---|---|---|
| 1 `GET /alerts` | `list_alerts` | InMemory | Mocked SQL only: `test_investigation_list_stores.py::test_postgres_list_alerts_joins_observed_at_and_filters`. Not live |
| 2 `GET /alerts/{id}` | `get`, `get_incident_alert` | InMemory **and** SQLite | `get` is in the live test (`test_postgres_live.py`, `PostgresInvestigationStore`). `get_incident_alert` on Postgres: no test found (only init, save, list by name in `test_incident_alert_store.py`, mocked). Unverified |
| 3 `GET /investigations` | `list_investigations` | InMemory | Mocked SQL only: `test_investigation_list_stores.py::test_postgres_list_investigations_joins_summary` |
| 4 `GET /investigations/{id}` | `get`, `get_incident_investigation` | InMemory and SQLite | `get`: mocked (`test_investigation_store.py`) and live (`test_postgres_live.py`). `get_incident_investigation` on Postgres: no test found by name (`test_incident_investigation_store.py` covers init and save, mocked). Unverified |
| 5 `.../case` | `get_case_by_alert_id` | SQLite restart test | Mocked (`test_investigation_store.py::test_postgres_store_gets_case_by_alert_id`) and live (`test_postgres_live.py` calls `get_case_by_alert_id`). The route itself is not run against Postgres |
| 6 `.../audit` | `list_by_alert_id` | InMemory | Mocked (`test_audit_store.py`) and live (`test_postgres_live.py`, `PostgresAuditStore`) |
| 7, 8 `/cases` | `list_all_incident_cases`, `get_incident_case`, workflow reads | InMemory | `list_all_incident_cases`: mocked SQL only (`test_case_workflow_store.py`). `get_incident_case` on Postgres: no test found by name. `PostgresCaseWorkflowStore`: mocked, plus a manual live check outside the repo (see 3.3) |
| 9 `GET /approvals` | `list_approval_requests` | InMemory | Mocked SQL only: `test_dashboard_summary.py::test_postgres_list_approval_requests_binds_status`. Not live |
| 9a, 9b approval get and decision | `get_approval_request`, `transition_pending_approval` | InMemory | The decision race is **live**: `test_atomic_approval_decisions.py::test_parallel_competing_decisions_real_postgres` (skipped without `ATHENASEC_TEST_PG_URL`). The HTTP routes against a Postgres response store: none |
| 10 `/audit*` | `PostgresOperatorAuditStore`, `list_incident_events`, `get_incident_event` | InMemory | Operator audit: mocked (`test_operator_audit_store.py`) plus manual live check (3.3). Incident events: mocked (`test_incident_audit_listing.py`) |
| 11 `/policies*` | `PostgresResponsePolicyStore` | InMemory | Mocked (`test_response_policy_store.py`) plus manual live check (3.3) |
| 12 `/system/*` | `PostgresHealthEventStore` | InMemory and SQLite store tests | Mocked (`test_system_health.py`) plus manual live check (3.3) |
| 13 `/users*` | `PostgresBrowserAuthStore.list_users/get_user` | A fake directory store in-test | Recording-connection SQL tests only (`test_users_store.py`). The live browser-auth test (`test_browser_auth_postgres.py`) covers login, MFA, cookie, revocation and replay, not the user directory |
| 14 `/dashboard/summary` | Aggregates over several stores | InMemory | `list_approval_requests` mocked; other store calls as above |

SQLite coverage at the HTTP level exists only for routes 2 and 4 (the `store` fixture in `test_alert_detail_and_dual_id.py` is parametrised `memory` and `sqlite`) and for the SQLite restart tests in `test_api.py` (routes 4 and 5). The other route test files set `ATHENASEC_PERSISTENCE_BACKEND=sqlite` and `ATHENASEC_DB_PATH` to a temp file, but pass InMemory stores into `create_app`, so SQLite is not what those requests read.

### 3.3 Manual live checks that are not in the repo

`postgres-migration-verification.md` section 7 records a script, kept **outside the repo**, that drove `PostgresOperatorAuditStore`, `PostgresResponsePolicyStore`, `PostgresCaseWorkflowStore` and `PostgresHealthEventStore` against real Postgres (18 of 20 checks passed; the 2 failures were artefacts of a re-run). That script is not a test in `backend/tests`, so it does not run with the suite and cannot be re-run from this repo. The four stores are therefore **not** covered by any live pytest test.

### 3.4 Other gaps recorded elsewhere

- Routes 4, 5, 6 have **no authentication** (`api-identifier-mapping.md` section 7). Only route 4 has a test that pins this (`test_investigation_route_stays_unauthenticated`). Whether `test_api.py` sends credentials for routes 5 and 6 was not checked.
- `PostgresCaseWorkflowStore.save_workflow` for an unknown `case_id` raises a raw `psycopg.errors.ForeignKeyViolation` (verification doc, difference 1). No route test covers it. A route that writes a case that does not exist would return 500 unless it checks first.
- The 409 detail strings on the approval decision route for causes other than "already decided" or "modified action" were not traced (`api-identifier-mapping.md` section 6).

## 4. Unverified

- **No test was run for this document.** `pytest` is not installed in the Python found on this machine (`C:\Users\Asus\AppData\Local\Python\pythoncore-3.14-64\python.exe`, 3.14.7). Status codes come from reading handlers and test asserts.
- `test_list_pagination.py` and `test_cors.py` were not read. They may add coverage for list routes that is not listed here.
- `test_operator_identity_gate.py`, `test_browser_auth.py` and `test_structured_runtime_api.py` reference the approval paths; only `test_approval_api.py` was read for assertions.
- Whether `POST /approvals/{id}/decision` returns 422 for an invalid body is not asserted in any test I read.
- Whether a Postgres-backed `get_incident_alert`, `get_incident_investigation` and `get_incident_case` work was not found in any test by name; this is a gap in what was searched (names only), not a confirmed failure.
- Tests that pass with the current `test-output.txt` do not include the tests added after it was written (see `evidence-bundle.md`).
