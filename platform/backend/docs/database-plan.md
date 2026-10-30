# Agent database plan

Status: **proposal only. No migration, dependency or schema change has been made.**
Branch `feature/api-list-endpoints`. Sources: `app/services/*_store.py`,
`persistence_config.py`, `web_auth.py`, `operator_identity.py`, and the website
types in `AthenaSec-Ahmed-Website/website/frontend/src/types/`.

## 1. Current state

### 1.1 There is no Alembic setup

- No `alembic.ini`, no `migrations/` or `versions/` directory, and `alembic` and `sqlalchemy` are not in
  `requirements.txt`. The only mention is a `pip install alembic` line in the website's
  `docs/modifications.md`.
- Schema is created by each store's constructor with `CREATE TABLE IF NOT EXISTS`.
  The only in-place change ever made is one SQLite `ALTER TABLE audit_records ADD COLUMN timestamp`
  (`audit_store.py:213`). There is no schema-version table, so nothing records which version a database is on.
- The existing tests assert that SQL is executed in the constructors (for example
  `"CREATE TABLE IF NOT EXISTS incident_investigations"` in `test_incident_investigation_store.py`).
  Removing constructor DDL would break them.

### 1.2 Which store is the default

`ATHENASEC_PERSISTENCE_BACKEND` defaults to **`postgres`** (needs `ATHENASEC_DATABASE_URL`).
SQLite is opt-in (`ATHENASEC_DB_PATH`, default `data/athenasec.db`) and is what the tests use.

Things that follow from this:
- `web_auth.build_browser_auth_store_from_env()` and `operator_identity.build_operator_identity_store_from_env()`
  return `None` on SQLite. **Login, users and operator tokens exist only in Postgres**, so SQLite
  runs have no browser auth at all.
- `compose.yaml` sets only `ATHENASEC_DB_PATH` and no backend, so it falls into the Postgres default
  and fails with "ATHENASEC_DATABASE_URL is required". This is an existing inconsistency to fix or document.
- Every store class has an in-memory, a SQLite and a Postgres implementation. A new table means
  three implementations, apart from the auth tables, which are Postgres-only.
- Most records are stored as a `payload TEXT` JSON blob plus a few key columns. Postgres columns are
  `TEXT`/`TIMESTAMPTZ`, not `JSONB`. SQLite timestamps are ISO `TEXT`.

### 1.3 Existing tables (same names in SQLite and Postgres unless noted)

| Store (file) | Tables |
|---|---|
| Investigation (`investigation_store.py`) | `incidents`, `incident_alerts`, `incident_investigations`, `investigation_evidence`, `investigation_steps`, `investigations` (one `InvestigationResponse` per `alert_id`), `cases` (legacy `CaseRecord`, unique `alert_id`), `incident_correlation_profiles` |
| Incident response (`incident_response_store.py`) | `incident_risk_assessments`, `incident_cases` (`IncidentCaseRecord`), `proposed_actions`, `action_risk_assessments`, `incident_policy_decisions`, `approval_requests`, `response_actions`, `action_results`, `action_verifications`, `action_rollbacks` |
| Audit (`audit_store.py`) | `audit_records` (legacy, per `alert_id`), `incident_audit_events` (per `incident_id`, indexed by incident and timestamp) |
| Runtime control | `runtime_control_state`, `runtime_control_changes` |
| Target protection | `target_protection_state`, `target_protection_changes` (this is the never-block and never-isolate list) |
| Containment expiry | `containment_expiries` (indexed on `status, due_at`) |
| Auth (Postgres only) | `athenasec_web_users` (role Analyst/Administrator, read/decide flags, lockout, TOTP counter), `athenasec_web_challenges`, `athenasec_web_sessions`, `athenasec_web_auth_events`, `athenasec_operator_identities`, `athenasec_operator_credentials` |

Two case concepts coexist: `cases` (legacy, written by `main.py` and `autonomous_response.py`) and
`incident_cases` (the structured V2 path). Neither has an assignee, notes or a timeline.

## 2. Website data with no table yet

| # | Website data | What exists today | Gap |
|---|---|---|---|
| 1 | Alert `status` (Open/Closed) and `assignedAnalyst` | Only `InvestigationResponse.status` (pipeline state such as `complete`) | No analyst workflow state |
| 2 | Rich cases (assignee, open/closed, summary, evidence, actions, MITRE, timeline) | Two thin case tables | No assignee, analyst-ticked actions or notes. Summary, evidence, MITRE and endpoint can be derived from the investigation at read time |
| 3 | Users (department, phone, suspended, MFA flag, last login, created) | `athenasec_web_users` has name, email, role, active, lockout | Missing department, phone, `created_at`, `last_login_at`. MFA is always on, so `mfaEnabled` can be derived |
| 4 | Notifications | None | Derivable from pending approvals and degraded services. Per-user read/dismissed state needs a table only if it must survive reloads |
| 5 | Response policies (whitelist, blacklist, protected targets, version) | Policy is code (`policy_engine.py`, `structured_action_policy.py`). The protected-targets part already exists as `target_protection_*` | No stored whitelist or blacklist, no versioning |
| 6 | System health (services, metrics, events) | `runtime/status` | No probe results or health events. Current state can be computed live without a table. Only the event history needs one |
| 7 | Frontend audit events (user, role, category, source IP, result, hash chain) | `incident_audit_events` (agent events only, no actor, role or IP, no chain) | Admin/approval-flow/login events, plus a server-side hash chain |

Alert fields the pages show (`sourceIp`, `destinationIp`, `endpoint`, `mitre`) are already in
`alert_metadata` and the correlation fingerprint. They need no table, only stable key names.

## 3. Proposed schemas (Postgres, run through Alembic)

Conventions: `TIMESTAMPTZ` for times, `JSONB` for blobs, real columns for anything filtered or joined,
`version INTEGER` for optimistic concurrency where an analyst can edit, and state kept in **side tables
keyed by the existing id** so the existing payload tables are never altered.
SQLite parity (code-created, as today) is described in section 5.

### M1. `alert_workflow`  (item 1)
```sql
CREATE TABLE alert_workflow (
    alert_id        TEXT PRIMARY KEY REFERENCES incident_alerts(alert_id),
    status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
    assigned_to     TEXT REFERENCES athenasec_web_users(user_id),
    closed_at       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by      TEXT,
    version         INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_alert_workflow_status ON alert_workflow(status);
CREATE INDEX idx_alert_workflow_assigned ON alert_workflow(assigned_to) WHERE assigned_to IS NOT NULL;
```
A missing row means open and unassigned (read with `LEFT JOIN`), so **no backfill is needed**.
`list_alerts()` already joins `incident_alerts`, so adding this join changes the SQL in
`PostgresInvestigationStore` and the `status` filter semantics. See risk R6.

### M2. Rich cases  (item 2)
Add side tables to `incident_cases`, since it is the V2 path. Legacy `cases` rows get a view-time mapping.
```sql
CREATE TABLE case_workflow (
    case_id       TEXT PRIMARY KEY REFERENCES incident_cases(case_id),
    assigned_to   TEXT REFERENCES athenasec_web_users(user_id),
    summary       TEXT,                       -- analyst override; NULL = derive from the investigation
    closed_at     TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    version       INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE case_actions (                   -- analyst-ticked recommended actions
    case_id       TEXT NOT NULL REFERENCES incident_cases(case_id),
    position      INTEGER NOT NULL,
    label         TEXT NOT NULL,
    run_id        TEXT,
    approval_id   TEXT REFERENCES approval_requests(approval_id),
    done          BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (case_id, position)
);
CREATE TABLE case_timeline (                  -- analyst notes; agent steps are derived
    case_id       TEXT NOT NULL REFERENCES incident_cases(case_id),
    seq           INTEGER NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    failed        BOOLEAN NOT NULL DEFAULT FALSE,
    author        TEXT,
    PRIMARY KEY (case_id, seq)
);
```
Status already exists on `incident_cases` (`IncidentCaseStatus`: open, investigating, contained,
resolved, closed). It needs no column. Evidence, endpoint, source IP, MITRE and recommended actions from the
agent are derived from the investigation, not copied.

### M3. Users  (item 3)
```sql
ALTER TABLE athenasec_web_users
    ADD COLUMN department    TEXT NOT NULL DEFAULT '',
    ADD COLUMN phone         TEXT NOT NULL DEFAULT '',
    ADD COLUMN created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN last_login_at TIMESTAMPTZ;
```
All additive with defaults. "Suspended" maps to `active = FALSE`. `last_login_at` is set by
`complete_mfa`. Password reset and user creation need new store methods
(`provision_user` exists); this is the only migration that touches an existing table.

### M4. Notifications  (item 4), optional
Derive the list and keep read state in the browser. If it must persist:
```sql
CREATE TABLE notification_state (
    user_id     TEXT NOT NULL REFERENCES athenasec_web_users(user_id),
    key         TEXT NOT NULL,                -- stable derived key, e.g. 'approval:APR-1'
    read_at     TIMESTAMPTZ,
    dismissed_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, key)
);
```

### M5. Response policies  (item 5)
Agent policy stays authoritative in code until this ships (no change to risk/policy logic in this plan).
Storage for the editable document:
```sql
CREATE TABLE response_policy_versions (
    version      INTEGER PRIMARY KEY,
    document     JSONB NOT NULL,              -- whitelist, blacklist, protected targets
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by   TEXT NOT NULL,
    reason       TEXT
);
```
Append-only, so every save is a new version and the "version +1 per change" rule is the primary key.
The never-block and never-isolate lists should map onto the existing `target_protection_*` tables
rather than be duplicated. **Open decision:** whether the stored policy actually drives the agent
(needs a code change in policy) or is display-only for now.

### M6. Health events  (item 6)
```sql
CREATE TABLE health_events (
    event_id     BIGSERIAL PRIMARY KEY,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity     TEXT NOT NULL CHECK (severity IN ('Info','Warning','Critical')),
    source       TEXT NOT NULL,
    message      TEXT NOT NULL
);
CREATE INDEX idx_health_events_time ON health_events(occurred_at DESC);
```
Service status, latency and metrics are computed per request from probes (Postgres, Ollama, MISP,
Cortex, Wazuh) and are not stored.

### M7. Operator and admin audit events with hash chain  (item 7)
```sql
CREATE TABLE operator_audit_events (
    seq          BIGSERIAL PRIMARY KEY,       -- gives the chain its order
    event_id     TEXT NOT NULL UNIQUE,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     TEXT NOT NULL,
    actor_role   TEXT NOT NULL,               -- Analyst / Administrator / System
    category     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target       TEXT NOT NULL,
    result       TEXT NOT NULL CHECK (result IN ('Success','Failed','Denied')),
    source_ip    INET,
    event_type   TEXT,
    detail       JSONB NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL,
    row_hash     TEXT NOT NULL
);
CREATE INDEX idx_operator_audit_time ON operator_audit_events(occurred_at);
CREATE INDEX idx_operator_audit_actor ON operator_audit_events(actor_id);
```
Separate from `incident_audit_events` on purpose: that table is keyed by `incident_id` (NOT NULL), and login or
user-management events have no incident. `GET /api/v1/audit` would merge the two. To protect the chain,
append through a single writer with `pg_advisory_xact_lock`, and revoke `UPDATE`/`DELETE` from the app role.
The existing `athenasec_web_auth_events` can be backfilled in, but its rows have no actor IP.

## 4. Alembic setup (before any of the above)

1. Add `alembic` and `sqlalchemy` to `requirements.txt` (pinned, as the file is). Alembic needs SQLAlchemy
   even though the app uses psycopg directly. Use the `postgresql+psycopg://` URL form and **raw SQL in
   `op.execute`, no ORM models**, so there is a single schema definition.
2. `backend/alembic.ini` + `backend/migrations/env.py` reading `ATHENASEC_DATABASE_URL`.
3. **Baseline revision `0001`** that creates every table in section 1.3 using the same `IF NOT EXISTS` DDL as
   today. On an existing database run `alembic stamp 0001`, not `upgrade`, so nothing is re-run.
4. Keep constructor DDL in place for now (idempotent, and the tests assert on it). Alembic owns Postgres
   *new* objects. A later, separate change can remove constructor DDL and update those tests.
5. SQLite stays code-created for dev and tests. It is not managed by Alembic.

## 5. Build order

| Step | Content | Why here |
|---|---|---|
| 0 | Alembic scaffold + baseline `0001` + `alembic stamp` runbook; fix the `compose.yaml` backend mismatch | Everything else depends on it. No behaviour change |
| 1 | M3 users columns + `GET /api/v1/users` (read-only) | Smallest, additive, and M1/M2 need `user_id` to reference |
| 2 | M1 `alert_workflow` + assign/close/reopen on alerts + `GET /alerts/{id}` | Highest value; alert list already built |
| 3 | M7 `operator_audit_events` + writer; emit events from steps 1 and 2 | Audit before more mutations land. Mutating endpoints must write it from the start |
| 4 | M2 case tables + `GET /cases`, `/cases/{id}`, analyst actions | Needs M1, M3 and M7 |
| 5 | Approvals list + `GET /audit` merge (no new table) | Reads existing tables |
| 6 | M5 policies | Largest design question; do after the data paths work |
| 7 | M6 health events, M4 notifications | Lowest value; compute-only versions first |

Each step: SQLite/in-memory implementation + Postgres implementation + tests + migration, and the
full suite run before moving on. SQLite versions are code-created, so M1, M2, M4, M5 and M6 need
SQLite `CREATE TABLE` equivalents (timestamps and JSON as `TEXT`). M3 and M7 are Postgres-only like the auth tables.

## 6. Risks

**To existing data**
- R1. **Baseline on a populated database.** Running `upgrade` instead of `stamp` is harmless because the DDL is
  `IF NOT EXISTS`, but a wrong baseline (a column that differs from what is live) would be silently skipped.
  Mitigation: generate `0001` from a `pg_dump --schema-only` of a real instance and diff it.
- R2. **M3 is the only `ALTER` on an existing table.** It takes a short `ACCESS EXCLUSIVE` lock. With constant
  defaults on Postgres 11+ it does not rewrite the table. Confirm the server version. Rollback is `DROP COLUMN`.
- R3. **Two sources of schema truth** (constructor DDL and Alembic) can drift. Mitigation: new objects only in Alembic;
  a test that fails if a constructor creates a table that is not in the baseline.
- R4. **Foreign keys to `incident_alerts`, `incident_cases` and `athenasec_web_users`** would fail on orphaned
  rows (an investigation can exist without its `incident_alerts` row; the list code already handles this). Add
  FKs as `NOT VALID`, validate after a data check, or drop the FK on `alert_workflow`.
- R5. **Two case tables.** Putting the workflow on `incident_cases` leaves legacy `cases` rows without a workflow.
  Decide whether the Cases page reads both.
- R6. **Alert `status` meaning changes.** Today `?status=` on `/alerts` filters the pipeline status. After M1 the
  website wants open/closed. Keep the old behaviour under a new name (`pipeline_status`) or version the endpoint.
- R7. **Hash chain concurrency and tamper-resistance.** Without a single serialized writer the chain forks.
  If the app DB role can `UPDATE`/`DELETE`, the chain detects tampering but does not prevent it.
- R8. **Agent-driven versus analyst-driven state.** An analyst closing a case while the agent is still writing to it
  needs the `version` check on update (409 on mismatch).

**To the tests**
- The suite is **946 passed, 9 skipped** on this branch (892 baseline plus 54 added today). The "444 tests"
  figure does not match what I measured in `agent/`, so confirm which suite you mean.
- Tests do not run Alembic and do not need a live Postgres: Postgres paths are exercised with `MagicMock`
  connections, SQLite paths with temp files. A migration step therefore cannot break them directly.
- They *can* break if: constructor DDL is removed or reworded (several tests assert the exact SQL); `list_alerts`
  / `list_investigations` SQL changes for M1 (the Postgres list tests assert `LEFT JOIN incident_alerts`); or
  `create_app()` starts requiring a new store argument. Keep new stores optional with in-memory defaults.
- Migrations themselves are **untested** by the current suite. Proposal: one opt-in test (skipped unless
  `ATHENASEC_TEST_DATABASE_URL` is set) that runs `alembic upgrade head` on an empty database and again from
  a `stamp 0001` database, so the 9 existing skips stay at 9 for people without Postgres.

## 7. Decisions needed before any migration is written

1. Alembic with SQLAlchemy as a dependency (raw SQL ops), or a smaller hand-rolled numbered-SQL runner on psycopg?
2. Case workflow on `incident_cases` only (recommended), or also legacy `cases`?
3. Alert open/closed: new `/alerts` filter name for the old pipeline status, or leave `status` alone and add `workflow_status`?
4. Should stored response policy (M5) drive the agent now, or stay display-only?
5. Which Postgres version is in use, and is there a real database whose schema I can dump for the baseline?
6. Confirm the "444 tests" figure.
