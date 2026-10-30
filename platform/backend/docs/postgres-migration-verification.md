# PostgreSQL migration verification

Date: 2026-10-23. Target: PostgreSQL 16.15 in container `athena-pg` (host port 5433).
Databases used: `athenasec_test` (given) and `athenasec_test2` (created for step 5). No other database was touched.
No app code, existing migration or git state was changed. This file is the only file created in the repo.

## Setup notes

- `ATHENASEC_DATABASE_URL` was **not set** in the shell this session ran in. I built the URL for `athenasec_test` on `localhost:5433` and exported it for each command only. The password was read from the container's `POSTGRES_PASSWORD` and not printed.
- No Python dependencies were installed, so I created a throwaway venv from `requirements.txt` outside the repo (alembic 1.20.0, SQLAlchemy 2.1.5, psycopg 3.3.5, pytest 9.1.1, Python 3.14.5).
- My first venv sat under a very long scratchpad path. scipy failed to import there (`cannot import name '_arpacklib'`), which broke collection of 31 test files. A venv at a short path fixed it. This is an environment issue, not a repo issue.

## 1. Reachability and emptiness

`athenasec_test` was reachable and empty: 0 tables and 0 functions in any non-system schema.

## 2. `alembic upgrade head` on the empty database

| Migration | Result |
|---|---|
| 0001 baseline | success |
| 0002 users profile columns | success |
| 0003 operator_audit_events | success |
| 0004 case workflow | success |
| 0005 response_policy_versions | success |
| 0006 health_events | success |

There were no errors. `alembic current` reports `0006 (head)`.

## 3. Migrated schema vs store-constructor baseline

I built the baseline in `athenasec_test2` by running the 8 store constructors that create tables: Investigation, IncidentResponse, Audit, RuntimeControl, TargetProtection, ContainmentExpiry, OperatorIdentity and BrowserAuth. Then I dumped columns, constraints, indexes and triggers from both databases and diffed them.

- Baseline: 31 tables. Migrated: 38 tables, which is the 31 plus `alembic_version` and the 6 new tables.
- Lines present only in the baseline: **0**. Every baseline table, column, type, nullability, default, constraint and index is identical in the migrated database.
- The only differences on baseline tables are the four `athenasec_web_users` columns added by 0002: `department`, `phone`, `created_at` (default `now()`) and `last_login_at`.
- The other additions are the six tables from 0003 to 0006 (with their indexes and triggers) and `alembic_version`.

**No differences were found.**

## 4. Append-only triggers

All statements were run against `athenasec_test` after migration. Rows were inserted with minimal SQL.

| Table | UPDATE | DELETE | TRUNCATE | Row survived |
|---|---|---|---|---|
| operator_audit_events | rejected | rejected | rejected | yes |
| response_policy_versions | rejected | rejected | rejected | yes |

Every rejection raised `<table> is append-only`. A multi-table `TRUNCATE response_policy_versions, operator_audit_events` was also rejected. The CHECK constraints rejected a bad `actor_role` and a bad health `status`.

Side effect: the rejected insert consumed a `BIGSERIAL` value, so `seq` has a gap. This is normal Postgres behaviour. It matters only if anything assumes `seq` is gapless. The chain hash does not depend on `seq` being contiguous.

Cleanup: the migrated objects in `athenasec_test` were removed with `DROP SCHEMA public CASCADE` followed by `CREATE SCHEMA public`. `athenasec_test` is back to 0 tables and 0 functions.

## 5. Stamp path

On `athenasec_test2`, with the baseline built from the constructors only:

- `alembic stamp 0001` succeeded.
- `alembic upgrade head` ran 0002, 0003, 0004, 0005 and 0006 cleanly.
- `alembic current` reports `0006 (head)`.
- The resulting schema is identical to the clean-upgrade path. The only difference is the line order of the `alembic_version` constraint in my dump.
- Running `upgrade head` again was a no-op.
- `downgrade -1` raised the intended `NotImplementedError("health_events cannot be downgraded.")`. Nothing changed.

`athenasec_test2` was dropped at the end.

## 6. Agent test suite with Postgres env vars set

`ATHENASEC_TEST_PG_URL` and `ATHENASEC_TEST_DATABASE_URL` were set to `athenasec_test`, which was migrated to head.

- **1420 passed, 0 skipped, 0 failed** (about 105 s).
- Without the two vars, the 5 Postgres test files give 11 passed and **9 skipped**. That confirms the 9 skipped tests are the ones that now run.
- An earlier run with `ATHENASEC_DATABASE_URL` also exported gave 2 failures: `test_approval_api.py::…503` and `test_operator_identity_gate.py::test_missing_identity_backend_fails_closed_even_with_shared_key`. Both got 401 instead of 503. These tests assume no database URL is configured, so the cause is the stray variable in my shell, not the code. Both pass with it unset. Run the suite with only the two `TEST_*` vars.

## 7. What the existing tests do not cover, and how I checked it

The 9 live Postgres tests only cover the older stores. The four stores added in this work are not touched by any live test: `PostgresOperatorAuditStore`, `PostgresResponsePolicyStore`, `PostgresCaseWorkflowStore` and `PostgresHealthEventStore`. Their SQL had only been exercised through mocks.

I ran each through its own code paths against real Postgres (script outside the repo). 18 of 20 checks passed. The 2 failures were artifacts of my own re-run, which duplicated the audit rows. Their first-run counterparts passed.

- **Operator audit:** 20 concurrent `append_event` calls all stored. The hash chain verified (`valid=True, checked=20`). It still verified at 40 rows. Actor and `since` filters work. A bad role is rejected by validation.
- **Response policy:** `get_current` on an empty table returns `None`. Versions 1 and 2 were appended. A stale `base_version` raised `PolicyVersionConflict`. With 8 racers on the same base version, exactly 1 won and 7 got a conflict. The advisory lock works. List and get round-trip.
- **Health:** a first `up` records nothing, a change records a row, the same status again is a no-op, and filters work.
- **Case workflow:** upsert, `replace_actions` (atomic delete and insert) and `append_note` work. A duplicate `seq` becomes `ValueError`.

## Differences between mock-tested SQL and real Postgres

1. **Foreign key errors are not wrapped.** `save_workflow` for an unknown `case_id` raises a raw `psycopg.errors.ForeignKeyViolation`. The store only translates `UndefinedTable` and `UniqueViolation`. A mock would not show this. It matters once a route writes a case that does not exist: it would be a 500 unless the route checks first. The 0004 note says writes will validate later.
2. **`BIGSERIAL` gaps.** A rejected insert still consumes a sequence value, so `seq` and `event_id` can have gaps.
3. **Triggers only guard against ordinary roles.** A superuser can drop them. The migrations say to also deny UPDATE and DELETE to the application role. I did **not** verify that grant, because no application role exists in this container. Every statement ran as `postgres`.
4. **Timestamps.** `TIMESTAMPTZ` values come back as aware datetimes from psycopg. This worked in every round trip I ran. The SQLite and in-memory paths use different types, so mocks that use naive datetimes would hide a mismatch.

## Not verified

- Behaviour as a non-superuser application role: grants, and whether the app can still create the baseline tables.
- Migrating a database that has real data in it (all tests here used empty or throwaway rows).
- The `0002` claim of "no table rewrite" for the constant-default columns. I did not time it on a large table.
- Downgrades. All of them are intentionally `NotImplementedError`.
- Postgres versions other than 16.15.
- Windows Python 3.14 only; I did not test the Docker image (`Dockerfile`) or Linux.
- The full HTTP routes against the migrated database. The suite uses the stores directly or mocks.

## Bugs found

None in the migrations or the stores. The one behavioural note is item 1 above, the unwrapped foreign key error. Nothing was fixed.
