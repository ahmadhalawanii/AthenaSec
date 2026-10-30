# Evidence bundle

Status: **documentation only. No code, test or existing doc was changed, and nothing was run to write this file.**
Every result below is copied from `backend/test-output.txt` or `backend/postgres-migration-verification.md`, or read from the code and tests. Where the two sources and the request disagree, that is stated, not resolved.
No password, token or connection secret appears here. Connection strings are placeholders.

## 1. Evidence levels used

| Level | Meaning in this document |
|---|---|
| **Unit** | Pytest tests with InMemory stores, SQLite temp files, or offline Alembic SQL. No Postgres involved. |
| **Simulated** | Postgres store code driven through an injected fake connection. Proves the SQL text, bound parameters and row mapping, not that Postgres accepts it. |
| **Isolated-live** | Run against a real PostgreSQL 16.15 instance (disposable container, database `athenasec_test`), either by pytest with the two test variables or by a one-off script that is **not** in the repo. |
| **Unverified** | Not run, or run only partly. Listed in section 8. |

## 2. Environment

| Item | Value | Source |
|---|---|---|
| Date of the live run | 2026-10-23 | verification doc, header |
| OS | Windows ("Windows Python 3.14 only"). The doc does not give the Windows version. This machine reports Windows 11 Pro 10.0.26200; that it was the same machine is assumed, not recorded | verification doc, "Not verified"; session environment |
| Python | 3.14.5 in a throw-away venv at a short path outside the repo (path not recorded) | verification doc, setup notes |
| Libraries | alembic 1.20.0, SQLAlchemy 2.1.5, psycopg 3.3.5, pytest 9.1.1 | verification doc, setup notes |
| PostgreSQL | 16.15 in container `athena-pg`, host port 5433 | verification doc, header |
| Databases | `athenasec_test` (given, empty at start) and `athenasec_test2` (created for the stamp-path check, dropped at the end). No other database was touched | verification doc, header and section 5 |
| Role | `postgres` (superuser). Every statement ran as `postgres` | verification doc, difference 3 |
| Shell variable state | `ATHENASEC_DATABASE_URL` was **not set** in the shell. The URL was built and exported per command only | verification doc, setup notes |
| Repo state | Branch `feature/agent-backend-pages`. The verification doc was written at 14:32 (local time). Commits `0c45413` (alert detail and dual-id) and `323d668` (approvals list) came after it, at 15:13 and 15:25 | file times and `git log`; see section 7 |

## 3. Unit evidence: suite without Postgres

Command (the exact flags are not recorded; this is the default form, run from `agent/`):

```
<short-venv-dir>\Scripts\python.exe -m pytest
```

Recorded result in `backend/test-output.txt`:

```
1411 passed, 9 skipped, 1 warning in 80.13s (0:01:20)
```

- The 9 skipped tests are the live Postgres tests (five files, listed in `test-fixtures-and-reproducibility.md`, section 1.5). The verification doc confirms this: without the two variables the five Postgres test files give 11 passed and 9 skipped.
- The one warning is a `DeprecationWarning` about the default `sqlite3` datetime adapter, raised from `incident_response_store.py:717` during `test_action_verification.py::test_sqlite_store_persists_verification`.
- **The request quotes 1460 passed / 9 skipped. The recorded file says 1411 passed / 9 skipped.** The file was last written at 14:21 on 2026-10-23. Two test files were written afterwards: `tests/test_alert_detail_and_dual_id.py` (15:00) and `tests/test_approval_list.py` (15:16, 11 `def test_` functions, with parametrised cases adding more). A run after those commits could plausibly give a larger number, but **no recorded output shows 1460**. It is listed as unverified in section 8. Until a new run is saved, the evidence-backed numbers are 1411 passed, 9 skipped (suite) and 1420 passed, 0 skipped (live).
- The same arithmetic ties the two recorded runs together: 1411 passed + 9 skipped = 1420, the number that ran in the live pass.

## 4. Isolated-live evidence: suite with Postgres variables

Setup: `ATHENASEC_TEST_PG_URL` and `ATHENASEC_TEST_DATABASE_URL` both pointing at `postgresql://<user>:<password>@localhost:5433/athenasec_test`, database migrated to `0006`.

| Run | Result |
|---|---|
| Only the two test variables set | **1420 passed, 0 skipped, 0 failed**, about 105 s |
| Same, with `ATHENASEC_DATABASE_URL` also exported (earlier attempt) | 2 failures: `test_approval_api.py::…503` and `test_operator_identity_gate.py::test_missing_identity_backend_fails_closed_even_with_shared_key`. Both returned 401 instead of 503 |
| Re-run with `ATHENASEC_DATABASE_URL` unset | both pass (verification doc: "Both pass with it unset") |

Assertion being checked by the two failing tests: with no identity store configured, the approval gate fails closed with **503**. A configured database URL makes the app build an identity store, so the expected 503 becomes 401. The doc concludes the cause is the stray variable, not the code, and says to run with only the two `TEST_*` variables.

The nine tests that ran live (all passed in the 1420):

- `test_postgres_live.py`: persist and read back investigation, response plan, execution result, case and audit record on real Postgres; production persistence builder returns Postgres stores.
- `test_browser_auth_postgres.py`: password, MFA, cookie, revocation and replay on real Postgres.
- `test_operator_identity_postgres.py` (4): digests only stored, re-provision revokes, expiry checked on each request, identity store controls the real approval decision route (approval and response stores are InMemory in that test).
- `test_atomic_approval_decisions.py`: parallel competing decisions on `PostgresIncidentResponseStore`.
- `test_target_operation_coordinator.py`: advisory lock serialises two workers.

(The per-test content comes from reading the test files; the doc records only that all passed.)

## 5. Isolated-live evidence: migrations 0001 to 0006

Step: `alembic upgrade head` on the empty `athenasec_test` (0 tables, 0 functions beforehand).

| Migration | Result |
|---|---|
| 0001 baseline | success |
| 0002 users profile columns | success |
| 0003 operator_audit_events | success |
| 0004 case workflow | success |
| 0005 response_policy_versions | success |
| 0006 health_events | success |

No errors. `alembic current` reported `0006 (head)`.

Schema comparison (migrated database vs a baseline built by the eight store constructors in `athenasec_test2`):

- Baseline 31 tables. Migrated 38 tables = the 31 + `alembic_version` + 6 new tables.
- Lines present only in the baseline: **0**. Every baseline table, column, type, nullability, default, constraint and index is identical in the migrated database.
- Only differences on baseline tables: the four `athenasec_web_users` columns added by 0002 (`department`, `phone`, `created_at` default `now()`, `last_login_at`).
- Conclusion in the doc: "No differences were found."

Stamp path (on `athenasec_test2`): `alembic stamp 0001` succeeded; `upgrade head` ran 0002 to 0006 cleanly; `alembic current` reported `0006 (head)`; schema identical to the clean-upgrade path except the line order of the `alembic_version` constraint in the dump; a second `upgrade head` was a no-op; `downgrade -1` raised the intended `NotImplementedError("health_events cannot be downgraded.")` and changed nothing.

Unit evidence for the same migrations (offline, no database): `tests/test_migrations.py` asserts one linear chain from `0001`, that no migration inserts rows except the version table, that 0002 is additive, that 0003 to 0006 create empty tables, and that 0003 to 0006 cannot be downgraded.

## 6. Isolated-live evidence: append-only triggers

Run against `athenasec_test` after migration, with rows inserted by minimal SQL, as `postgres`.

| Table | UPDATE | DELETE | TRUNCATE | Row survived |
|---|---|---|---|---|
| `operator_audit_events` | rejected | rejected | rejected | yes |
| `response_policy_versions` | rejected | rejected | rejected | yes |

- Every rejection raised `<table> is append-only`.
- A multi-table `TRUNCATE response_policy_versions, operator_audit_events` was also rejected.
- CHECK constraints rejected a bad `actor_role` and a bad health `status`.
- Side effect: the rejected insert consumed a `BIGSERIAL` value, so `seq` has a gap. The chain hash does not depend on `seq` being contiguous.
- Cleanup: `DROP SCHEMA public CASCADE` then `CREATE SCHEMA public`; `athenasec_test` returned to 0 tables and 0 functions.

These trigger checks were manual SQL statements. They are **not** a pytest test in the repo. The offline migration tests only assert the empty table definitions; the mocked store tests do not exercise the triggers.

## 7. Store checks run live by script (not in the repo)

A script kept outside the repo ran four stores against real Postgres: 18 of 20 checks passed, and the 2 failures were artefacts of a re-run that duplicated audit rows (their first-run counterparts passed).

| Store | Result recorded |
|---|---|
| `PostgresOperatorAuditStore` | 20 concurrent `append_event` calls all stored. Hash chain verified (`valid=True, checked=20`), and again at 40 rows. Actor and `since` filters work. A bad role is rejected by validation |
| `PostgresResponsePolicyStore` | `get_current` on empty returns `None`. Versions 1 and 2 appended. Stale `base_version` raised `PolicyVersionConflict`. 8 racers on one base version: exactly 1 won, 7 got a conflict (advisory lock works). List and get round-trip |
| `PostgresHealthEventStore` | First `up` records nothing, a change records a row, same status again is a no-op, filters work |
| `PostgresCaseWorkflowStore` | Upsert, `replace_actions` (atomic delete and insert) and `append_note` work. A duplicate `seq` becomes `ValueError` |

Classification: isolated-live, but **not reproducible from the repo** because the script is not committed. Simulated equivalents exist as pytest tests (`test_operator_audit_store.py`, `test_response_policy_store.py`, `test_case_workflow_store.py`, `test_system_health.py`).

Differences found between mock-tested SQL and real Postgres (verification doc):

1. Foreign key errors are not wrapped: see section 8, item 4.
2. `BIGSERIAL` gaps after a rejected insert.
3. Triggers only guard ordinary roles; a superuser can drop them.
4. `TIMESTAMPTZ` values come back as aware datetimes; SQLite and InMemory paths use other types.

"Bugs found: None in the migrations or the stores." Nothing was fixed.

## 8. Limits and unverified items

Stated limits from the verification doc:

1. **Superuser-only run.** Every statement ran as `postgres`. Behaviour as a non-superuser application role is unverified: whether UPDATE and DELETE are denied to it (the migrations say they should be), and whether the app can still create the baseline tables. No application role existed in the container.
2. **No real-data migration.** All runs used empty databases or throw-away rows. The `0002` claim of "no table rewrite" for constant-default columns was not timed on a large table.
3. **No Linux or VM run.** Windows with Python 3.14 only. The `Dockerfile` image was not tested. Postgres versions other than 16.15 were not tested.
4. **Unwrapped `ForeignKeyViolation` on the case workflow.** `PostgresCaseWorkflowStore.save_workflow` for an unknown `case_id` raises a raw `psycopg.errors.ForeignKeyViolation`. The store only translates `UndefinedTable` and `UniqueViolation`. A mock would not show this. It matters once a route writes a case that does not exist: it would be a 500 unless the route checks first. Not fixed; no test covers it.
5. **Downgrades.** All are intentionally `NotImplementedError`; none was exercised beyond `downgrade -1` on the head revision.
6. **HTTP routes against the migrated database** were not exercised. The suite uses the stores directly or mocks (see `website-api-test-matrix.md`, section 3).

Further unverified items from this documentation task:

- **The 1460 passed figure.** Not in any recorded output (section 3). A fresh run is needed to confirm or replace it.
- **Anything added after the recorded runs.** The suite (14:21) and live run (before 14:32) predate the alert detail and dual-id commit and the approvals list commit. Those routes and their tests were not part of the 1411 or the 1420.
- **The exact Python path, venv location and pytest flags** used for both runs.
- **The Windows version** the live run used.
- **Whether the 1420 live figure still holds** after the later commits. The Postgres run was not repeated.
- **Cleanup of data left by the live pytest tests.** They use random identifiers and no cleanup code was found, so rows accumulate in the test database between runs.
- **Triggers under the application role**, and any trigger test as pytest (none exists).
- This document was written without running anything; `pytest` is not installed in the default interpreter on this machine.
