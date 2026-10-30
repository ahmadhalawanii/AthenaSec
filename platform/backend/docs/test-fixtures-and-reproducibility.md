# Test fixtures and reproducibility

Status: **documentation only. No code, test or existing doc was changed.**
Sources: `backend/pytest.ini`, `backend/tests/*.py`, `backend/migrations/env.py`, `backend/test-output.txt`, `backend/postgres-migration-verification.md`.
Nothing here was run for this document. Items I could not confirm are in "Unverified" at the end.
No credential appears in this file. Placeholders are written `<like-this>`.

## 1. How tests create and discard their own data

There is no `conftest.py` in `backend/tests`. Fixtures live in each test file. `backend/tests/__init__.py` exists, so tests import each other as `tests.<module>` (for example `from tests.test_investigation_list_stores import seed`).

### 1.1 InMemory stores

- Each test builds a new `InMemory*Store()` (investigation, audit, incident response, operator audit, response policy, case workflow, health event, operator identity) in a helper or fixture, then passes it to `create_app(...)`.
- Nothing is written outside the process. The data is dropped when the object is garbage-collected. There is nothing to clean up and tests cannot see each other's rows.
- Seeding helpers are shared by import (for example `seed` in `test_investigation_list_stores.py`, used by `test_list_endpoints.py` and `test_alert_detail_and_dual_id.py`).

### 1.2 SQLite stores

- A SQLite file is created under pytest's `tmp_path` fixture, for example `SQLiteInvestigationStore(tmp_path / "lookup.db")`. `tmp_path` is a fresh directory per test; pytest, not the test, removes old ones (it keeps the most recent base temp directories).
- Many API test files have an autouse fixture that points the app's own persistence at a throw-away file, using `monkeypatch` (undone after each test):
  - `ATHENASEC_PERSISTENCE_BACKEND=sqlite`
  - `ATHENASEC_DB_PATH=<tmp_path>/<name>.db`
  - This is in `test_list_endpoints.py`, `test_alert_detail_and_dual_id.py`, `test_approval_list.py`. (`test_users_endpoints.py` sets the same two variables inside one test, `test_no_browser_auth_store_is_503`.)
  - Those files still pass InMemory stores to `create_app`, so the SQLite file is only what the app would build for any store it was not given.
- Some fixtures are parametrised over backends so one test body runs on each: `["memory", "sqlite"]` in `test_alert_detail_and_dual_id.py`, `test_system_health.py`, `test_dashboard_summary.py`, `test_atomic_approval_decisions.py`.
- `test_sqlite_state_survives_reopening` (health events) and the `*_survives_app_restart` tests in `test_api.py` reopen the same temp file on purpose.

### 1.3 Mocked Postgres

- Postgres stores are built with an injected connection factory so no socket opens, for example `PostgresAuditStore("postgresql://x/y", connect=lambda url: Connection(log, rows))`. The URLs are fake. `grep` finds 61 `connect=` uses in `backend/tests`.
- The fake connection records each `(sql, params)` call. Tests assert on the SQL text (for example `pg_advisory_xact_lock`), on bound parameters, on row mapping, and that a constructor creates no tables.
- "Not migrated" is simulated by a fake store whose methods raise `...SchemaNotReady` (`UnmigratedWorkflowStore`, `UnmigratedStore`, `UnmigratedPolicyStore`, `UnmigratedEventStore`, `UnmigratedAuditStore`); the route tests then assert 503.
- `tests/network_guard.py` makes a test fail if it opens a real connection to a non-loopback host or to ports 80, 443, 5432, 8443, 9000, 9001, 9200, 9443, 11434. Only `test_health_probes.py` installs it (checked by grep). Port 5433, which the live runs used, is not in that list.
- Mocked tests prove the SQL strings and Python mapping. They do not prove that real Postgres accepts the SQL (see `evidence-bundle.md`, "simulated" versus "isolated-live").

### 1.4 Offline Alembic tests

`test_migrations.py` runs Alembic in offline mode (`--sql`), with `ATHENASEC_DATABASE_URL` set by `monkeypatch` to a dummy URL. No database is contacted. It asserts one linear chain from `0001`, no data-inserting migrations, and that `0003`, `0004`, `0005`, `0006` create the expected empty tables and cannot be downgraded.

### 1.5 Live Postgres tests (skipped unless env vars are set)

Nine tests are skipped without Postgres variables (`test-output.txt` shows `9 skipped`; the verification doc names the five files):

| File | Test(s) | Variable that enables it |
|---|---|---|
| `test_postgres_live.py` | `test_postgres_stores_persist_real_records`, `test_production_persistence_builder_uses_real_postgres` | `ATHENASEC_TEST_DATABASE_URL` (via `pytest.skip` in `get_database_url()`) |
| `test_browser_auth_postgres.py` | `test_live_browser_password_mfa_cookie_revocation_and_replay` | `ATHENASEC_TEST_PG_URL` (`skipif`) |
| `test_operator_identity_postgres.py` | 4 tests, module fixture `pg_store` | `ATHENASEC_TEST_PG_URL` (`pytest.skip`) |
| `test_atomic_approval_decisions.py` | `test_parallel_competing_decisions_real_postgres` | `ATHENASEC_TEST_PG_URL` (`skipif`) |
| `test_target_operation_coordinator.py` | `test_real_postgres_advisory_lock_serializes_workers` | `ATHENASEC_TEST_PG_URL` (`skipif`) |

That is 2 + 1 + 4 + 1 + 1 = 9.

How they isolate data: every live test generates random identifiers (`uuid4().hex`) for alerts, users, and operators (`ALT-POSTGRES-<hex>`, `user-<hex>`, `m8-test-<hex>`) so reruns do not collide.

How they discard data: **they do not.** A search of the four live files for `DELETE`, `DROP`, `TRUNCATE`, `cleanup`, `teardown` and `yield` found nothing. Rows remain in the test database. `test_operator_identity_postgres.py` states in its docstring that it "expire[s]/revoke[s] only those credentials", but no cleanup code was found in that file. The verification run reset its database by hand with `DROP SCHEMA public CASCADE` then `CREATE SCHEMA public`. Use a disposable database.

Guards: only `test_operator_identity_postgres.py` refuses to run unless the URL host is `localhost` or `127.0.0.1` and the database path is `/athenasec_test` (`pytest.fail` otherwise). The other live tests have no such check; they run against whatever URL is supplied.

## 2. Running the suite

### 2.1 Working directory

Run from the **`agent`** folder:

```
C:\Users\Asus\OneDrive - University of Wollongong\Desktop\AthenaSec-Scripts\AthenaSec\agent
```

Reasons found in the repo:

- `pytest.ini` is in `agent/` (`testpaths = tests`, `python_files = test_*.py`). It sets no `pythonpath`.
- Tests import `app.*` and `tests.*`. Both resolve from `agent/` (the rootdir with `tests/__init__.py`).
- `tests/test_demo_graph.py::test_demo_uses_autonomous_policy_fields` opens `Path("demo_graph.py")`, a path relative to the current directory. `demo_graph.py` is in `agent/`. From any other directory that test fails with a missing-file error. This is the one test that depends on the working directory directly.
- `test_migrations.py` locates `alembic.ini` and `migrations/` from `Path(__file__).parents[1]`, so it does not depend on the directory.

### 2.2 Python path

The interpreter used for the recorded runs is **not recorded** in `test-output.txt` or `postgres-migration-verification.md`. What the verification doc does say:

- It used a throw-away virtual environment created from `backend/requirements.txt`, at a short path outside the repo.
- Versions: Python 3.14.5, alembic 1.20.0, SQLAlchemy 2.1.5, psycopg 3.3.5, pytest 9.1.1.
- A first venv under a very long path broke `scipy` imports (`cannot import name '_arpacklib'`) and stopped 31 test files from being collected. A venv at a short path fixed it.

So the exact path of that venv's `python.exe` cannot be given from the repo. Use:

```
<short-venv-dir>\Scripts\python.exe -m pytest -q
```

On this machine the default interpreter is `C:\Users\Asus\AppData\Local\Python\pythoncore-3.14-64\python.exe` (3.14.7). `python -m pytest --version` there reports **No module named pytest**, so it cannot run the suite until `pip install -r requirements.txt` is done into a venv. Do not place that venv in a very long path (the scipy problem above).

### 2.3 Command (no Postgres)

PowerShell, from `agent/`:

```powershell
Remove-Item Env:ATHENASEC_DATABASE_URL, Env:ATHENASEC_TEST_PG_URL, Env:ATHENASEC_TEST_DATABASE_URL -ErrorAction SilentlyContinue
& "<short-venv-dir>\Scripts\python.exe" -m pytest
```

The exact flags used for `test-output.txt` are not recorded. Its layout (dots with `[ nn%]` markers and a final `... in 80.13s (0:01:20)` line) is what the default progress output looks like. Recorded result in the file: `1411 passed, 9 skipped, 1 warning in 80.13s`.

## 3. Running the live Postgres tests

Prerequisites:

1. A disposable PostgreSQL database named `athenasec_test` on loopback (the verification run used PostgreSQL 16.15 in a container, host port 5433).
2. The database migrated to head. Alembic reads `ATHENASEC_DATABASE_URL` (`migrations/env.py`, which exits if it is missing or not a PostgreSQL URL). Set it for the migration command only:

```powershell
$env:ATHENASEC_DATABASE_URL = "postgresql://<user>:<password>@localhost:5433/athenasec_test"
& "<short-venv-dir>\Scripts\python.exe" -m alembic upgrade head
Remove-Item Env:ATHENASEC_DATABASE_URL
```

   `alembic current` should then report `0006 (head)`.

3. Set **only** the two test variables for the pytest run:

```powershell
$env:ATHENASEC_TEST_PG_URL       = "postgresql://<user>:<password>@localhost:5433/athenasec_test"
$env:ATHENASEC_TEST_DATABASE_URL = "postgresql://<user>:<password>@localhost:5433/athenasec_test"
& "<short-venv-dir>\Scripts\python.exe" -m pytest
```

Why not `ATHENASEC_DATABASE_URL` during pytest: the verification doc (section 6) records that with it exported, two tests failed with **401 instead of 503**:

- `test_approval_api.py::…503` (the test at `test_unconfigured_approval_gate_fails_closed`, which expects 503 from `GET` and `POST …/decision` when no identity store exists)
- `test_operator_identity_gate.py::test_missing_identity_backend_fails_closed_even_with_shared_key`

These tests assume no database URL is configured. With one set, the app builds an identity store from it, so the gate is no longer "unconfigured" and returns 401. Both pass with the variable unset. The doc attributes the failures to the stray variable in the shell, not to the code. The reading of the mechanism above is mine from the handler code (`require_approval_identity` returns 503 only when no identity store exists) and was not run.

Expected result recorded: `1420 passed, 0 skipped, 0 failed` (about 105 s) with the two vars set and the database at `0006`. Without the two vars the same five files give 11 passed and 9 skipped.

Keep real passwords out of shell history and out of any file you commit.

## 4. Unverified

- The path of the Python interpreter and venv used for the recorded runs; the exact pytest flags.
- That the commands in sections 2 and 3 run as written on this machine. None was executed for this document.
- That the `test_approval_api.py` 503 test is the one the verification doc abbreviates as `test_approval_api.py::…503`. I matched it by content (`test_unconfigured_approval_gate_fails_closed` is the only 503 test in that file).
- The no-cleanup finding comes from searching for cleanup keywords, not from reading every line of the live tests.
- `test_target_operation_coordinator.py` and `test_atomic_approval_decisions.py` were read only around their live tests.
- Whether the run recorded in `test-output.txt` used any non-default pytest options.
- Running on Linux, in the Docker image (`Dockerfile`), or with another Postgres version: not tested (verification doc).
