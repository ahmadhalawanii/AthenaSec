"""SQLite -> PostgreSQL migration tool: conversions, and (with a live database) a full copy."""

import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from app.services.storage import sqlite_to_postgres as tool

BACKEND = Path(__file__).resolve().parents[1]


# ----- conversions (no database needed) ---------------------------------------------------


def test_timestamps_become_aware_utc():
    aware = tool.convert("2026-10-30T09:01:00+04:00", "timestamp with time zone", "t")
    assert aware == datetime(2026, 10, 30, 5, 1, tzinfo=timezone.utc)
    naive = tool.convert("2026-10-30T09:01:00.123456", "timestamp with time zone", "t")
    assert naive.tzinfo is timezone.utc and naive.microsecond == 123456
    zulu = tool.convert("2026-10-30T09:01:00.000001Z", "timestamp with time zone", "t")
    assert zulu.tzinfo is not None
    assert tool.convert(None, "timestamp with time zone", "t") is None


def test_booleans_from_sqlite_integers():
    assert tool.convert(1, "boolean", "b") is True
    assert tool.convert(0, "boolean", "b") is False
    assert tool.convert(None, "boolean", "b") is None
    with pytest.raises(tool.MigrationError):
        tool.convert(7, "boolean", "b")


def test_bad_timestamp_names_the_row():
    with pytest.raises(tool.MigrationError, match="incidents row 3"):
        tool.convert("not a time", "timestamp with time zone", "incidents row 3 column x")


def test_other_values_pass_through():
    assert tool.convert('{"a": 1}', "text", "x") == '{"a": 1}'
    assert tool.convert(42, "integer", "x") == 42


def test_missing_sqlite_file_is_reported(tmp_path):
    with pytest.raises(tool.MigrationError, match="not found"):
        tool.open_sqlite_read_only(tmp_path / "nope.db")


# ----- full copy against a real PostgreSQL --------------------------------------------------


def _admin_url():
    url = os.getenv("ATHENASEC_TEST_DATABASE_URL")
    if not url:
        pytest.skip("ATHENASEC_TEST_DATABASE_URL is not configured.")
    return url


@pytest.fixture
def empty_postgres():
    """A brand-new database at the newest Alembic revision, dropped afterwards."""
    admin_url = _admin_url()
    name = "athenasec_migtest_" + uuid.uuid4().hex[:10]
    try:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error as error:
        pytest.skip(f"cannot create a scratch database: {error}")

    info = psycopg.conninfo.conninfo_to_dict(admin_url)
    info["dbname"] = name
    url = psycopg.conninfo.make_conninfo(**info)
    env = dict(os.environ, ATHENASEC_DATABASE_URL=_as_url(info))
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], cwd=BACKEND,
                   env=env, check=True, capture_output=True)
    try:
        yield url
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _as_url(info):
    from urllib.parse import quote

    user = quote(info.get("user", "postgres"))
    password = f":{quote(info['password'])}" if info.get("password") else ""
    host = info.get("host", "localhost")
    port = info.get("port", "5432")
    if host.startswith("/"):
        return f"postgresql://{user}{password}@/{info['dbname']}?host={quote(host)}&port={port}"
    return f"postgresql://{user}{password}@{host}:{port}/{info['dbname']}"


def _filled_sqlite(path):
    from app.services.audit.operator_audit_store import SQLiteOperatorAuditStore
    from app.services.cases.case_workflow_store import SQLiteCaseWorkflowStore
    from app.services.health.health_event_store import SQLiteHealthEventStore
    from app.services.investigations.investigation_store import SQLiteInvestigationStore
    from app.services.storage.incident_response_store import SQLiteIncidentResponseStore
    from tests.test_case_workflow_store import action, note, workflow
    from tests.test_investigation_list_stores import seed
    from tests.test_responses_route import fill

    seed(SQLiteInvestigationStore(path))
    responses = SQLiteIncidentResponseStore(path)
    fill(responses)
    from app.schemas import IncidentCaseRecord

    responses.save_incident_case(IncidentCaseRecord(
        case_id="CASE-MIG", incident_id="INC-A", status="open", reason="migration test",
        created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 6, 1, tzinfo=timezone.utc)))
    cases = SQLiteCaseWorkflowStore(path)
    cases.save_workflow(workflow("CASE-MIG"))
    cases.replace_actions("CASE-MIG", [action(1, "CASE-MIG", done=True), action(2, "CASE-MIG")])
    cases.append_note(note(1, "CASE-MIG", failed=True))
    audit = SQLiteOperatorAuditStore(path)
    for index in range(5):
        audit.append_event(actor_id="admin-1", actor_role="Administrator", category="Users",
                           action=f"change {index}", target="USR-1", result="Success",
                           detail={"n": index, "text": "ünïcode"})
    health = SQLiteHealthEventStore(path)
    health.record_status(source="ollama", status="down", severity="Warning", message="down")
    health.record_status(source="ollama", status="up", severity="Info", message="up",
                         occurred_at=datetime.now(timezone.utc) + timedelta(seconds=1))
    return path


def _drop_orphans(path):
    # seed() deliberately stores an investigation whose alert is missing
    import sqlite3

    with sqlite3.connect(path) as connection:
        connection.execute("DELETE FROM incident_investigations WHERE primary_alert_id = 'ALT-MISSING'")
        connection.execute("DELETE FROM investigation_steps WHERE investigation_id NOT IN "
                           "(SELECT investigation_id FROM incident_investigations)")
        connection.execute("DELETE FROM investigation_evidence WHERE investigation_id NOT IN "
                           "(SELECT investigation_id FROM incident_investigations)")


def test_orphan_rows_stop_the_copy_before_writing(tmp_path, empty_postgres):
    lite = _filled_sqlite(tmp_path / "athenasec.db")
    with pytest.raises(tool.MigrationError, match="ALT-MISSING"):
        tool.run(lite, empty_postgres, log=lambda *_: None)
    with psycopg.connect(empty_postgres) as pg:
        assert pg.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 0


def test_full_copy_is_verified_and_leaves_sqlite_untouched(tmp_path, empty_postgres):
    lite = _filled_sqlite(tmp_path / "athenasec.db")
    _drop_orphans(lite)
    before = tool.sha256_file(lite)

    dry = tool.run(lite, empty_postgres, dry_run=True, log=lambda *_: None)
    assert not dry.committed
    with psycopg.connect(empty_postgres) as pg:
        assert pg.execute("SELECT COUNT(*) FROM operator_audit_events").fetchone()[0] == 0

    report = tool.run(lite, empty_postgres, log=lambda *_: None)
    assert report.committed
    counts = {t.name: (t.sqlite_rows, t.postgres_rows) for t in report.tables}
    assert all(a == b for a, b in counts.values())
    assert counts["operator_audit_events"] == (5, 5)
    assert counts["case_actions"] == (2, 2)
    assert report.audit_chain_postgres["head_hash"] == report.audit_chain_sqlite["head_hash"]
    assert tool.sha256_file(lite) == before

    with psycopg.connect(empty_postgres) as pg:
        done = pg.execute("SELECT done FROM case_actions ORDER BY position").fetchall()
        assert done == [(True,), (False,)]

    verified = tool.run(lite, empty_postgres, verify_only=True, log=lambda *_: None)
    assert sum(t.rows_verified for t in verified.tables) == sum(t.sqlite_rows for t in report.tables)

    # New rows continue after the copied ones and keep the chain valid
    from app.services.audit.operator_audit_store import PostgresOperatorAuditStore
    from app.services.health.health_event_store import PostgresHealthEventStore

    url = _as_url(psycopg.conninfo.conninfo_to_dict(empty_postgres))
    store = PostgresOperatorAuditStore(url)
    event = store.append_event(actor_id="admin-1", actor_role="Administrator", category="Users",
                               action="after", target="USR-1", result="Success")
    assert event.seq == 6 and store.verify_chain().valid
    PostgresHealthEventStore(url).record_status(source="ollama", status="down",
                                                severity="Warning", message="again")

    with pytest.raises(tool.MigrationError, match="already hold data"):
        tool.run(lite, empty_postgres, log=lambda *_: None)


def test_schema_behind_is_refused(tmp_path):
    admin_url = _admin_url()
    name = "athenasec_migtest_" + uuid.uuid4().hex[:10]
    try:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'CREATE DATABASE "{name}"')
    except psycopg.Error as error:
        pytest.skip(f"cannot create a scratch database: {error}")
    info = psycopg.conninfo.conninfo_to_dict(admin_url)
    info["dbname"] = name
    try:
        lite = _filled_sqlite(tmp_path / "athenasec.db")
        with pytest.raises(tool.MigrationError, match="alembic upgrade head"):
            tool.run(lite, psycopg.conninfo.make_conninfo(**info), log=lambda *_: None)
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
