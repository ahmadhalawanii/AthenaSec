"""Alembic revisions: a single linear chain, additive, and free of data writes.

Runs Alembic in offline (--sql) mode, so no database is needed.
"""

import io
import re
from pathlib import Path

import pytest

pytest.importorskip("alembic")

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

AGENT_DIR = Path(__file__).resolve().parents[1]


def alembic_config(buffer=None):
    config = Config(str(AGENT_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(AGENT_DIR / "migrations"))
    if buffer is not None:
        config.output_buffer = buffer
    return config


def offline_sql(monkeypatch, start="base", end="head"):
    monkeypatch.setenv("ATHENASEC_DATABASE_URL", "postgresql://u:p@localhost/db")
    buffer = io.StringIO()
    command.upgrade(alembic_config(buffer), f"{start}:{end}", sql=True)
    return buffer.getvalue()


def test_single_linear_chain_from_baseline():
    script = ScriptDirectory.from_config(alembic_config())

    assert len(script.get_heads()) == 1
    revisions = list(script.walk_revisions())
    assert [r.revision for r in reversed(revisions)][0] == "0001"
    assert revisions[-1].down_revision is None
    assert not any(r.branch_labels for r in revisions)


def test_no_migration_inserts_rows_except_version_table(monkeypatch):
    sql = offline_sql(monkeypatch)

    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    writes = re.findall(
        r"^\s*(?:UPDATE|DELETE\s+FROM)\s+(\w+)", sql, re.IGNORECASE | re.MULTILINE
    )
    assert set(writes) <= {"alembic_version"}


def test_baseline_is_idempotent_ddl_only(monkeypatch):
    sql = offline_sql(monkeypatch, "base", "0001")

    statements = re.findall(r"CREATE (?:TABLE|INDEX)[^\n]*", sql)
    statements = [s for s in statements if "alembic_version" not in s]
    assert statements
    for statement in statements:
        assert "IF NOT EXISTS" in statement
    assert "DROP" not in sql.upper()
    assert "athenasec_web_users" in sql


def test_users_columns_migration_is_additive(monkeypatch):
    sql = offline_sql(monkeypatch, "0001", "0002")

    assert "ALTER TABLE athenasec_web_users" in sql
    for column in ("department", "phone", "created_at", "last_login_at"):
        assert f"ADD COLUMN IF NOT EXISTS {column}" in sql
    assert "DROP" not in sql.upper()


def test_operator_audit_migration_creates_empty_append_only_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0002", "0003")

    assert "CREATE TABLE IF NOT EXISTS operator_audit_events" in sql
    for column in ("seq BIGSERIAL PRIMARY KEY", "event_id TEXT NOT NULL UNIQUE",
                   "prev_hash TEXT NOT NULL", "row_hash TEXT NOT NULL UNIQUE"):
        assert column in sql
    assert "BEFORE UPDATE OR DELETE ON operator_audit_events" in sql
    assert "BEFORE TRUNCATE ON operator_audit_events" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}


def test_operator_audit_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())
    module = script.get_revision("0003").module

    with pytest.raises(NotImplementedError):
        module.downgrade()


def test_revisions_are_numbered_in_a_straight_line():
    script = ScriptDirectory.from_config(alembic_config())
    revisions = sorted(script.walk_revisions(), key=lambda r: r.revision)

    assert [r.revision for r in revisions] == [f"{n:04d}" for n in range(1, len(revisions) + 1)]
    assert revisions[0].down_revision is None
    for previous, current in zip(revisions, revisions[1:]):
        assert current.down_revision == previous.revision
    assert script.get_heads() == [revisions[-1].revision]


def test_case_workflow_migration_creates_three_empty_tables(monkeypatch):
    sql = offline_sql(monkeypatch, "0003", "0004")

    for table in ("case_workflow", "case_actions", "case_timeline"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
    assert sql.count("REFERENCES incident_cases(case_id)") == 3
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert not re.search(r"ALTER\s+TABLE\s+incident_cases", sql, re.IGNORECASE)
    assert "DROP" not in sql.upper()


def test_case_workflow_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0004").module.downgrade()


def test_database_url_is_required(monkeypatch):
    monkeypatch.delenv("ATHENASEC_DATABASE_URL", raising=False)

    with pytest.raises(SystemExit):
        command.upgrade(alembic_config(io.StringIO()), "base:head", sql=True)


def test_sqlite_url_is_rejected(monkeypatch):
    monkeypatch.setenv("ATHENASEC_DATABASE_URL", "sqlite:///x.db")

    with pytest.raises(SystemExit):
        command.upgrade(alembic_config(io.StringIO()), "base:head", sql=True)


def test_response_policy_migration_creates_empty_append_only_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0004", "0005")

    assert "CREATE TABLE IF NOT EXISTS response_policy_versions" in sql
    assert "version INTEGER PRIMARY KEY" in sql
    assert "BEFORE UPDATE OR DELETE ON response_policy_versions" in sql
    assert "BEFORE TRUNCATE ON response_policy_versions" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert "DROP TABLE" not in sql.upper()


def test_response_policy_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0005").module.downgrade()


def test_health_events_migration_creates_an_empty_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0005", "0006")

    assert "CREATE TABLE IF NOT EXISTS health_events" in sql
    assert "event_id BIGSERIAL PRIMARY KEY" in sql
    assert "idx_health_events_time" in sql and "idx_health_events_source" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert "DROP TABLE" not in sql.upper()


def test_health_events_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0006").module.downgrade()

def test_action_policy_migration_creates_empty_append_only_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0006", "0007")

    assert "CREATE TABLE IF NOT EXISTS action_policy_versions" in sql
    assert "BEFORE UPDATE OR DELETE ON action_policy_versions" in sql
    assert "BEFORE TRUNCATE ON action_policy_versions" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert "DROP TABLE" not in sql.upper()


def test_action_policy_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0007").module.downgrade()

def test_alert_workflow_migration_creates_an_empty_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0007", "0008")

    assert "CREATE TABLE IF NOT EXISTS alert_workflow" in sql
    assert "CHECK (status IN ('open', 'closed'))" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert "DROP TABLE" not in sql.upper()


def test_alert_workflow_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0008").module.downgrade()

def test_app_settings_migration_creates_an_empty_table(monkeypatch):
    sql = offline_sql(monkeypatch, "0008", "0009")

    assert "CREATE TABLE IF NOT EXISTS app_settings" in sql
    inserts = re.findall(r"INSERT\s+INTO\s+(\w+)", sql, flags=re.IGNORECASE)
    assert set(inserts) <= {"alembic_version"}
    assert "DROP TABLE" not in sql.upper()


def test_app_settings_migration_cannot_be_downgraded():
    script = ScriptDirectory.from_config(alembic_config())

    with pytest.raises(NotImplementedError):
        script.get_revision("0009").module.downgrade()


def test_account_recovery_migration_only_adds_columns(monkeypatch):
    sql = offline_sql(monkeypatch, "0009", "0010")

    assert "ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE" in sql
    assert "ADD COLUMN IF NOT EXISTS totp_epoch INTEGER NOT NULL DEFAULT 0" in sql
    assert "UPDATE ATHENASEC_WEB_USERS" not in sql.upper()
    assert "DROP" not in sql.upper()
