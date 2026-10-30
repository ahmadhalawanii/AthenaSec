"""Analyst workflow state that sits beside incident_cases (assignee, notes, ticked actions).

incident_cases is never altered. A case with no rows here simply reads as unassigned, with
no notes and no stored actions, so nothing needs backfilling.

The Postgres tables (case_workflow, case_actions, case_timeline) are created by Alembic
migration 0004, never by this module. SQLite tables are created by the constructor.

Routes only read these tables for now; the save/replace/append methods exist so later
steps can write and so tests can build fixtures.
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Protocol

import psycopg

from app.schemas import (
    CaseActionRecord,
    CaseNoteRecord,
    CaseWorkflowRecord,
)


class CaseWorkflowSchemaNotReady(RuntimeError):
    """The case workflow tables do not exist yet (run alembic upgrade head)."""


class CaseWorkflowStore(Protocol):
    def get_workflow(self, case_id: str) -> CaseWorkflowRecord | None: ...

    def save_workflow(self, record: CaseWorkflowRecord) -> CaseWorkflowRecord: ...

    def list_actions(self, case_id: str) -> list[CaseActionRecord]: ...

    def replace_actions(
        self, case_id: str, actions: list[CaseActionRecord]
    ) -> list[CaseActionRecord]: ...

    def list_notes(self, case_id: str) -> list[CaseNoteRecord]: ...

    def append_note(self, note: CaseNoteRecord) -> CaseNoteRecord: ...


def _check_actions(case_id, actions):
    positions = [action.position for action in actions]

    if any(action.case_id != case_id for action in actions):
        raise ValueError("Every action must belong to the case.")

    if len(set(positions)) != len(positions):
        raise ValueError("Action positions must be unique.")


class InMemoryCaseWorkflowStore:
    def __init__(self):
        self._workflows: dict[str, CaseWorkflowRecord] = {}
        self._actions: dict[str, list[CaseActionRecord]] = {}
        self._notes: dict[str, list[CaseNoteRecord]] = {}
        self._lock = threading.Lock()

    def get_workflow(self, case_id):
        return self._workflows.get(case_id)

    def save_workflow(self, record):
        with self._lock:
            self._workflows[record.case_id] = record

        return record

    def list_actions(self, case_id):
        return sorted(self._actions.get(case_id, []), key=lambda a: a.position)

    def replace_actions(self, case_id, actions):
        _check_actions(case_id, actions)

        with self._lock:
            self._actions[case_id] = list(actions)

        return self.list_actions(case_id)

    def list_notes(self, case_id):
        return sorted(self._notes.get(case_id, []), key=lambda n: n.seq)

    def append_note(self, note):
        with self._lock:
            notes = self._notes.setdefault(note.case_id, [])

            if any(existing.seq == note.seq for existing in notes):
                raise ValueError(f"Note seq {note.seq} already exists for the case.")

            notes.append(note)

        return note


def _time(value):
    return value if isinstance(value, datetime) else datetime.fromisoformat(value)


def _workflow_from_row(row):
    return CaseWorkflowRecord(
        case_id=row[0],
        assigned_analyst=row[1],
        summary=row[2],
        closed_at=None if row[3] is None else _time(row[3]),
        updated_at=_time(row[4]),
        version=row[5],
    )


def _action_from_row(row):
    return CaseActionRecord(
        case_id=row[0],
        position=row[1],
        label=row[2],
        proposed_action_id=row[3],
        approval_id=row[4],
        done=bool(row[5]),
    )


def _note_from_row(row):
    return CaseNoteRecord(
        case_id=row[0],
        seq=row[1],
        occurred_at=_time(row[2]),
        title=row[3],
        description=row[4],
        failed=bool(row[5]),
        author=row[6],
    )


_WORKFLOW_COLUMNS = "case_id, assigned_analyst, summary, closed_at, updated_at, version"
_ACTION_COLUMNS = "case_id, position, label, proposed_action_id, approval_id, done"
_NOTE_COLUMNS = "case_id, seq, occurred_at, title, description, failed, author"


class SQLiteCaseWorkflowStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, timeout=30)

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_workflow (
                    case_id TEXT PRIMARY KEY,
                    assigned_analyst TEXT,
                    summary TEXT,
                    closed_at TEXT,
                    updated_at TEXT NOT NULL,
                    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_actions (
                    case_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    label TEXT NOT NULL,
                    proposed_action_id TEXT,
                    approval_id TEXT,
                    done INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (case_id, position)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_timeline (
                    case_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    failed INTEGER NOT NULL DEFAULT 0,
                    author TEXT,
                    PRIMARY KEY (case_id, seq)
                )
                """
            )

    def get_workflow(self, case_id):
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {_WORKFLOW_COLUMNS} FROM case_workflow WHERE case_id = ?",
                (case_id,),
            ).fetchone()

        return _workflow_from_row(row) if row else None

    def save_workflow(self, record):
        with self._connect() as connection:
            connection.execute(
                f"""
                INSERT INTO case_workflow ({_WORKFLOW_COLUMNS})
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (case_id) DO UPDATE SET
                    assigned_analyst = excluded.assigned_analyst,
                    summary = excluded.summary,
                    closed_at = excluded.closed_at,
                    updated_at = excluded.updated_at,
                    version = excluded.version
                """,
                (
                    record.case_id, record.assigned_analyst, record.summary,
                    None if record.closed_at is None else record.closed_at.isoformat(),
                    record.updated_at.isoformat(), record.version,
                ),
            )

        return record

    def list_actions(self, case_id):
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {_ACTION_COLUMNS} FROM case_actions WHERE case_id = ? ORDER BY position",
                (case_id,),
            ).fetchall()

        return [_action_from_row(row) for row in rows]

    def replace_actions(self, case_id, actions):
        _check_actions(case_id, actions)

        with self._connect() as connection:
            connection.execute("DELETE FROM case_actions WHERE case_id = ?", (case_id,))
            connection.executemany(
                f"INSERT INTO case_actions ({_ACTION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (a.case_id, a.position, a.label, a.proposed_action_id,
                     a.approval_id, int(a.done))
                    for a in actions
                ],
            )

        return self.list_actions(case_id)

    def list_notes(self, case_id):
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT {_NOTE_COLUMNS} FROM case_timeline WHERE case_id = ? ORDER BY seq",
                (case_id,),
            ).fetchall()

        return [_note_from_row(row) for row in rows]

    def append_note(self, note):
        try:
            with self._connect() as connection:
                connection.execute(
                    f"INSERT INTO case_timeline ({_NOTE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (note.case_id, note.seq, note.occurred_at.isoformat(), note.title,
                     note.description, int(note.failed), note.author),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Note seq {note.seq} already exists for the case.") from exc

        return note


class PostgresCaseWorkflowStore:
    """Reads and writes only; tables come from migration 0004."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def _run(self, statement, params=(), *, fetch=None, many=None):
        try:
            with self._connect(self.database_url) as connection:
                if many is not None:
                    for step_statement, step_params in many:
                        connection.execute(step_statement, step_params)
                    return None

                result = connection.execute(statement, params)

                if fetch == "one":
                    return result.fetchone()

                if fetch == "all":
                    return result.fetchall()

                return None
        except psycopg.errors.UndefinedTable as exc:
            raise CaseWorkflowSchemaNotReady("Run alembic upgrade head.") from exc

    def get_workflow(self, case_id):
        row = self._run(
            f"SELECT {_WORKFLOW_COLUMNS} FROM case_workflow WHERE case_id = %s",
            (case_id,), fetch="one",
        )

        return _workflow_from_row(row) if row else None

    def save_workflow(self, record):
        self._run(
            f"""
            INSERT INTO case_workflow ({_WORKFLOW_COLUMNS})
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (case_id) DO UPDATE SET
                assigned_analyst = EXCLUDED.assigned_analyst,
                summary = EXCLUDED.summary,
                closed_at = EXCLUDED.closed_at,
                updated_at = EXCLUDED.updated_at,
                version = EXCLUDED.version
            """,
            (record.case_id, record.assigned_analyst, record.summary,
             record.closed_at, record.updated_at, record.version),
        )

        return record

    def list_actions(self, case_id):
        rows = self._run(
            f"SELECT {_ACTION_COLUMNS} FROM case_actions WHERE case_id = %s ORDER BY position",
            (case_id,), fetch="all",
        )

        return [_action_from_row(row) for row in rows]

    def replace_actions(self, case_id, actions):
        _check_actions(case_id, actions)
        # One connection, so the delete and inserts commit together.
        steps = [("DELETE FROM case_actions WHERE case_id = %s", (case_id,))]
        steps += [
            (
                f"INSERT INTO case_actions ({_ACTION_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s)",
                (a.case_id, a.position, a.label, a.proposed_action_id, a.approval_id, a.done),
            )
            for a in actions
        ]
        self._run(None, many=steps)

        return self.list_actions(case_id)

    def list_notes(self, case_id):
        rows = self._run(
            f"SELECT {_NOTE_COLUMNS} FROM case_timeline WHERE case_id = %s ORDER BY seq",
            (case_id,), fetch="all",
        )

        return [_note_from_row(row) for row in rows]

    def append_note(self, note):
        try:
            self._run(
                f"INSERT INTO case_timeline ({_NOTE_COLUMNS}) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (note.case_id, note.seq, note.occurred_at, note.title,
                 note.description, note.failed, note.author),
            )
        except psycopg.errors.UniqueViolation as exc:
            raise ValueError(f"Note seq {note.seq} already exists for the case.") from exc

        return note
