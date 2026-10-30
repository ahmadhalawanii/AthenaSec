"""Case workflow store (three backends) and IncidentResponseStore.list_all_incident_cases."""

from datetime import datetime, timedelta, timezone

import psycopg
import pytest

from app.schemas import (
    CaseActionRecord,
    CaseNoteRecord,
    CaseWorkflowRecord,
    IncidentCaseRecord,
)
from app.services.cases.case_workflow_store import (
    CaseWorkflowSchemaNotReady,
    InMemoryCaseWorkflowStore,
    PostgresCaseWorkflowStore,
    SQLiteCaseWorkflowStore,
)
from app.services.storage.incident_response_store import (
    InMemoryIncidentResponseStore,
    PostgresIncidentResponseStore,
    SQLiteIncidentResponseStore,
)

T0 = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)


def workflow(case_id="CASE-1", **overrides):
    fields = dict(case_id=case_id, assigned_analyst="analyst-1", summary="s",
                  closed_at=None, updated_at=T0, version=1)
    fields.update(overrides)
    return CaseWorkflowRecord(**fields)


def action(position, case_id="CASE-1", **overrides):
    fields = dict(case_id=case_id, position=position, label=f"Action {position}")
    fields.update(overrides)
    return CaseActionRecord(**fields)


def note(seq, case_id="CASE-1", **overrides):
    fields = dict(case_id=case_id, seq=seq, occurred_at=T0 + timedelta(minutes=seq),
                  title=f"Note {seq}", description="d", failed=False, author="analyst-1")
    fields.update(overrides)
    return CaseNoteRecord(**fields)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryCaseWorkflowStore()

    return SQLiteCaseWorkflowStore(tmp_path / "workflow.db")


# ---- workflow --------------------------------------------------------------

def test_empty_reads(store):
    assert store.get_workflow("CASE-1") is None
    assert store.list_actions("CASE-1") == []
    assert store.list_notes("CASE-1") == []


def test_workflow_round_trip_and_upsert(store):
    closed = T0 + timedelta(hours=1)
    store.save_workflow(workflow(closed_at=closed, version=2))

    loaded = store.get_workflow("CASE-1")
    assert loaded == workflow(closed_at=closed, version=2)

    store.save_workflow(workflow(assigned_analyst=None, summary=None, version=3))
    again = store.get_workflow("CASE-1")
    assert again.assigned_analyst is None and again.summary is None
    assert again.closed_at is None and again.version == 3


def test_workflow_version_must_be_positive():
    with pytest.raises(ValueError):
        workflow(version=0)


def test_cases_are_isolated(store):
    store.save_workflow(workflow("CASE-1", assigned_analyst="a"))
    store.save_workflow(workflow("CASE-2", assigned_analyst="b"))
    store.replace_actions("CASE-1", [action(0)])
    store.append_note(note(1, "CASE-1"))

    assert store.get_workflow("CASE-2").assigned_analyst == "b"
    assert store.list_actions("CASE-2") == [] and store.list_notes("CASE-2") == []


# ---- actions ---------------------------------------------------------------

def test_actions_replace_is_ordered_and_total(store):
    store.replace_actions("CASE-1", [action(2, done=True), action(0), action(1, approval_id="APR-1",
                                                                          proposed_action_id="PACT-1")])

    listed = store.list_actions("CASE-1")
    assert [a.position for a in listed] == [0, 1, 2]
    assert listed[2].done is True and listed[1].approval_id == "APR-1"

    store.replace_actions("CASE-1", [action(0, label="Only one")])
    assert [a.label for a in store.list_actions("CASE-1")] == ["Only one"]

    store.replace_actions("CASE-1", [])
    assert store.list_actions("CASE-1") == []


def test_invalid_action_sets_are_rejected_without_changes(store):
    store.replace_actions("CASE-1", [action(0)])

    with pytest.raises(ValueError):
        store.replace_actions("CASE-1", [action(0), action(0)])
    with pytest.raises(ValueError):
        store.replace_actions("CASE-1", [action(0, case_id="CASE-2")])

    assert [a.position for a in store.list_actions("CASE-1")] == [0]


# ---- notes -----------------------------------------------------------------

def test_notes_are_ordered_and_seq_unique(store):
    store.append_note(note(2))
    store.append_note(note(1, failed=True, author=None))

    listed = store.list_notes("CASE-1")
    assert [n.seq for n in listed] == [1, 2]
    assert listed[0].failed is True and listed[0].author is None
    assert listed[1].occurred_at == T0 + timedelta(minutes=2)

    with pytest.raises(ValueError):
        store.append_note(note(2))

    assert len(store.list_notes("CASE-1")) == 2


def test_sqlite_state_survives_reopening(tmp_path):
    path = tmp_path / "w.db"
    first = SQLiteCaseWorkflowStore(path)
    first.save_workflow(workflow())
    first.append_note(note(1))

    second = SQLiteCaseWorkflowStore(path)

    assert second.get_workflow("CASE-1") == workflow()
    assert len(second.list_notes("CASE-1")) == 1


# ---- postgres, recording connection ---------------------------------------

class Result:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class Connection:
    def __init__(self, log, script, error):
        self.log, self.script, self.error = log, script, error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement, params=None):
        text = " ".join(str(statement).split())
        self.log.append((text, params))
        if self.error is not None:
            raise self.error
        for needle, rows in self.script:
            if needle in text:
                return Result(rows)
        return Result([])


def pg(script=(), error=None):
    log, connections = [], []

    def connect(url):
        connections.append(url)
        return Connection(log, list(script), error)

    return PostgresCaseWorkflowStore("postgresql://test/test", connect=connect), log, connections


def test_postgres_constructor_creates_no_tables():
    _, log, _ = pg()

    assert log == []


def test_postgres_reads_map_rows_and_bind_ids():
    row = ("CASE-1", "analyst-1", "s", None, T0, 4)
    store, log, _ = pg(script=[("FROM case_workflow", [row]),
                               ("FROM case_actions", [("CASE-1", 0, "L", None, None, True)]),
                               ("FROM case_timeline", [("CASE-1", 1, T0, "t", "d", False, None)])])

    assert store.get_workflow("c'; DROP TABLE x;--").version == 4
    assert store.list_actions("CASE-1")[0].done is True
    assert store.list_notes("CASE-1")[0].title == "t"
    assert log[0][1] == ("c'; DROP TABLE x;--",)
    assert all("DROP TABLE" not in text for text, _ in log)


def test_postgres_missing_tables_raise_schema_not_ready():
    store, _, _ = pg(error=psycopg.errors.UndefinedTable("missing"))

    for call in (
        lambda: store.get_workflow("c"),
        lambda: store.save_workflow(workflow()),
        lambda: store.list_actions("c"),
        lambda: store.replace_actions("c", []),
        lambda: store.list_notes("c"),
        lambda: store.append_note(note(1, "c")),
    ):
        with pytest.raises(CaseWorkflowSchemaNotReady):
            call()


def test_postgres_replace_actions_runs_in_one_connection():
    store, log, connections = pg()
    log.clear()
    connections.clear()

    store.replace_actions("CASE-1", [action(0), action(1)])

    statements = [text for text, _ in log]
    assert statements[0].startswith("DELETE FROM case_actions")
    assert statements[1].startswith("INSERT INTO case_actions")
    assert statements[2].startswith("INSERT INTO case_actions")
    assert connections[:1] == ["postgresql://test/test"]
    # Exactly one connection for the three writes, then one more for the read-back.
    assert len(connections) == 2


def test_postgres_invalid_actions_never_reach_database():
    store, log, _ = pg()

    with pytest.raises(ValueError):
        store.replace_actions("CASE-1", [action(0), action(0)])

    assert log == []


def test_postgres_duplicate_note_seq_is_a_value_error():
    store, _, _ = pg(error=psycopg.errors.UniqueViolation("dup"))

    with pytest.raises(ValueError):
        store.append_note(note(1))


def test_postgres_save_workflow_upserts():
    store, log, _ = pg()

    store.save_workflow(workflow())

    text, params = log[-1]
    assert "ON CONFLICT (case_id) DO UPDATE" in text
    assert params[0] == "CASE-1" and params[-1] == 1


# ---- IncidentResponseStore.list_all_incident_cases -------------------------

def incident_case(case_id, incident_id, minutes):
    when = T0 + timedelta(minutes=minutes)
    return IncidentCaseRecord(case_id=case_id, incident_id=incident_id, status="open",
                              reason="r", created_at=when, updated_at=when)


@pytest.fixture(params=["memory", "sqlite"])
def response_store(request, tmp_path):
    if request.param == "memory":
        return InMemoryIncidentResponseStore()

    return SQLiteIncidentResponseStore(tmp_path / "response.db")


def test_list_all_incident_cases_empty(response_store):
    assert response_store.list_all_incident_cases() == []


def test_list_all_incident_cases_newest_first_across_incidents(response_store):
    for record in (incident_case("C-1", "INC-A", 1), incident_case("C-3", "INC-B", 3),
                   incident_case("C-2", "INC-A", 2)):
        response_store.save_incident_case(record)

    assert [c.case_id for c in response_store.list_all_incident_cases()] == ["C-3", "C-2", "C-1"]
    assert [c.case_id for c in response_store.list_incident_cases("INC-A")] == ["C-1", "C-2"]


def test_postgres_list_all_incident_cases_sql():
    log = []
    rows = [(incident_case("C-1", "INC-A", 1).model_dump_json(),)]

    class Conn(Connection):
        def execute(self, statement, params=None):
            log.append(" ".join(str(statement).split()))
            return Result(rows if "SELECT payload" in str(statement) else [])

    store = PostgresIncidentResponseStore(
        "postgresql://x/y", connect=lambda url: Conn(log, [], None))
    log.clear()

    result = store.list_all_incident_cases()

    assert [c.case_id for c in result] == ["C-1"]
    assert log[-1].endswith("FROM incident_cases ORDER BY created_at DESC, case_id DESC")
