"""Append-only, hash-chained audit log for operator and administrator events.

Separate from incident_audit_events, which is keyed by incident and records agent
activity. Each row stores prev_hash (the previous row's row_hash, or GENESIS_HASH) and
row_hash = sha256(prev_hash + canonical JSON of the row's fields), so editing or
removing a row in the middle of the log breaks verification from that row on.

Limits: truncating the newest rows cannot be detected from the log alone. verify_chain
returns head_hash so an outside monitor can pin it. The database role should also be
denied UPDATE/DELETE; the table triggers block them for every role but not for a
superuser who drops the trigger.

The Postgres table is created by Alembic migration 0003, never by this module.
Nothing in the application writes here yet: callers use append_event() from later steps.
"""

import hashlib
import ipaddress
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Protocol

import psycopg

from app.schemas import AuditEvent, ChainVerification, IncidentAuditRecord

GENESIS_HASH = "0" * 64
ACTOR_ROLES = {"Analyst", "Administrator", "System"}
RESULTS = {"Success", "Failed", "Denied"}
_ADVISORY_LOCK_KEY = 7_265_043_001

_COLUMNS = (
    "seq, event_id, occurred_at, actor_id, actor_role, category, action, "
    "target, result, source_ip, event_type, detail, prev_hash, row_hash"
)


class OperatorAuditSchemaNotReady(RuntimeError):
    """operator_audit_events does not exist yet (run alembic upgrade head)."""


def canonical_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_time(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )


def canonical_detail(detail: dict[str, Any]) -> str:
    return json.dumps(
        detail, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def compute_row_hash(
    prev_hash: str,
    *,
    event_id: str,
    occurred_at: datetime,
    actor_id: str,
    actor_role: str,
    category: str,
    action: str,
    target: str,
    result: str,
    source_ip: str | None,
    event_type: str | None,
    detail: dict[str, Any],
) -> str:
    body = json.dumps(
        {
            "event_id": event_id,
            "occurred_at": canonical_time(occurred_at),
            "actor_id": actor_id,
            "actor_role": actor_role,
            "category": category,
            "action": action,
            "target": target,
            "result": result,
            "source_ip": source_ip,
            "event_type": event_type,
            "detail": canonical_detail(detail),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

    return hashlib.sha256((prev_hash + body).encode("ascii")).hexdigest()


def _row_hash_for(prev_hash: str, event: AuditEvent) -> str:
    return compute_row_hash(
        prev_hash,
        event_id=event.event_id,
        occurred_at=event.occurred_at,
        actor_id=event.actor_id,
        actor_role=event.actor_role,
        category=event.category,
        action=event.action,
        target=event.target,
        result=event.result,
        source_ip=event.source_ip,
        event_type=event.event_type,
        detail=event.detail,
    )


def verify_chain(events: Iterable[AuditEvent]) -> ChainVerification:
    """Walk events in seq order and report the first row that does not chain."""

    previous = GENESIS_HASH
    checked = 0

    for event in events:
        if (
            event.prev_hash != previous
            or _row_hash_for(previous, event) != event.row_hash
        ):
            return ChainVerification(
                valid=False,
                checked=checked,
                first_broken_seq=event.seq,
                head_hash=None,
            )

        previous = event.row_hash
        checked += 1

    return ChainVerification(
        valid=True,
        checked=checked,
        first_broken_seq=None,
        head_hash=previous if checked else None,
    )


def _validated_fields(
    *,
    actor_id: str,
    actor_role: str,
    category: str,
    action: str,
    target: str,
    result: str,
    source_ip: str | None,
    event_type: str | None,
    detail: dict[str, Any] | None,
    occurred_at: datetime | None,
) -> dict[str, Any]:
    for name, value in (
        ("actor_id", actor_id),
        ("category", category),
        ("action", action),
        ("target", target),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} is required.")

    if actor_role not in ACTOR_ROLES:
        raise ValueError("actor_role must be Analyst, Administrator or System.")

    if result not in RESULTS:
        raise ValueError("result must be Success, Failed or Denied.")

    if source_ip is not None:
        source_ip = str(ipaddress.ip_address(source_ip.strip()))

    detail = {} if detail is None else detail

    if not isinstance(detail, dict):
        raise ValueError("detail must be an object.")

    # Must survive a JSON round trip unchanged, or the stored hash could not be rechecked.
    if json.loads(canonical_detail(detail)) != detail:
        raise ValueError("detail must contain only JSON values.")

    when = datetime.now(timezone.utc) if occurred_at is None else occurred_at
    when = _parse_time(canonical_time(when))

    return dict(
        event_id="OPAUD-" + uuid.uuid4().hex,
        occurred_at=when,
        actor_id=actor_id.strip(),
        actor_role=actor_role,
        category=category.strip(),
        action=action.strip(),
        target=target.strip(),
        result=result,
        source_ip=source_ip,
        event_type=event_type,
        detail=detail,
    )


def _matches(
    event: AuditEvent,
    *,
    actor: str | None,
    category: str | None,
    result: str | None,
    event_type: str | None,
    since: datetime | None,
    until: datetime | None,
) -> bool:
    if actor is not None and event.actor_id != actor:
        return False
    if category is not None and event.category != category:
        return False
    if result is not None and event.result != result:
        return False
    if event_type is not None and event.event_type != event_type:
        return False
    if since is not None and event.occurred_at < since:
        return False
    if until is not None and event.occurred_at > until:
        return False
    return True


class OperatorAuditStore(Protocol):
    def append_event(self, **fields: Any) -> AuditEvent: ...

    def get_event(self, event_id: str) -> AuditEvent | None: ...

    def list_events(self, **filters: Any) -> list[AuditEvent]: ...

    def verify_chain(self) -> ChainVerification: ...


class InMemoryOperatorAuditStore:
    def __init__(self):
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def append_event(self, *, actor_id, actor_role, category, action, target,
                     result, source_ip=None, event_type=None, detail=None,
                     occurred_at=None) -> AuditEvent:
        fields = _validated_fields(
            actor_id=actor_id, actor_role=actor_role, category=category,
            action=action, target=target, result=result, source_ip=source_ip,
            event_type=event_type, detail=detail, occurred_at=occurred_at,
        )

        with self._lock:
            prev = self._events[-1].row_hash if self._events else GENESIS_HASH
            event = AuditEvent(
                seq=len(self._events) + 1,
                source="operator",
                prev_hash=prev,
                row_hash=compute_row_hash(prev, **fields),
                **fields,
            )
            self._events.append(event)

        return event

    def get_event(self, event_id: str) -> AuditEvent | None:
        return next((e for e in self._events if e.event_id == event_id), None)

    def list_events(self, *, actor=None, category=None, result=None,
                    event_type=None, since=None, until=None) -> list[AuditEvent]:
        events = [
            e for e in self._events
            if _matches(e, actor=actor, category=category, result=result,
                        event_type=event_type, since=since, until=until)
        ]

        return sorted(events, key=lambda e: e.seq, reverse=True)

    def verify_chain(self) -> ChainVerification:
        return verify_chain(list(self._events))


def _event_from_row(row) -> AuditEvent:
    occurred = row[2]

    if isinstance(occurred, str):
        occurred = _parse_time(occurred)

    return AuditEvent(
        seq=row[0],
        event_id=row[1],
        occurred_at=occurred,
        actor_id=row[3],
        actor_role=row[4],
        category=row[5],
        action=row[6],
        target=row[7],
        result=row[8],
        source_ip=row[9],
        event_type=row[10],
        detail=json.loads(row[11]),
        prev_hash=row[12],
        row_hash=row[13],
        source="operator",
    )


def _filter_sql(placeholder: str, *, actor, category, result, event_type,
                since, until, time_value):
    clauses, params = [], []

    for column, value in (
        ("actor_id", actor),
        ("category", category),
        ("result", result),
        ("event_type", event_type),
    ):
        if value is not None:
            clauses.append(f"{column} = {placeholder}")
            params.append(value)

    if since is not None:
        clauses.append(f"occurred_at >= {placeholder}")
        params.append(time_value(since))

    if until is not None:
        clauses.append(f"occurred_at <= {placeholder}")
        params.append(time_value(until))

    return (" WHERE " + " AND ".join(clauses) if clauses else ""), tuple(params)


class SQLiteOperatorAuditStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        # isolation_level=None: transactions are explicit (BEGIN IMMEDIATE) so appends serialise.
        return sqlite3.connect(self.database_path, isolation_level=None, timeout=30)

    def _initialize_database(self) -> None:
        connection = self._connect()

        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    occurred_at TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL
                        CHECK (actor_role IN ('Analyst','Administrator','System')),
                    category TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result TEXT NOT NULL
                        CHECK (result IN ('Success','Failed','Denied')),
                    source_ip TEXT,
                    event_type TEXT,
                    detail TEXT NOT NULL DEFAULT '{}',
                    prev_hash TEXT NOT NULL,
                    row_hash TEXT NOT NULL UNIQUE
                )
                """
            )
            for name, operation in (("update", "UPDATE"), ("delete", "DELETE")):
                connection.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS operator_audit_events_no_{name}
                    BEFORE {operation} ON operator_audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'operator_audit_events is append-only');
                    END
                    """
                )
            for column in ("occurred_at", "actor_id", "category"):
                connection.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_operator_audit_events_{column}
                    ON operator_audit_events({column})
                    """
                )
        finally:
            connection.close()

    def append_event(self, *, actor_id, actor_role, category, action, target,
                     result, source_ip=None, event_type=None, detail=None,
                     occurred_at=None) -> AuditEvent:
        fields = _validated_fields(
            actor_id=actor_id, actor_role=actor_role, category=category,
            action=action, target=target, result=result, source_ip=source_ip,
            event_type=event_type, detail=detail, occurred_at=occurred_at,
        )
        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                last = connection.execute(
                    "SELECT row_hash FROM operator_audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = last[0] if last else GENESIS_HASH
                row_hash = compute_row_hash(prev, **fields)
                cursor = connection.execute(
                    """
                    INSERT INTO operator_audit_events (
                        event_id, occurred_at, actor_id, actor_role, category,
                        action, target, result, source_ip, event_type, detail,
                        prev_hash, row_hash
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fields["event_id"], canonical_time(fields["occurred_at"]),
                        fields["actor_id"], fields["actor_role"], fields["category"],
                        fields["action"], fields["target"], fields["result"],
                        fields["source_ip"], fields["event_type"],
                        canonical_detail(fields["detail"]), prev, row_hash,
                    ),
                )
                seq = cursor.lastrowid
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        finally:
            connection.close()

        return AuditEvent(seq=seq, source="operator", prev_hash=prev,
                          row_hash=row_hash, **fields)

    def get_event(self, event_id: str) -> AuditEvent | None:
        connection = self._connect()

        try:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM operator_audit_events WHERE event_id = ?",
                (event_id,),
            ).fetchone()
        finally:
            connection.close()

        return _event_from_row(row) if row else None

    def list_events(self, *, actor=None, category=None, result=None,
                    event_type=None, since=None, until=None) -> list[AuditEvent]:
        where, params = _filter_sql(
            "?", actor=actor, category=category, result=result,
            event_type=event_type, since=since, until=until,
            time_value=canonical_time,
        )
        connection = self._connect()

        try:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM operator_audit_events{where} ORDER BY seq DESC",
                params,
            ).fetchall()
        finally:
            connection.close()

        return [_event_from_row(row) for row in rows]

    def verify_chain(self) -> ChainVerification:
        connection = self._connect()

        try:
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM operator_audit_events ORDER BY seq ASC"
            ).fetchall()
        finally:
            connection.close()

        return verify_chain(_event_from_row(row) for row in rows)


class PostgresOperatorAuditStore:
    """Reads and appends only; the table, indexes and triggers come from migration 0003."""

    def __init__(self, database_url: str, *, connect=None):
        self.database_url = database_url
        self._connect = psycopg.connect if connect is None else connect

    def append_event(self, *, actor_id, actor_role, category, action, target,
                     result, source_ip=None, event_type=None, detail=None,
                     occurred_at=None) -> AuditEvent:
        fields = _validated_fields(
            actor_id=actor_id, actor_role=actor_role, category=category,
            action=action, target=target, result=result, source_ip=source_ip,
            event_type=event_type, detail=detail, occurred_at=occurred_at,
        )

        try:
            with self._connect(self.database_url) as connection:
                # One writer at a time for the whole table keeps the chain linear.
                connection.execute(
                    "SELECT pg_advisory_xact_lock(%s)", (_ADVISORY_LOCK_KEY,)
                )
                last = connection.execute(
                    "SELECT row_hash FROM operator_audit_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev = last[0] if last else GENESIS_HASH
                row_hash = compute_row_hash(prev, **fields)
                seq = connection.execute(
                    """
                    INSERT INTO operator_audit_events (
                        event_id, occurred_at, actor_id, actor_role, category,
                        action, target, result, source_ip, event_type, detail,
                        prev_hash, row_hash
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING seq
                    """,
                    (
                        fields["event_id"], fields["occurred_at"],
                        fields["actor_id"], fields["actor_role"], fields["category"],
                        fields["action"], fields["target"], fields["result"],
                        fields["source_ip"], fields["event_type"],
                        canonical_detail(fields["detail"]), prev, row_hash,
                    ),
                ).fetchone()[0]
        except psycopg.errors.UndefinedTable as exc:
            raise OperatorAuditSchemaNotReady("Run alembic upgrade head.") from exc

        return AuditEvent(seq=seq, source="operator", prev_hash=prev,
                          row_hash=row_hash, **fields)

    def _fetch(self, statement: str, params: tuple = (), *, one: bool = False):
        try:
            with self._connect(self.database_url) as connection:
                result = connection.execute(statement, params)
                return result.fetchone() if one else result.fetchall()
        except psycopg.errors.UndefinedTable as exc:
            raise OperatorAuditSchemaNotReady("Run alembic upgrade head.") from exc

    def get_event(self, event_id: str) -> AuditEvent | None:
        row = self._fetch(
            f"SELECT {_COLUMNS} FROM operator_audit_events WHERE event_id = %s",
            (event_id,), one=True,
        )

        return _event_from_row(row) if row else None

    def list_events(self, *, actor=None, category=None, result=None,
                    event_type=None, since=None, until=None) -> list[AuditEvent]:
        where, params = _filter_sql(
            "%s", actor=actor, category=category, result=result,
            event_type=event_type, since=since, until=until,
            time_value=lambda value: value,
        )
        rows = self._fetch(
            f"SELECT {_COLUMNS} FROM operator_audit_events{where} ORDER BY seq DESC",
            params,
        )

        return [_event_from_row(row) for row in rows]

    def verify_chain(self) -> ChainVerification:
        rows = self._fetch(
            f"SELECT {_COLUMNS} FROM operator_audit_events ORDER BY seq ASC"
        )

        return verify_chain(_event_from_row(row) for row in rows)


def incident_event_view(record: IncidentAuditRecord) -> AuditEvent:
    """Read-only view of an agent event in the audit list. Not hash-chained."""

    return AuditEvent(
        event_id=record.audit_id,
        occurred_at=record.timestamp,
        actor_id="system",
        actor_role="System",
        category=record.entity_type,
        action=record.event_type,
        target=record.entity_id,
        result="Success",
        source="incident",
        incident_id=record.incident_id,
        event_type=record.event_type,
        message=record.message,
        detail=record.details,
    )


def view_matches(
    event: AuditEvent,
    *,
    actor: str | None,
    category: str | None,
    result: str | None,
    alert_id: str | None,
    q: str | None,
) -> bool:
    if actor is not None and event.actor_id != actor:
        return False
    if category is not None and event.category != category:
        return False
    if result is not None and event.result != result:
        return False
    if alert_id is not None and event.target != alert_id:
        return False
    if q:
        needle = q.strip().casefold()
        haystack = (
            event.actor_id, event.category, event.action, event.target,
            event.message or "",
        )
        if not any(needle in part.casefold() for part in haystack):
            return False
    return True
