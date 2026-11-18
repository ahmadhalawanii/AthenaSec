"""Chat sessions and messages. A session belongs to the operator who created it.

Postgres tables (chat_sessions, chat_messages) are created by Alembic migration 0012.
"""

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

import psycopg


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ChatStore(Protocol):
    def create_session(self, owner_id: str, presentation: str) -> dict[str, Any]: ...

    def list_sessions(self, owner_id: str) -> list[dict[str, Any]]: ...

    def get_session(self, session_id: str, owner_id: str) -> dict[str, Any] | None: ...

    def append_message(
        self, session_id: str, role: str, content: str, meta: dict[str, Any] | None = None
    ) -> dict[str, Any]: ...

    def list_messages(self, session_id: str) -> list[dict[str, Any]]: ...

    def get_message(self, message_id: str) -> dict[str, Any] | None: ...

    def add_feedback(
        self, message_id: str, owner_id: str, category: str, note: str | None
    ) -> dict[str, Any]: ...


class InMemoryChatStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._messages: dict[str, list[dict[str, Any]]] = {}
        self._feedback: list[dict[str, Any]] = []

    def create_session(self, owner_id, presentation):
        session = {
            "session_id": f"CHAT-{uuid.uuid4().hex[:12]}",
            "owner_id": owner_id,
            "presentation": presentation,
            "created_at": _now(),
        }
        with self._lock:
            self._sessions[session["session_id"]] = session
            self._messages[session["session_id"]] = []
        return dict(session)

    def list_sessions(self, owner_id):
        with self._lock:
            mine = [s for s in self._sessions.values() if s["owner_id"] == owner_id]
        return sorted(mine, key=lambda s: s["created_at"], reverse=True)

    def get_session(self, session_id, owner_id):
        with self._lock:
            session = self._sessions.get(session_id)
        # Someone else's session reads exactly like a missing one
        return dict(session) if session and session["owner_id"] == owner_id else None

    def append_message(self, session_id, role, content, meta=None):
        message = {
            "message_id": f"MSG-{uuid.uuid4().hex[:12]}",
            "session_id": session_id,
            "role": role,
            "content": content,
            "meta": meta or {},
            "created_at": _now(),
        }
        with self._lock:
            self._messages[session_id].append(message)
        return dict(message)

    def list_messages(self, session_id):
        with self._lock:
            return [dict(m) for m in self._messages.get(session_id, [])]

    def get_message(self, message_id):
        with self._lock:
            for messages in self._messages.values():
                for message in messages:
                    if message["message_id"] == message_id:
                        return dict(message)
        return None

    def add_feedback(self, message_id, owner_id, category, note):
        record = {
            "feedback_id": f"FB-{uuid.uuid4().hex[:12]}", "message_id": message_id,
            "owner_id": owner_id, "category": category, "note": note, "created_at": _now(),
        }
        with self._lock:
            self._feedback.append(record)
        return dict(record)


class PostgresChatStore:
    def __init__(self, database_url: str):
        self._url = database_url

    def _connect(self):
        return psycopg.connect(self._url)

    def create_session(self, owner_id, presentation):
        session_id = f"CHAT-{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO chat_sessions (session_id, owner_id, presentation, created_at) "
                "VALUES (%s, %s, %s, now()) RETURNING created_at",
                (session_id, owner_id, presentation),
            ).fetchone()
        return {
            "session_id": session_id, "owner_id": owner_id,
            "presentation": presentation, "created_at": row[0],
        }

    def _session(self, row):
        return {
            "session_id": row[0], "owner_id": row[1],
            "presentation": row[2], "created_at": row[3],
        }

    def list_sessions(self, owner_id):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT session_id, owner_id, presentation, created_at FROM chat_sessions "
                "WHERE owner_id = %s ORDER BY created_at DESC LIMIT 200",
                (owner_id,),
            ).fetchall()
        return [self._session(r) for r in rows]

    def get_session(self, session_id, owner_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT session_id, owner_id, presentation, created_at FROM chat_sessions "
                "WHERE session_id = %s AND owner_id = %s",
                (session_id, owner_id),
            ).fetchone()
        return self._session(row) if row else None

    def append_message(self, session_id, role, content, meta=None):
        message_id = f"MSG-{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO chat_messages (message_id, session_id, role, content, meta, created_at) "
                "VALUES (%s, %s, %s, %s, %s::jsonb, now()) RETURNING created_at",
                (message_id, session_id, role, content, json.dumps(meta or {}, default=str)),
            ).fetchone()
        return {
            "message_id": message_id, "session_id": session_id, "role": role,
            "content": content, "meta": meta or {}, "created_at": row[0],
        }

    def list_messages(self, session_id):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT message_id, session_id, role, content, meta, created_at "
                "FROM chat_messages WHERE session_id = %s ORDER BY created_at, message_id",
                (session_id,),
            ).fetchall()
        return [
            {"message_id": r[0], "session_id": r[1], "role": r[2],
             "content": r[3], "meta": r[4] or {}, "created_at": r[5]}
            for r in rows
        ]

    def get_message(self, message_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT message_id, session_id, role, content, meta, created_at "
                "FROM chat_messages WHERE message_id = %s",
                (message_id,),
            ).fetchone()
        return None if row is None else {
            "message_id": row[0], "session_id": row[1], "role": row[2],
            "content": row[3], "meta": row[4] or {}, "created_at": row[5],
        }

    def add_feedback(self, message_id, owner_id, category, note):
        feedback_id = f"FB-{uuid.uuid4().hex[:12]}"
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO chat_feedback (feedback_id, message_id, owner_id, category, note, created_at) "
                "VALUES (%s, %s, %s, %s, %s, now()) RETURNING created_at",
                (feedback_id, message_id, owner_id, category, note),
            ).fetchone()
        return {
            "feedback_id": feedback_id, "message_id": message_id, "owner_id": owner_id,
            "category": category, "note": note, "created_at": row[0],
        }


def build_chat_store_from_env() -> ChatStore:
    backend = os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower()

    if backend == "sqlite":
        # ponytail: dev SQLite mode keeps chat in memory; add a SQLite store if it must survive restarts
        return InMemoryChatStore()

    if backend != "postgres":
        raise ValueError(f"Unsupported ATHENASEC_PERSISTENCE_BACKEND: {backend}")

    database_url = os.getenv("ATHENASEC_DATABASE_URL")

    if not database_url:
        raise ValueError("ATHENASEC_DATABASE_URL is required.")

    return PostgresChatStore(database_url)
