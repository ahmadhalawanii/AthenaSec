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


PREVIEW_CHARS = 80


def _preview(text: str | None) -> str:
    """The first question of a session, shortened, for the history list."""
    flat = " ".join((text or "").split())

    return flat if len(flat) <= PREVIEW_CHARS else flat[:PREVIEW_CHARS].rstrip() + "…"


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

    def list_feedback(self, limit: int = 200) -> list[dict[str, Any]]: ...


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
            mine = [
                {**s, "preview": _preview(next(
                    (m["content"] for m in self._messages[s["session_id"]] if m["role"] == "user"), ""))}
                for s in self._sessions.values() if s["owner_id"] == owner_id
            ]
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

    def list_feedback(self, limit=200):
        with self._lock:
            records = sorted(self._feedback, key=lambda r: r["created_at"], reverse=True)[:limit]
            found = []
            for record in records:
                message = next((m for ms in self._messages.values() for m in ms
                                if m["message_id"] == record["message_id"]), None)
                found.append({**record, "answer": message["content"] if message else "",
                              "session_id": message["session_id"] if message else None})
        return found


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
            "presentation": presentation, "created_at": row[0], "preview": "",
        }

    def _session(self, row):
        return {
            "session_id": row[0], "owner_id": row[1],
            "presentation": row[2], "created_at": row[3],
            "preview": _preview(row[4]) if len(row) > 4 else "",
        }

    def list_sessions(self, owner_id):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT s.session_id, s.owner_id, s.presentation, s.created_at, "
                "(SELECT left(m.content, 200) FROM chat_messages m WHERE m.session_id = s.session_id "
                "AND m.role = 'user' ORDER BY m.created_at, m.message_id LIMIT 1) "
                "FROM chat_sessions s WHERE s.owner_id = %s ORDER BY s.created_at DESC LIMIT 200",
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

    def list_feedback(self, limit=200):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT f.feedback_id, f.message_id, f.owner_id, f.category, f.note, f.created_at, "
                "m.content, m.session_id FROM chat_feedback f "
                "JOIN chat_messages m ON m.message_id = f.message_id "
                "ORDER BY f.created_at DESC, f.feedback_id DESC LIMIT %s",
                (limit,),
            ).fetchall()
        keys = ["feedback_id", "message_id", "owner_id", "category", "note", "created_at",
                "answer", "session_id"]
        return [dict(zip(keys, row)) for row in rows]


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
