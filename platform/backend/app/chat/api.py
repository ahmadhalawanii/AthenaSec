"""Routes for the Security Copilot. Reuses the app's own authentication; adds no new access."""

import re
import secrets
from datetime import datetime
from typing import Any, Callable, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from app.chat.service import ChatSources, knowledge_source, respond
from app.chat.store import ChatStore

Presentation = Literal["simple", "technical"]
RECORD_ID = re.compile(r"\b(?:ALT|ALERT|CASE|INC|INV|APR|PACT)-[A-Za-z0-9_-]+", re.IGNORECASE)
CSRF_HEADER = "x-athenasec-csrf"


class CreateSessionRequest(BaseModel):
    presentation: Presentation = "simple"


class MessageRequest(BaseModel):
    content: str
    presentation: Presentation | None = None

    @field_validator("content")
    @classmethod
    def check_content(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 2000:
            raise ValueError("Message must be 1 to 2000 characters.")
        return value


class FeedbackRequest(BaseModel):
    message_id: str
    category: Literal["confusing", "wrong_source", "incorrect", "other"]
    note: str | None = Field(default=None, max_length=500)


class EvidenceRef(BaseModel):
    type: str
    id: str
    href: str


class ChatAnswer(BaseModel):
    message_id: str
    answer: str
    answer_type: Literal["knowledge", "operational", "investigation", "action_status", "unable_to_verify"]
    data_status: Literal["live", "stored", "cached", "partial", "unavailable"]
    checked_at: datetime
    evidence_refs: list[EvidenceRef]
    known_limitations: list[str]
    suggested_followups: list[str]
    technical: dict[str, Any] | None = None


def _keeps_the_same_records(original: str, reworded: str) -> bool:
    """A reworded answer may not mention a record the facts never named."""
    known = {m.upper() for m in RECORD_ID.findall(original)}
    return {m.upper() for m in RECORD_ID.findall(reworded)} <= known


def register_chat_routes(
    app: FastAPI,
    *,
    require_identity: Callable,
    session_cookie_name: str,
    store: ChatStore,
    sources: ChatSources,
    phraser: Callable[[str, str], str] | None = None,
    audit: Callable[[Any, str, list[str], str], None] | None = None,
) -> None:
    def reader(request: Request, authorization: str | None = Header(default=None)):
        return require_identity(authorization, request=request)

    def writer(request: Request, authorization: str | None = Header(default=None)):
        principal = require_identity(authorization, request=request)
        # Browser sessions use cookies, so every change must carry the CSRF token
        if session_cookie_name in request.cookies:
            token = request.headers.get(CSRF_HEADER)
            if not token or not secrets.compare_digest(token, principal.csrf_token):
                raise HTTPException(status_code=403, detail="CSRF token required.")
        return principal

    def owned(session_id: str, principal) -> dict:
        session = store.get_session(session_id, principal.operator_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Chat session not found.")
        return session

    @app.get("/api/v1/chat/capabilities")
    def chat_capabilities(principal=Depends(reader)):
        return {
            "read_only": True,
            "can_execute_actions": False,
            "presentations": ["simple", "technical"],
            "topics": ["recent alerts", "alert by ID", "case by ID", "open cases",
                       "response mode", "security terms"],
        }

    @app.post("/api/v1/chat/sessions", status_code=201)
    def create_chat_session(payload: CreateSessionRequest | None = None, principal=Depends(writer)):
        payload = payload or CreateSessionRequest()
        return store.create_session(principal.operator_id, payload.presentation)

    @app.get("/api/v1/chat/sessions")
    def list_chat_sessions(principal=Depends(reader)):
        return {"items": store.list_sessions(principal.operator_id)}

    @app.get("/api/v1/chat/sessions/{session_id}")
    def get_chat_session(session_id: str, principal=Depends(reader)):
        session = owned(session_id, principal)
        messages = [
            {
                "message_id": m["message_id"], "role": m["role"], "content": m["content"],
                "created_at": m["created_at"], "tools": m["meta"].get("tools", []),
                "evidence_refs": m["meta"].get("evidence_refs", []),
                "data_status": m["meta"].get("data_status"),
            }
            for m in store.list_messages(session_id)
        ]
        return {**session, "messages": messages}

    @app.post("/api/v1/chat/sessions/{session_id}/messages", response_model=ChatAnswer)
    def send_chat_message(session_id: str, payload: MessageRequest, principal=Depends(writer)):
        session = owned(session_id, principal)
        presentation = payload.presentation or session["presentation"]
        store.append_message(session_id, "user", payload.content)

        result = respond(
            payload.content, sources, presentation=presentation,
            role=getattr(principal, "role", None),
        )

        # The facts are fixed above; the phraser may only reword them.
        if phraser is not None and result["data_status"] != "unavailable" and result["tools"]:
            try:
                reworded = phraser(result["answer"], presentation)
            except Exception:
                reworded = None
            if reworded and _keeps_the_same_records(result["answer"], reworded):
                result["answer"] = reworded

        message = store.append_message(session_id, "assistant", result["answer"], {
            "tools": result["tools"], "evidence_refs": result["evidence_refs"],
            "data_status": result["data_status"], "answer_type": result["answer_type"],
        })
        # Who asked, which tools ran and how fresh the data was; never the question text.
        # A read-only answer is not held back if the audit write fails.
        if audit is not None:
            try:
                audit(principal, session_id, result["tools"], result["data_status"])
            except Exception:
                pass

        return ChatAnswer(message_id=message["message_id"], **result)

    @app.get("/api/v1/chat/knowledge/sources/{source_id}")
    def get_knowledge_source(source_id: str, principal=Depends(reader)):
        source = knowledge_source(source_id)

        if source is None:
            raise HTTPException(status_code=404, detail="Knowledge source not found.")

        return source

    @app.post("/api/v1/chat/feedback", status_code=201)
    def send_chat_feedback(payload: FeedbackRequest, principal=Depends(writer)):
        message = store.get_message(payload.message_id)

        # Someone else's message reads exactly like a missing one
        if message is None or store.get_session(message["session_id"], principal.operator_id) is None:
            raise HTTPException(status_code=404, detail="Chat message not found.")

        record = store.add_feedback(
            payload.message_id, principal.operator_id, payload.category, payload.note)
        return {"feedback_id": record["feedback_id"]}
