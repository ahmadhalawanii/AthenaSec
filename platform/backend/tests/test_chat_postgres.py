"""PostgresChatStore against a real, migrated database (alembic upgrade head).

Skipped unless ATHENASEC_TEST_PG_URL points at an isolated, throwaway database.
"""

import os
import uuid

import psycopg
import pytest

from app.chat.store import PostgresChatStore

pytestmark = pytest.mark.skipif(
    not os.getenv("ATHENASEC_TEST_PG_URL"), reason="isolated PostgreSQL URL required"
)


@pytest.fixture
def store():
    return PostgresChatStore(os.environ["ATHENASEC_TEST_PG_URL"])


@pytest.fixture
def owner():
    return f"owner-{uuid.uuid4().hex[:8]}"


def test_sessions_belong_to_their_owner(store, owner):
    session = store.create_session(owner, "simple")

    assert store.get_session(session["session_id"], owner)["presentation"] == "simple"
    assert store.get_session(session["session_id"], "someone-else") is None
    assert [s["session_id"] for s in store.list_sessions(owner)] == [session["session_id"]]
    assert store.list_sessions("someone-else") == []


def test_messages_keep_order_and_meta(store, owner):
    session_id = store.create_session(owner, "technical")["session_id"]
    store.append_message(session_id, "user", "any urgent problems?")
    store.append_message(session_id, "assistant", "answer",
                         {"tools": ["soc_snapshot"], "data_status": "stored"})

    messages = store.list_messages(session_id)

    assert [m["role"] for m in messages] == ["user", "assistant"]
    assert messages[1]["meta"] == {"tools": ["soc_snapshot"], "data_status": "stored"}
    assert store.get_message(messages[1]["message_id"])["session_id"] == session_id
    assert store.get_message("MSG-missing") is None


def test_feedback_is_stored_and_the_database_rejects_a_bad_category(store, owner):
    session_id = store.create_session(owner, "simple")["session_id"]
    message_id = store.append_message(session_id, "assistant", "answer")["message_id"]

    saved = store.add_feedback(message_id, owner, "confusing", "too long")
    assert saved["feedback_id"].startswith("FB-")

    with pytest.raises(psycopg.errors.CheckViolation):
        store.add_feedback(message_id, owner, "bogus", None)

    with pytest.raises(psycopg.errors.CheckViolation):
        store.add_feedback(message_id, owner, "other", "x" * 501)


def test_a_message_must_belong_to_a_real_session(store):
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        store.append_message("CHAT-does-not-exist", "user", "hello")
