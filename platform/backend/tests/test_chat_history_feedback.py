"""Chat history (what a person can resume) and feedback review (what an administrator can read)."""

from datetime import datetime

import pytest

from app.chat.store import InMemoryChatStore
from tests.test_chat_api import ChatHarness, build_client, say

FEEDBACK = "/api/v1/chat/feedback"


class Pair:
    """An analyst and an administrator on one chat store, so the admin sees the analyst's feedback."""

    def __init__(self):
        self.h = ChatHarness()
        shared = dict(chat_store=InMemoryChatStore())
        self.analyst = build_client(self.h, **shared)
        self.admin = build_client(self.h, admin=True, **shared)

    def ask(self, text, client=None):
        return say(client or self.analyst, text).json()


# ---- history ---------------------------------------------------------------------------

def test_sessions_list_shows_a_preview_of_the_first_question_newest_first():
    pair = Pair()
    first = pair.analyst.post("/api/v1/chat/sessions", json={}).json()["session_id"]
    second = pair.analyst.post("/api/v1/chat/sessions", json={}).json()["session_id"]
    pair.analyst.post(f"/api/v1/chat/sessions/{first}/messages", json={"content": "any urgent problems?"})
    long_question = "show my unresolved cases " + "please " * 30
    pair.analyst.post(f"/api/v1/chat/sessions/{second}/messages", json={"content": long_question})

    items = pair.analyst.get("/api/v1/chat/sessions").json()["items"]

    assert [i["session_id"] for i in items] == [second, first]
    assert items[1]["preview"] == "any urgent problems?"
    assert items[0]["preview"].startswith("show my unresolved cases")
    assert len(items[0]["preview"]) <= 81 and items[0]["preview"].endswith("…")


def test_an_empty_session_has_an_empty_preview():
    pair = Pair()
    pair.analyst.post("/api/v1/chat/sessions", json={})

    assert pair.analyst.get("/api/v1/chat/sessions").json()["items"][0]["preview"] == ""


def test_history_keeps_what_is_needed_to_show_an_answer_again():
    pair = Pair()
    session_id = pair.analyst.post("/api/v1/chat/sessions", json={}).json()["session_id"]
    answer = pair.analyst.post(
        f"/api/v1/chat/sessions/{session_id}/messages", json={"content": "any urgent problems?"}).json()

    saved = pair.analyst.get(f"/api/v1/chat/sessions/{session_id}").json()["messages"][1]

    assert saved["content"] == answer["answer"]
    assert saved["answer_type"] == answer["answer_type"]
    # the same moment, whichever way the live answer and the saved copy write the timezone
    assert datetime.fromisoformat(saved["checked_at"]) == datetime.fromisoformat(answer["checked_at"])
    assert saved["known_limitations"] == answer["known_limitations"]
    assert saved["suggested_followups"] == answer["suggested_followups"]
    assert [r["id"] for r in saved["evidence_refs"]] == [r["id"] for r in answer["evidence_refs"]]


def test_someone_elses_history_stays_private():
    pair = Pair()
    session_id = pair.analyst.post("/api/v1/chat/sessions", json={}).json()["session_id"]

    assert pair.admin.get("/api/v1/chat/sessions").json()["items"] == []
    assert pair.admin.get(f"/api/v1/chat/sessions/{session_id}").status_code == 404


# ---- feedback review -------------------------------------------------------------------

def leave_feedback(pair, category="confusing", note="too long"):
    reply = pair.ask("any urgent problems?")
    response = pair.analyst.post(FEEDBACK, json={
        "message_id": reply["message_id"], "category": category, "note": note})
    assert response.status_code == 201
    return reply


def test_only_administrators_can_read_feedback():
    pair = Pair()

    assert pair.analyst.get(FEEDBACK).status_code == 403
    assert ChatHarness(authenticated=False).client.get(FEEDBACK).status_code == 401
    assert pair.admin.get(FEEDBACK).json() == {"items": []}


def test_an_administrator_sees_what_was_reported_and_which_answer_it_was_about():
    pair = Pair()
    reply = leave_feedback(pair)

    [item] = pair.admin.get(FEEDBACK).json()["items"]

    assert item["category"] == "confusing" and item["note"] == "too long"
    assert item["owner_id"] == "analyst-009"
    assert item["message_id"] == reply["message_id"]
    assert item["answer"] == reply["answer"]
    assert item["created_at"]


def test_the_question_text_is_not_shown_with_feedback():
    pair = Pair()
    reply = pair.ask("any urgent problems? my password is hunter2")
    pair.analyst.post(FEEDBACK, json={"message_id": reply["message_id"], "category": "other"})

    assert "hunter2" not in str(pair.admin.get(FEEDBACK).json())


def test_feedback_is_newest_first():
    pair = Pair()
    leave_feedback(pair, "confusing", "first")
    leave_feedback(pair, "incorrect", "second")

    notes = [i["note"] for i in pair.admin.get(FEEDBACK).json()["items"]]

    assert notes == ["second", "first"]
