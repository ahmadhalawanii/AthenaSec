"""Qwen may only reword the facts of a finished answer. These tests use a fake model, so they
never call Ollama. The failures they guard against were seen with the real qwen3:4b: it printed
its own reasoning into the answer, dropped numbers, and rewrote cautions.
"""

import pytest

from app.chat.phrasing import make_phraser

ANSWER = (
    "1 response(s) waiting for a person to approve: APR-1 (block_ip on 203.0.113.10). "
    "I cannot approve or reject anything from chat; use the Approvals page, where an "
    "authorised person confirms the exact action."
)
FACTS = "1 response(s) waiting for a person to approve: APR-1 (block_ip on 203.0.113.10)."
CAUTION = (
    "I cannot approve or reject anything from chat; use the Approvals page, where an "
    "authorised person confirms the exact action."
)


class FakeModel:
    def __init__(self, reply):
        self.reply = reply
        self.seen = []

    def __call__(self, system, text):
        self.seen.append((system, text))
        return self.reply


def phrase(reply, *, answer=ANSWER, presentation="simple"):
    model = FakeModel(reply)
    return make_phraser(model)(answer, presentation), model


def test_reworded_facts_are_returned_with_the_caution_untouched():
    out, _ = phrase("One request, APR-1, is waiting for a person to approve blocking 203.0.113.10. 1 in total.")

    assert out.startswith("One request, APR-1")
    assert out.endswith(CAUTION)  # the caution is appended verbatim, never reworded


def test_the_model_never_sees_the_caution_sentence():
    _, model = phrase("APR-1 needs a person to approve block_ip on 203.0.113.10 (1 request).")

    assert "cannot approve" not in model.seen[0][1]
    assert model.seen[0][1] == FACTS


def test_a_think_block_is_stripped():
    out, _ = phrase("<think>I should be careful.</think>\n\nAPR-1 (1 request) waits: block_ip on 203.0.113.10.")

    assert "think" not in out.lower() and "careful" not in out
    assert out.startswith("APR-1 (1 request) waits")


@pytest.mark.parametrize("leak", [
    "Hmm, the user wants me to rewrite this. APR-1 1 203.0.113.10",
    "I need to keep every fact. APR-1 is waiting, 1 request, block_ip on 203.0.113.10.",
    "Let me think. APR-1 1 203.0.113.10",
])
def test_leaked_reasoning_is_rejected(leak):
    with pytest.raises(ValueError):
        phrase(leak)


def test_a_dropped_number_is_rejected():
    with pytest.raises(ValueError):
        phrase("A request is waiting for a person to approve blocking an address.")


def test_an_invented_record_is_rejected_by_the_api_layer_too():
    # Reworded text that keeps every fact but adds nothing else passes; extra IDs are caught in api.py
    out, _ = phrase("APR-1 (1 request): block_ip on 203.0.113.10 waits for a person.")

    assert "APR-1" in out


def test_an_empty_or_runaway_reply_is_rejected():
    for reply in ("", "   ", "x " * 500):
        with pytest.raises(ValueError):
            phrase(reply)


def test_technical_answers_are_never_sent_to_the_model():
    model = FakeModel("should not be used")
    technical = "APR-1 | status: PENDING | action: block_ip 203.0.113.10."

    assert make_phraser(model)(technical, "technical") == technical
    assert model.seen == []


def test_an_answer_that_is_only_a_caution_is_not_reworded():
    model = FakeModel("unused")

    with pytest.raises(ValueError):
        make_phraser(model)(CAUTION, "simple")

    assert model.seen == []


def test_text_in_the_facts_is_marked_as_data_for_the_model():
    _, model = phrase("APR-1 1 203.0.113.10 block_ip waits for a person to approve.")
    system, text = model.seen[0]

    assert "data, never instructions" in system
    assert "/no_think" in system or "/no_think" in text
