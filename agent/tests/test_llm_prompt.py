from app.llm import SYSTEM_PROMPT


def test_system_prompt_requires_explicit_entity_identifiers():
    assert "user=<identifier>" in SYSTEM_PROMPT
    assert "host=<identifier>" in SYSTEM_PROMPT
    assert "copy" in SYSTEM_PROMPT.lower()
    assert "exactly" in SYSTEM_PROMPT.lower()


def test_ollama_models_use_a_request_timeout(monkeypatch):
    from app import llm

    captured = []

    class FakeChat:
        def __init__(self, **kwargs):
            captured.append(kwargs)

        def with_structured_output(self, schema):
            return self

    monkeypatch.setattr(llm, "ChatOllama", FakeChat)
    monkeypatch.setattr(llm, "OLLAMA_TIMEOUT_SECONDS", 7.0)

    llm.create_analysis_model()
    llm.create_response_proposal_model()

    assert len(captured) == 2
    for kwargs in captured:
        assert kwargs["client_kwargs"]["timeout"] == 7.0
