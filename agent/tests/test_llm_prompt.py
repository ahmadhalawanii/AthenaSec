from app.llm import SYSTEM_PROMPT


def test_system_prompt_requires_explicit_entity_identifiers():
    assert "user=<identifier>" in SYSTEM_PROMPT
    assert "host=<identifier>" in SYSTEM_PROMPT
    assert "copy" in SYSTEM_PROMPT.lower()
    assert "exactly" in SYSTEM_PROMPT.lower()
