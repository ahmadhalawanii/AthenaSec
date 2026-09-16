from pathlib import Path


def test_demo_uses_autonomous_policy_fields():
    source = Path(
        "demo_graph.py"
    ).read_text(
        encoding="utf-8"
    )

    assert "approval_type" not in source
    assert "execution_mode" not in source
    assert "response_allowed" in source
    assert "ALLOWED" in source
    assert "NOT_ALLOWED" in source
