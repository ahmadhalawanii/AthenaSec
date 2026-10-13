from app.graph.nodes.normalize import normalize_alert
from app.schemas import SecurityAlertInput


def test_normalize_alert_creates_initial_evidence():
    alert = SecurityAlertInput(
        alert_id="ALT-TEST-001",
        source="mock",
        event_text="""
            148 failed SSH login attempts
            occurred against the root account
            within five minutes.
        """,
    )

    result = normalize_alert(
        {
            "alert": alert,
            "status": "received",
        }
    )

    assert result["normalized_event"] == (
        "148 failed SSH login attempts "
        "occurred against the root account "
        "within five minutes."
    )

    assert len(result["evidence_records"]) == 1

    evidence = result["evidence_records"][0]

    assert evidence.evidence_id == "E001"
    assert evidence.source == "alert"

    assert evidence.content == (
        "148 failed SSH login attempts "
        "occurred against the root account "
        "within five minutes."
    )

    assert result["status"] == "normalized"