from app.graph.nodes.normalize import normalize_alert
from app.schemas import SecurityAlertInput


def test_normalize_alert_cleans_event_text():
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

    assert result["status"] == "normalized"
    assert result["investigation_iteration"] == 0
    assert result["gathered_evidence"] == []